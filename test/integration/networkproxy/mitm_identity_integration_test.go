//go:build envoyintegration

// Copyright 2026 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
	policy "github.com/bytedance/vArmor/internal/policy"
)

// A rejected policy update must be explicit, with no invalid xDS to publish.
// Once the caller removes the alias, the same deny must reach a live Envoy.
func TestMITMIdentityValidationReloadEnvoy(t *testing.T) {
	binary := envoyBinary(t)
	dir := t.TempDir()
	cert, key, roots := testCertificate(t, dir, "api.example.com")
	sds := certificateSDS(t, cert, key)
	socket, events := startAuditCollector(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
	for proxyPort == adminPort {
		adminPort = freePort(t, "127.0.0.1")
	}
	port := uint16(proxyPort)
	current := &varmor.VarmorPolicy{ObjectMeta: metav1.ObjectMeta{Name: "identity-review", Namespace: "default"}, Spec: varmor.VarmorPolicySpec{
		Target: varmor.Target{Kind: "Pod", Name: "sandbox"}, Policy: varmor.Policy{
			Enforcer: "NetworkProxy", Mode: varmor.EnhanceProtectMode,
			NetworkProxyConfig: &varmor.NetworkProxyConfig{ProxyPort: &port, MITM: &varmor.MITMConfig{Domains: []string{"api.example.com", "127.0.0.1"}}},
			EnhanceProtect:     &varmor.EnhanceProtect{NetworkProxyRawRules: &varmor.NetworkProxyRules{Egress: &varmor.NetworkProxyEgress{DefaultAction: "allow"}}},
		},
	}}
	audit := profile.AuditSinkConfig{ProfileName: "identity-review", ALSUDSPath: socket}
	generate := func(p *varmor.VarmorPolicy, version int64) (string, string, error) {
		return profile.GenerateEnvoyConfig(p.Spec.Policy, version, &profile.MITMInput{Domains: p.Spec.Policy.NetworkProxyConfig.MITM.Domains, CertificateSDSPath: sds}, profile.IPStackConfig{IPv4: true}, audit)
	}
	ldsPath, cdsPath := filepath.Join(dir, "lds.json"), filepath.Join(dir, "cds.json")
	publish := func(lds, cds string) {
		l, c := reloadTransport(t, lds, cds, proxyPort, upstream.Listener.Addr().(*net.TCPAddr).Port)
		atomicWrite(t, cdsPath, c)
		atomicWrite(t, ldsPath, l)
	}
	lds, cds, err := generate(current, 1)
	require.NoError(t, err)
	publish(lds, cds)
	originalLDS, err := os.ReadFile(ldsPath)
	require.NoError(t, err)
	source := func(path string) any {
		return map[string]any{"path_config_source": map[string]any{"path": path, "watched_directory": map[string]any{"path": dir}}}
	}
	bootstrap, err := json.Marshal(map[string]any{"node": map[string]any{"id": "identity-review", "cluster": "identity-review"}, "admin": map[string]any{"address": socketAddress(adminPort)}, "dynamic_resources": map[string]any{"lds_config": source(ldsPath), "cds_config": source(cdsPath)}})
	require.NoError(t, err)
	config := filepath.Join(dir, "bootstrap.json")
	atomicWrite(t, config, bootstrap)
	output := startEnvoy(t, binary, config)
	waitEnvoyReady(t, adminPort, output)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		},
	}}
	t.Cleanup(client.CloseIdleConnections)
	request := func(scheme, path string, status int) {
		t.Helper()
		resp, err := client.Get(scheme + "://api.example.com" + path)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)
		require.Equal(t, status, resp.StatusCode)
	}
	request("http", "/identity-before", 200)
	next := current.DeepCopy()
	next.Spec.Policy.EnhanceProtect.NetworkProxyRawRules.Egress.HTTPRules = []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"deny", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"api.example.com"}}}}
	for _, alias := range []string{"127.0.0.1/32", "API.EXAMPLE.COM"} {
		candidate := next.DeepCopy()
		candidate.Spec.Policy.NetworkProxyConfig.MITM.Domains = append(candidate.Spec.Policy.NetworkProxyConfig.MITM.Domains, alias)
		valid, msg := policy.ValidateAddPolicy(candidate, true)
		require.False(t, valid)
		require.Contains(t, msg, "duplicates the identity")
		valid, msg = policy.ValidateUpdatePolicy(candidate, "NetworkProxy", current.Spec.Target, current.Spec.Policy.NetworkProxyConfig)
		require.False(t, valid)
		require.Contains(t, msg, "duplicates the identity")
		l, c, err := generate(candidate, 2)
		require.ErrorContains(t, err, "duplicates the identity")
		require.Empty(t, l)
		require.Empty(t, c)
		unchanged, err := os.ReadFile(ldsPath)
		require.NoError(t, err)
		require.Equal(t, originalLDS, unchanged)
		request("http", "/identity-rejected-update", 200)
	}
	// The corrected update retains a supported /32 entry and the exact same deny.
	next.Spec.Policy.NetworkProxyConfig.MITM.Domains = []string{"api.example.com", "127.0.0.1/32"}
	valid, msg := policy.ValidateUpdatePolicy(next, "NetworkProxy", current.Spec.Target, current.Spec.Policy.NetworkProxyConfig)
	require.True(t, valid, msg)
	lds, cds, err = generate(next, 2)
	require.NoError(t, err)
	publish(lds, cds)
	admin := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(admin.CloseIdleConnections)
	awaitCondition(t, "active listener with new deny", func() bool {
		resp, err := admin.Get(fmt.Sprintf("http://127.0.0.1:%d/config_dump", adminPort))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var dump struct {
			Configs []struct {
				Listeners []struct {
					Active struct {
						Listener json.RawMessage `json:"listener"`
					} `json:"active_state"`
				} `json:"dynamic_listeners"`
			}
		}
		if json.NewDecoder(resp.Body).Decode(&dump) != nil {
			return false
		}
		for _, config := range dump.Configs {
			for _, listener := range config.Listeners {
				if bytes.Contains(listener.Active.Listener, []byte(`"http_0"`)) {
					return true
				}
			}
		}
		return false
	})
	before := calls.Load()
	request("http", "/identity-denied-http", 403)
	request("https", "/identity-denied-https", 403)
	require.Equal(t, before, calls.Load(), "new deny must stop forwarding")
	awaitCondition(t, "two deny audit events", func() bool { return len(events()) >= 2 })
	got := events()
	require.Len(t, got, 2)
	byPath := map[string]observedEvent{}
	for _, event := range got {
		byPath[event.Path] = event
	}
	require.Equal(t, "DENIED", byPath["/identity-denied-http"].Action)
	require.Equal(t, "http_ip_chain", byPath["/identity-denied-http"].FilterChain)
	require.Equal(t, "DENIED", byPath["/identity-denied-https"].Action)
	require.Equal(t, "mitm_tls_dns_ip_chain", byPath["/identity-denied-https"].FilterChain)
	require.NotContains(t, output.String(), "Filesystem config update rejected")
}
