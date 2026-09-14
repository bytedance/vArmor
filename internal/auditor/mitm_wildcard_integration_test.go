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

package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// TestMITMWildcardEnvoyAudit is opt-in: ENVOY_BINARY must name an installed
// Envoy executable. It exercises actual TLS, RBAC, CEL, gRPC ALS and this
// package's production consumer. No Docker, Kubernetes or iptables is needed.
// Only transport plumbing is adapted: listen on loopback and replace
// ORIGINAL_DST upstream clusters with a local HTTP server. Generated MITM
// chains, virtual hosts, RBAC predicates and access loggers remain in use.
func TestMITMWildcardEnvoyAudit(t *testing.T) {
	binary := os.Getenv("ENVOY_BINARY")
	if binary == "" {
		t.Skip("set ENVOY_BINARY to run local Envoy integration tests")
	}
	var err error
	binary, err = exec.LookPath(binary)
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, defaultAction string
		qualifiers          [][]string
		status              int
		action              string
	}{
		{"allow_unmatched", "allow", nil, 200, ""},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}, 403, ""},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}, 403, "DENIED"},
		{"allow_audit", "allow", [][]string{{"audit"}}, 200, "AUDIT"},
		{"deny_unmatched", "deny", nil, 403, "DENIED"},
		{"deny_allow", "deny", [][]string{{"allow"}}, 200, ""},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}, 200, "AUDIT"},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}, 403, "DENIED"},
	}
	overlaps := []struct {
		name, host, domain, requestHost, requestPort, serverName string
		rejectRoute, checkPort, unmatchedPort                    bool
	}{
		{name: "wildcard_rule", host: "*.example.com", domain: "api.example.com", requestHost: "api.example.com"},
		{name: "wildcard_MITM", host: "api.example.com", domain: "*.example.com", requestHost: "api.example.com"},
		{name: "nested_wildcards", host: "*.svc.example.com", domain: "*.example.com", requestHost: "api.svc.example.com"},
		{name: "exact_default_port", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", requestPort: ":443"},
		{name: "exact_custom_port", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", requestPort: ":8834"},
		{name: "wildcard_default_port", host: "api.example.com", domain: "*.example.com", requestHost: "api.example.com", requestPort: ":443"},
		{name: "wildcard_custom_port", host: "api.example.com", domain: "*.example.com", requestHost: "api.example.com", requestPort: ":8834"},
		{name: "nested_wildcards_custom_port", host: "*.svc.example.com", domain: "*.example.com", requestHost: "api.svc.example.com", requestPort: ":8834"},
		{name: "unrelated_authority", host: "other.invalid", domain: "*.example.com", requestHost: "other.invalid", requestPort: ":8834", serverName: "api.example.com", rejectRoute: true},
		{name: "parent_authority", host: "example.com", domain: "*.example.com", requestHost: "example.com", requestPort: ":8834", serverName: "api.example.com", rejectRoute: true},
		{name: "suffix_spoof_authority", host: "api.example.com.evil", domain: "*.example.com", requestHost: "api.example.com.evil", requestPort: ":8834", serverName: "api.example.com", rejectRoute: true},
		{name: "destination_port_match", host: "api.example.com", domain: "*.example.com", requestHost: "api.example.com", checkPort: true},
		{name: "destination_port_mismatch", host: "api.example.com", domain: "*.example.com", requestHost: "api.example.com", checkPort: true, unmatchedPort: true},
	}
	for _, overlap := range overlaps {
		for _, row := range rows {
			t.Run(overlap.name+"/"+row.name, func(t *testing.T) {
				dir := t.TempDir()
				serverName := overlap.serverName
				if serverName == "" {
					serverName = overlap.requestHost
				}
				cert, key, roots := wildcardTestCertificate(t, dir, serverName)
				proxyPort, adminPort := wildcardFreePort(t), wildcardFreePort(t)
				for adminPort == proxyPort {
					adminPort = wildcardFreePort(t)
				}
				requestPort := overlap.requestPort
				rulePort := proxyPort
				if overlap.unmatchedPort {
					rulePort = adminPort
				}
				if overlap.checkPort {
					// Match the authority's port but independently verify the actual
					// destination (the proxy socket in this transport-only fixture).
					requestPort = ":" + strconv.Itoa(rulePort)
				}
				wantStatus, wantAction := row.status, row.action
				// HTTP rules outside the MITM domain set are excluded from this
				// chain, and a mismatched destination port also leaves no match.
				if overlap.unmatchedPort || overlap.rejectRoute {
					wantStatus, wantAction = http.StatusOK, ""
					if row.defaultAction == "deny" {
						wantStatus, wantAction = http.StatusForbidden, "DENIED"
					}
				}
				if overlap.rejectRoute && wantStatus == http.StatusOK {
					wantStatus = http.StatusNotFound
				}
				// Keep the UDS path short even for long subtest names.
				socketDir, err := os.MkdirTemp("", "mitm-als-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(socketDir) })
				socket := filepath.Join(socketDir, "als.sock")
				listener, err := net.Listen("unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				service, events := wildcardTestConsumer(t)
				server := grpc.NewServer()
				accesslogv3.RegisterAccessLogServiceServer(server, service)
				go server.Serve(listener)
				t.Cleanup(func() { server.Stop(); listener.Close() })
				var upstreamCalls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					if r.Host != overlap.requestHost+requestPort {
						t.Errorf("upstream Host=%q want %q", r.Host, overlap.requestHost+requestPort)
					}
					if got := r.Header.Get("X-MITM-Probe"); got != "injected" {
						t.Errorf("upstream X-MITM-Probe=%q want injected", got)
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(upstream.Close)
				upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
				// Keep an audit logger present even for silent rows. Its shadow
				// rule does not match /secret, so these rows also detect false
				// audit selection and accidental loss of the path constraint.
				e.HTTPRules = []varmor.NetworkProxyHTTPRule{{
					Qualifiers: []string{"allow", "audit"},
					Match: varmor.HTTPMatch{
						Hosts: []string{overlap.host},
						Paths: []varmor.HTTPPathMatch{{Exact: "/unmatched"}},
					},
				}}
				for _, q := range row.qualifiers {
					e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: q, Match: varmor.HTTPMatch{Hosts: []string{overlap.host}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}}, Methods: []string{"GET"}}})
				}
				if overlap.checkPort {
					for i := range e.HTTPRules {
						e.HTTPRules[i].Match.Ports = []varmor.Port{{Port: uint16(rulePort)}}
					}
				}
				result, err := profile.TranslateEgressRules(e, 1, uint16(proxyPort), &profile.MITMInput{Domains: []string{overlap.domain}, LeafCertPath: cert, LeafKeyPath: key, HeadersByDomain: map[string][]profile.HeaderToAdd{overlap.domain: {{Name: "X-MITM-Probe", Value: "injected"}}}}, profile.IPStackConfig{IPv4: true}, profile.AuditSinkConfig{ProfileName: "wildcard-test", ALSUDSPath: socket})
				if err != nil {
					t.Fatal(err)
				}
				var lds, cds map[string]interface{}
				if err := yaml.Unmarshal([]byte(result.LDS), &lds); err != nil {
					t.Fatal(err)
				}
				if err := yaml.Unmarshal([]byte(result.CDS), &cds); err != nil {
					t.Fatal(err)
				}
				envoyListener := lds["resources"].([]interface{})[0].(map[string]interface{})
				delete(envoyListener, "@type")
				envoyListener["address"] = wildcardSocketAddress(proxyPort)
				// The test connects directly rather than via transparent redirection.
				var filters []interface{}
				for _, raw := range envoyListener["listener_filters"].([]interface{}) {
					if raw.(map[string]interface{})["name"] != "envoy.filters.listener.original_dst" {
						filters = append(filters, raw)
					}
				}
				envoyListener["listener_filters"] = filters
				var clusters []interface{}
				for _, raw := range cds["resources"].([]interface{}) {
					cluster := raw.(map[string]interface{})
					delete(cluster, "@type")
					if cluster["type"] == "ORIGINAL_DST" {
						name := cluster["name"]
						cluster = map[string]interface{}{
							"name": name, "type": "STATIC", "connect_timeout": "1s",
							"load_assignment": map[string]interface{}{"cluster_name": name, "endpoints": []interface{}{
								map[string]interface{}{"lb_endpoints": []interface{}{map[string]interface{}{"endpoint": map[string]interface{}{"address": wildcardSocketAddress(upstreamPort)}}}},
							}},
						}
					}
					clusters = append(clusters, cluster)
				}
				// Shorten ALS batching, not audit selection, for bounded silent checks.
				wildcardSetFlushInterval(envoyListener)
				bootstrap := map[string]interface{}{
					"node":             map[string]interface{}{"id": "wildcard-test", "cluster": "wildcard-test"},
					"admin":            map[string]interface{}{"address": wildcardSocketAddress(adminPort)},
					"static_resources": map[string]interface{}{"listeners": []interface{}{envoyListener}, "clusters": clusters},
				}
				data, err := json.Marshal(bootstrap)
				if err != nil {
					t.Fatal(err)
				}
				configPath := filepath.Join(dir, "envoy.json")
				if err := os.WriteFile(configPath, data, 0600); err != nil {
					t.Fatal(err)
				}
				var output wildcardLockedBuffer
				cmd := exec.Command(binary, "-c", configPath, "--concurrency", "1", "--disable-hot-restart", "--log-level", "error")
				cmd.Stdout, cmd.Stderr = &output, &output
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				t.Cleanup(func() {
					_ = cmd.Process.Kill()
					<-done
					if t.Failed() {
						t.Logf("Envoy output: %s", output.snapshot())
					}
				})
				adminClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 200 * time.Millisecond}
				t.Cleanup(adminClient.CloseIdleConnections)
				deadline := time.Now().Add(5 * time.Second)
				for {
					resp, err := adminClient.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort))
					ready := false
					if err == nil {
						ready = resp.StatusCode == 200
						resp.Body.Close()
					}
					if ready {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("Envoy did not become ready: %s", output.snapshot())
					}
					time.Sleep(20 * time.Millisecond)
				}
				transport := &http.Transport{
					Proxy:           nil,
					TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12},
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)))
					},
				}
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				t.Cleanup(client.CloseIdleConnections)
				resp, err := client.Get("https://" + overlap.requestHost + requestPort + "/secret")
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if resp.StatusCode != wantStatus {
					t.Errorf("HTTP=%d want %d", resp.StatusCode, wantStatus)
				}
				wantCalls := int32(0)
				if wantStatus == 200 {
					wantCalls = 1
				}
				if got := upstreamCalls.Load(); got != wantCalls {
					t.Errorf("upstream calls=%d want %d", got, wantCalls)
				}
				// Poll for expected delivery, then observe several extra flush periods
				// to detect duplicates. Silent rows observe the same bounded window.
				deadline = time.Now().Add(3 * time.Second)
				if wantAction != "" {
					for len(events()) == 0 && time.Now().Before(deadline) {
						time.Sleep(20 * time.Millisecond)
					}
				}
				time.Sleep(300 * time.Millisecond)
				got := events()
				wantCount := 0
				if wantAction != "" {
					wantCount = 1
				}
				if len(got) != wantCount {
					t.Fatalf("events=%+v; want count=%d", got, wantCount)
				}
				if wantCount == 1 && (got[0].Action != wantAction || got[0].Path != "/secret" || got[0].FilterChain != "mitm_tls_dns_chain") {
					t.Fatalf("event=%+v; want action=%s on MITM /secret", got[0], wantAction)
				}
			})
		}
	}
}

type wildcardObservedEvent struct{ Action, Path, FilterChain string }

func wildcardTestConsumer(t *testing.T) (accesslogv3.AccessLogServiceServer, func() []wildcardObservedEvent) {
	t.Helper()
	var out wildcardLockedBuffer
	a := newTestAuditor(&bytes.Buffer{})
	a.violationLogger = zerolog.New(&out)
	return &alsServer{auditor: a}, func() []wildcardObservedEvent {
		var events []wildcardObservedEvent
		dec := json.NewDecoder(bytes.NewReader(out.snapshot()))
		for {
			var ev recordedViolation
			err := dec.Decode(&ev)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, wildcardObservedEvent{Action: ev.Action, Path: ev.Event.Path, FilterChain: ev.Event.FilterChain})
		}
		return events
	}
}

type wildcardLockedBuffer struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (b *wildcardLockedBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.buffer.Write(p)
}
func (b *wildcardLockedBuffer) snapshot() []byte {
	b.Lock()
	defer b.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

func wildcardFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
func wildcardSocketAddress(port int) map[string]interface{} {
	return map[string]interface{}{"socket_address": map[string]interface{}{"address": "127.0.0.1", "port_value": port}}
}
func wildcardSetFlushInterval(node interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		if _, ok := v["log_name"]; ok {
			v["buffer_flush_interval"] = "0.05s"
		}
		for _, child := range v {
			wildcardSetFlushInterval(child)
		}
	case []interface{}:
		for _, child := range v {
			wildcardSetFlushInterval(child)
		}
	}
}
func wildcardTestCertificate(t *testing.T, dir, host string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPath, keyPath := filepath.Join(dir, "leaf.crt"), filepath.Join(dir, "leaf.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid test certificate")
	}
	return certPath, keyPath, roots
}
