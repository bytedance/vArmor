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

package profile

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	mitm "github.com/bytedance/vArmor/internal/networkproxy/mitm"
)

// TestTLSSecretRotationEnvoy keeps the same Envoy process and LDS/CDS resources
// throughout. Only local transport addresses are adapted; both generated TLS
// contexts and certificate validation remain enabled. No Docker or iptables.
func TestTLSSecretRotationEnvoy(t *testing.T) {
	binary := os.Getenv("ENVOY_BINARY")
	if binary == "" {
		t.Skip("set ENVOY_BINARY to run local Envoy integration tests")
	}
	for _, mode := range []string{"atomic_files", "kubernetes_projection", "static_tls_control"} {
		t.Run(mode, func(t *testing.T) { testTLSSecretRotation(t, binary, mode) })
	}
}

func testTLSSecretRotation(t *testing.T, binary, mode string) {
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	if err := os.Mkdir(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := mitm.GenerateMITMMaterial([]string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := mitm.GenerateMITMMaterial([]string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := mitm.RenewLeaf(a.CA, []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	pair := func(cert, key []byte) *tls.Certificate {
		p, err := tls.X509KeyPair(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		return &p
	}
	pairA, pairB := pair(a.Leaf.CertPEM, a.Leaf.KeyPEM), pair(b.Leaf.CertPEM, b.Leaf.KeyPEM)
	var upstreamPair atomic.Pointer[tls.Certificate]
	upstreamPair.Store(pairA)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(200)
	}))
	upstream.TLS = &tls.Config{SessionTicketsDisabled: true, MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return upstreamPair.Load(), nil }}
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	upstream.StartTLS()
	upstream.Config.SetKeepAlivesEnabled(false)
	t.Cleanup(upstream.Close)
	proxyPort, adminPort := sdsFreePort(t), sdsFreePort(t)
	for proxyPort == adminPort {
		adminPort = sdsFreePort(t)
	}
	port := uint16(proxyPort)
	p := varmor.Policy{Enforcer: "NetworkProxy", Mode: varmor.EnhanceProtectMode,
		NetworkProxyConfig: &varmor.NetworkProxyConfig{ProxyPort: &port},
		EnhanceProtect:     &varmor.EnhanceProtect{NetworkProxyRawRules: &varmor.NetworkProxyRules{Egress: &varmor.NetworkProxyEgress{DefaultAction: "allow"}}},
	}
	lds, cds, err := GenerateEnvoyConfig(p, 1, &MITMInput{Domains: []string{"api.example.test"}}, IPStackConfig{IPv4: true}, AuditSinkConfig{ProfileName: "sds-test", ALSUDSPath: filepath.Join(dir, "als.sock")})
	if err != nil {
		t.Fatal(err)
	}
	lds = strings.ReplaceAll(lds, "/etc/envoy/tls", tlsDir)
	cds = strings.ReplaceAll(cds, "/etc/envoy/tls", tlsDir)
	var l, c map[string]interface{}
	if err := yaml.Unmarshal([]byte(lds), &l); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(cds), &c); err != nil {
		t.Fatal(err)
	}
	listener := l["resources"].([]interface{})[0].(map[string]interface{})
	listener["address"] = sdsSocket(proxyPort)
	delete(listener, "additional_addresses")
	var filters []interface{}
	for _, f := range listener["listener_filters"].([]interface{}) {
		if f.(map[string]interface{})["name"] != "envoy.filters.listener.original_dst" {
			filters = append(filters, f)
		}
	}
	listener["listener_filters"] = filters
	for _, v := range c["resources"].([]interface{}) {
		cluster := v.(map[string]interface{})
		if cluster["type"] != "ORIGINAL_DST" {
			continue
		}
		cluster["type"], cluster["lb_policy"] = "STATIC", "ROUND_ROBIN"
		delete(cluster, "original_dst_lb_config")
		cluster["load_assignment"] = map[string]interface{}{"cluster_name": cluster["name"], "endpoints": []interface{}{
			map[string]interface{}{"lb_endpoints": []interface{}{map[string]interface{}{"endpoint": map[string]interface{}{"address": sdsSocket(upstream.Listener.Addr().(*net.TCPAddr).Port)}}}},
		}}
	}
	if mode == "static_tls_control" {
		// Reproduce the pre-fix static filename contexts, without SDS watches.
		for _, raw := range listener["filter_chains"].([]interface{}) {
			chain := raw.(map[string]interface{})
			if ts, ok := chain["transport_socket"].(map[string]interface{}); ok {
				ctx := ts["typed_config"].(map[string]interface{})["common_tls_context"].(map[string]interface{})
				delete(ctx, "tls_certificate_sds_secret_configs")
				ctx["tls_certificates"] = []interface{}{map[string]interface{}{
					"certificate_chain": map[string]interface{}{"filename": filepath.Join(tlsDir, "leaf.crt")},
					"private_key":       map[string]interface{}{"filename": filepath.Join(tlsDir, "leaf.key")},
				}}
			}
		}
		for _, raw := range c["resources"].([]interface{}) {
			cluster := raw.(map[string]interface{})
			if ts, ok := cluster["transport_socket"].(map[string]interface{}); ok {
				ctx := ts["typed_config"].(map[string]interface{})["common_tls_context"].(map[string]interface{})
				delete(ctx, "validation_context_sds_secret_config")
				ctx["validation_context"] = map[string]interface{}{"trusted_ca": map[string]interface{}{"filename": filepath.Join(tlsDir, "ca-bundle.crt")}}
			}
		}
	}
	writeJSON := func(path string, v interface{}) {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		sdsAtomicWrite(t, path, data)
	}
	writeJSON(filepath.Join(dir, "lds.yaml"), l)
	writeJSON(filepath.Join(dir, "cds.yaml"), c)
	certSDS, validationSDS, err := GenerateTLSSecrets(a.Leaf.CertPEM, a.Leaf.KeyPEM, a.CA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	revision := 0
	publish := func(cert, trust []byte) {
		revision++
		if mode == "kubernetes_projection" {
			subdir := fmt.Sprintf("..revision-%d", revision)
			if err := os.Mkdir(filepath.Join(tlsDir, subdir), 0700); err != nil {
				t.Fatal(err)
			}
			sdsAtomicWrite(t, filepath.Join(tlsDir, subdir, MITMCertSDSFile), cert)
			sdsAtomicWrite(t, filepath.Join(tlsDir, subdir, MITMValidationSDSFile), trust)
			if revision == 1 {
				for _, name := range []string{MITMCertSDSFile, MITMValidationSDSFile} {
					if err := os.Symlink(filepath.Join("..data", name), filepath.Join(tlsDir, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := os.Symlink(subdir, filepath.Join(tlsDir, "..data_tmp")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(tlsDir, "..data_tmp"), filepath.Join(tlsDir, "..data")); err != nil {
				t.Fatal(err)
			}
		} else {
			sdsAtomicWrite(t, filepath.Join(tlsDir, MITMValidationSDSFile), trust)
			sdsAtomicWrite(t, filepath.Join(tlsDir, MITMCertSDSFile), cert)
		}
	}
	publish(certSDS, validationSDS)
	sdsAtomicWrite(t, filepath.Join(tlsDir, "leaf.crt"), a.Leaf.CertPEM)
	sdsAtomicWrite(t, filepath.Join(tlsDir, "leaf.key"), a.Leaf.KeyPEM)
	sdsAtomicWrite(t, filepath.Join(tlsDir, "ca-bundle.crt"), a.CA.CertPEM)
	pathSource := func(name string) interface{} {
		return map[string]interface{}{"path_config_source": map[string]interface{}{"path": filepath.Join(dir, name), "watched_directory": map[string]interface{}{"path": dir}}}
	}
	bootstrap := map[string]interface{}{"node": map[string]interface{}{"id": "sds-test", "cluster": "sds-test"}, "admin": map[string]interface{}{"address": sdsSocket(adminPort)}, "dynamic_resources": map[string]interface{}{"lds_config": pathSource("lds.yaml"), "cds_config": pathSource("cds.yaml")}}
	configPath := filepath.Join(dir, "bootstrap.json")
	writeJSON(configPath, bootstrap)
	var output sdsLockedBuffer
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
			t.Log(output.String())
		}
	})
	admin := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(admin.CloseIdleConnections)
	adminGet := func(path string) []byte {
		resp, err := admin.Get(fmt.Sprintf("http://127.0.0.1:%d/%s", adminPort, path))
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	sdsAwait(t, "Envoy ready", func() bool { return strings.Contains(string(adminGet("ready")), "LIVE") })
	roots := x509.NewCertPool()
	roots.AddCert(a.CA.Cert)
	roots.AddCert(b.CA.Cert)
	probe := func(expected *tls.Certificate, status int) bool {
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "api.example.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		resp, err := client.Get("https://api.example.test/")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode == status && resp.TLS != nil && len(resp.TLS.VerifiedChains) > 0 && bytes.Equal(resp.TLS.PeerCertificates[0].Raw, expected.Certificate[0])
	}
	sdsAwait(t, "initial TLS and upstream validation", func() bool { return probe(pairA, 200) })
	certRenewed, _, err := GenerateTLSSecrets(renewed.CertPEM, renewed.KeyPEM, a.CA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	pairRenewed := pair(renewed.CertPEM, renewed.KeyPEM)
	if mode == "static_tls_control" {
		sdsAtomicWrite(t, filepath.Join(tlsDir, "leaf.crt"), renewed.CertPEM)
		sdsAtomicWrite(t, filepath.Join(tlsDir, "leaf.key"), renewed.KeyPEM)
		// Re-notify xDS with byte-identical resources, as in the original defect.
		writeJSON(filepath.Join(dir, "lds.yaml"), l)
		writeJSON(filepath.Join(dir, "cds.yaml"), c)
		time.Sleep(300 * time.Millisecond)
		if !probe(pairA, 200) {
			t.Fatal("static control should retain the old handshake certificate")
		}
		upstreamPair.Store(pairB)
		sdsAtomicWrite(t, filepath.Join(tlsDir, "ca-bundle.crt"), b.CA.CertPEM)
		time.Sleep(300 * time.Millisecond)
		if !probe(pairA, 503) {
			t.Fatal("static control should retain the old upstream trust")
		}
		return
	}
	publish(certRenewed, validationSDS)
	sdsAwait(t, "leaf and private key rotation", func() bool { return probe(pairRenewed, 200) })
	// Changing the upstream first proves the new trust is actually required.
	upstreamPair.Store(pairB)
	sdsAwait(t, "untrusted upstream rejected", func() bool { return probe(pairRenewed, 503) })
	certB, trustB, err := GenerateTLSSecrets(b.Leaf.CertPEM, b.Leaf.KeyPEM, b.CA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	publish(certRenewed, trustB)
	sdsAwait(t, "trust bundle rotation", func() bool { return probe(pairRenewed, 200) })
	upstreamPair.Store(pairA)
	sdsAwait(t, "removed upstream CA rejected", func() bool { return probe(pairRenewed, 503) })
	upstreamPair.Store(pairB)
	publish(certB, trustB)
	sdsAwait(t, "CA and certificate rotation", func() bool { return probe(pairB, 200) })
	upstreamPair.Store(pairA)
	publish(certSDS, validationSDS)
	sdsAwait(t, "combined CA rotation", func() bool { return probe(pairA, 200) })
	upstreamPair.Store(pairB)
	publish(certB, trustB)
	sdsAwait(t, "combined CA rotation again", func() bool { return probe(pairB, 200) })
	rejected := func() uint64 {
		var stats struct {
			Stats []struct {
				Name  string
				Value uint64
			}
		}
		_ = json.Unmarshal(adminGet("stats?format=json&filter=update_rejected"), &stats)
		var sum uint64
		for _, s := range stats.Stats {
			sum += s.Value
		}
		return sum
	}
	for _, badKind := range []string{"mismatched_key", "invalid_bundle"} {
		before := rejected()
		badCert, badTrust := certB, trustB
		if badKind == "mismatched_key" {
			var doc map[string]interface{}
			if err := json.Unmarshal(certB, &doc); err != nil {
				t.Fatal(err)
			}
			doc["resources"].([]interface{})[0].(map[string]interface{})["tls_certificate"].(map[string]interface{})["private_key"] = map[string]interface{}{"inline_string": string(a.Leaf.KeyPEM)}
			badCert, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			var doc map[string]interface{}
			if err := json.Unmarshal(trustB, &doc); err != nil {
				t.Fatal(err)
			}
			doc["resources"].([]interface{})[0].(map[string]interface{})["validation_context"].(map[string]interface{})["trusted_ca"] = map[string]interface{}{"inline_string": "invalid PEM"}
			badTrust, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
		}
		publish(badCert, badTrust)
		sdsAwait(t, badKind+" rejected by SDS", func() bool { return rejected() > before })
		if !probe(pairB, 200) {
			t.Fatal("invalid SDS replaced last usable TLS material")
		}
		publish(certRenewed, trustB)
		sdsAwait(t, "recovery after invalid SDS", func() bool { return probe(pairRenewed, 200) })
		publish(certB, trustB)
		sdsAwait(t, "successive rotation", func() bool { return probe(pairB, 200) })
	}
	// Projecting a temporarily missing resource retains existing TLS state.
	missing := filepath.Join(tlsDir, MITMCertSDSFile)
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	if !probe(pairB, 200) {
		t.Fatal("missing resource invalidated active TLS state")
	}
	if mode == "kubernetes_projection" {
		if err := os.Symlink(filepath.Join("..data", MITMCertSDSFile), missing); err != nil {
			t.Fatal(err)
		}
	}
	publish(certRenewed, trustB)
	sdsAwait(t, "recovery after missing resource", func() bool { return probe(pairRenewed, 200) })
	if !strings.Contains(string(adminGet("config_dump?resource=dynamic_active_secrets")), MITMCertSecretName) {
		t.Fatal("dynamic certificate secret not visible in Envoy admin state")
	}
}

func sdsSocket(port int) map[string]interface{} {
	return map[string]interface{}{"socket_address": map[string]interface{}{"address": "127.0.0.1", "port_value": port}}
}
func sdsFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}
func sdsAtomicWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}
func sdsAwait(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type sdsLockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *sdsLockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *sdsLockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
