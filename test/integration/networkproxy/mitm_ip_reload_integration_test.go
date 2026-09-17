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

	"golang.org/x/net/http2"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// IP candidates must work after file-based LDS updates as well as at startup.
// Transport-only adaptations are shared with the LDS/CDS reload tests.
func TestMITMIPSelectionReloadEnvoy(t *testing.T) {
	binary := envoyBinary(t)
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	if err := os.Mkdir(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	cert, key, roots := testCertificate(t, tlsDir, "api.example.com")
	socket, events := startAuditCollector(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Echo injected headers to distinguish plaintext and MITM routing.
		w.Header().Set("X-Received-Scope", r.Header.Get("X-Scope"))
		if r.URL.Path == "/upstream403" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(upstream.Close)
	proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
	for proxyPort == adminPort {
		adminPort = freePort(t, "127.0.0.1")
	}
	e := &varmor.NetworkProxyEgress{DefaultAction: "allow", HTTPRules: []varmor.NetworkProxyHTTPRule{
		{Qualifiers: []string{"audit"}, Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{{Prefix: "/"}}}},
		{Qualifiers: []string{"deny"}, Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{{Prefix: "/admin/"}}}},
	}}
	audit := profile.AuditSinkConfig{ProfileName: "ip-selection-reload", ALSUDSPath: socket}
	sds := certificateSDS(t, cert, key)
	ldsPath, cdsPath := filepath.Join(dir, "lds.json"), filepath.Join(dir, "cds.json")
	publish := func(version int64, domains []string) {
		result, err := profile.TranslateEgressRules(e, version, uint16(proxyPort), &profile.MITMInput{Domains: domains, CertificateSDSPath: sds, HeadersByDomain: map[string][]profile.HeaderToAdd{
			"api.example.com": {{Name: "X-Scope", Value: "dns"}}, "127.0.0.1": {{Name: "X-Scope", Value: "ip"}},
		}}, profile.IPStackConfig{IPv4: true}, audit)
		if err != nil {
			t.Fatal(err)
		}
		lds, cds := reloadTransport(t, result.LDS, result.CDS, proxyPort, upstream.Listener.Addr().(*net.TCPAddr).Port)
		atomicWrite(t, cdsPath, cds)
		atomicWrite(t, ldsPath, lds)
	}
	source := func(path string) any {
		return map[string]any{"path_config_source": map[string]any{"path": path, "watched_directory": map[string]any{"path": dir}}}
	}
	bootstrap := map[string]any{"node": map[string]any{"id": "ip-selection", "cluster": "ip-selection"}, "admin": map[string]any{"address": socketAddress(adminPort)}, "dynamic_resources": map[string]any{"lds_config": source(ldsPath), "cds_config": source(cdsPath)}}
	data, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "bootstrap.json")
	atomicWrite(t, config, data)
	publish(1, []string{"api.example.com"})
	output := startEnvoy(t, binary, config)
	waitEnvoyReady(t, adminPort, output)
	admin := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(admin.CloseIdleConnections)
	// Envoy's in-place filter-chain updates can retain the listener's old
	// active_state.version_info. Inspect the active chain set, then send traffic.
	active := func(wantIP bool) bool {
		resp, err := admin.Get(fmt.Sprintf("http://127.0.0.1:%d/config_dump", adminPort))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var doc struct {
			Configs []struct {
				Listeners []struct {
					Active struct {
						Listener struct {
							Chains []struct{ Name string } `json:"filter_chains"`
						} `json:"listener"`
					} `json:"active_state"`
				} `json:"dynamic_listeners"`
			}
		}
		if json.NewDecoder(resp.Body).Decode(&doc) != nil {
			return false
		}
		for _, c := range doc.Configs {
			for _, l := range c.Listeners {
				names := map[string]bool{}
				for _, chain := range l.Active.Listener.Chains {
					names[chain.Name] = true
				}
				if names["mitm_tls_dns_chain"] && names["http_ip_chain"] == wantIP && names["mitm_tls_dns_ip_chain"] == wantIP && names["mitm_tls_ip_chain"] == wantIP {
					return true
				}
			}
		}
		return false
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12}
	clients := map[string]*http.Client{
		"h1": {Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsConfig, DialContext: dial}},
		"h2": {Timeout: 3 * time.Second, Transport: &http2.Transport{TLSClientConfig: tlsConfig, DialTLSContext: func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			secured := tls.Client(conn, cfg)
			if err := secured.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return secured, nil
		}}},
		"h2c": {Timeout: 3 * time.Second, Transport: &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			return dial(ctx, network, address)
		}}},
	}
	for _, c := range clients {
		t.Cleanup(c.CloseIdleConnections)
	}
	var want []observedEvent
	for i, domains := range [][]string{{"api.example.com"}, {"api.example.com", "127.0.0.1"}, {"api.example.com"}} {
		version := i + 1
		if i > 0 {
			publish(int64(version), domains)
		}
		t.Logf("revision %d: domains=%v", version, domains)
		awaitCondition(t, fmt.Sprintf("active LDS revision %d", version), func() bool { return active(i == 1) })
		for _, tc := range []struct {
			protocol, scheme, host, path string
			status                       int
			action                       string
		}{
			{"h1", "http", "api.example.com", "/ok", 200, "AUDIT"},
			{"h1", "https", "api.example.com", "/ok", 200, "AUDIT"},
			{"h1", "http", "api.example.com", "/admin/secret", 403, "DENIED"},
			{"h1", "https", "api.example.com", "/admin/secret", 403, "DENIED"},
			{"h1", "https", "api.example.com", "/upstream403", 403, "AUDIT"},
			{"h1", "https", "unrelated.invalid", "/outside", 404, "AUDIT"},
			{"h2c", "http", "api.example.com", "/h2", 200, "AUDIT"},
			{"h2", "https", "api.example.com", "/h2", 200, "AUDIT"},
			{"h2c", "http", "api.example.com", "/admin/h2", 403, "DENIED"},
			{"h2", "https", "api.example.com", "/admin/h2", 403, "DENIED"},
		} {
			client := clients[tc.protocol]
			// Reconnect after a revision: existing streams intentionally keep their chain.
			client.CloseIdleConnections()
			req, err := http.NewRequest(http.MethodGet, tc.scheme+"://api.example.com"+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host
			before := calls.Load()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("revision %d %s %s %s: status %d want %d", version, tc.protocol, tc.host, tc.path, resp.StatusCode, tc.status)
			}
			if tc.protocol != "h1" && resp.ProtoMajor != 2 {
				t.Fatalf("expected HTTP/2, got %s", resp.Proto)
			}
			forwarded := tc.status == 200 || tc.path == "/upstream403"
			expectedCalls := before
			if forwarded {
				expectedCalls++
			}
			if calls.Load() != expectedCalls {
				t.Fatalf("upstream calls %d want %d", calls.Load(), expectedCalls)
			}
			if forwarded {
				expectedHeader := ""
				if tc.scheme == "https" {
					expectedHeader = "dns"
				}
				if got := resp.Header.Get("X-Received-Scope"); got != expectedHeader {
					t.Fatalf("header=%q want %q", got, expectedHeader)
				}
			}
			chain := "http_chain"
			if tc.scheme == "https" {
				chain = "mitm_tls_dns_chain"
			}
			if i == 1 {
				chain = "http_ip_chain"
				if tc.scheme == "https" {
					chain = "mitm_tls_dns_ip_chain"
				}
			}
			want = append(want, observedEvent{Action: tc.action, Path: tc.path, FilterChain: chain})
		}
	}
	awaitCondition(t, "audit delivery", func() bool { return len(events()) >= len(want) })
	time.Sleep(300 * time.Millisecond)
	got := events()
	if len(got) != len(want) {
		t.Fatalf("events=%d want %d", len(got), len(want))
	}
	// Different HCM loggers may flush in different order.
	type eventKey struct{ action, path, chain string }
	counts := map[eventKey]int{}
	for _, event := range got {
		counts[eventKey{event.Action, event.Path, event.FilterChain}]++
	}
	for _, event := range want {
		counts[eventKey{event.Action, event.Path, event.FilterChain}]--
	}
	for k, n := range counts {
		if n != 0 {
			t.Errorf("event %+v count difference %d", k, n)
		}
	}
}

// HTTP inspection must not capture arbitrary non-TLS TCP on a MITM IP.
func TestMITMIPSelectionTCPFallbackEnvoy(t *testing.T) {
	binary := envoyBinary(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 6)
		_, err = io.ReadFull(conn, buf)
		if err == nil && string(buf) != "PING\r\n" {
			err = fmt.Errorf("upstream got %q", buf)
		}
		if err == nil {
			_, err = conn.Write([]byte("PONG"))
		}
		done <- err
	}()
	dir := t.TempDir()
	cert, key, _ := testCertificate(t, dir, "127.0.0.1")
	proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
	for proxyPort == adminPort {
		adminPort = freePort(t, "127.0.0.1")
	}
	socket, _ := startAuditCollector(t)
	result, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{DefaultAction: "allow"}, 1, uint16(proxyPort), &profile.MITMInput{Domains: []string{"127.0.0.1"}, CertificateSDSPath: certificateSDS(t, cert, key)}, profile.IPStackConfig{IPv4: true}, profile.AuditSinkConfig{ALSUDSPath: socket})
	if err != nil {
		t.Fatal(err)
	}
	lds, cds := reloadTransport(t, result.LDS, result.CDS, proxyPort, listener.Addr().(*net.TCPAddr).Port)
	ldsPath, cdsPath := filepath.Join(dir, "lds.json"), filepath.Join(dir, "cds.json")
	atomicWrite(t, ldsPath, lds)
	atomicWrite(t, cdsPath, cds)
	config, err := json.Marshal(map[string]any{"node": map[string]any{"id": "tcp-fallback", "cluster": "tcp-fallback"}, "admin": map[string]any{"address": socketAddress(adminPort)}, "dynamic_resources": map[string]any{"lds_config": map[string]any{"path_config_source": map[string]any{"path": ldsPath}}, "cds_config": map[string]any{"path_config_source": map[string]any{"path": cdsPath}}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bootstrap.json")
	atomicWrite(t, path, config)
	output := startEnvoy(t, binary, path)
	waitEnvoyReady(t, adminPort, output)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PONG" {
		t.Fatalf("got %q want PONG", buf)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
