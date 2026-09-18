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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	proxy "github.com/bytedance/vArmor/internal/networkproxy"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

type customMethodMode struct {
	name, host, chain string
	domains           []string
	tls, h2           bool
}

var customMethodModes = []customMethodMode{
	{name: "http", host: "api.example.com", chain: "http_chain"},
	{name: "http_ip", host: "api.example.com", chain: "http_ip_chain", domains: []string{"127.0.0.1"}},
	{name: "http_mixed", host: "api.example.com", chain: "http_ip_chain", domains: []string{"api.example.com", "127.0.0.1"}},
	{name: "mitm_dns", host: "api.example.com", chain: "mitm_tls_dns_chain", domains: []string{"api.example.com"}, tls: true},
	{name: "mitm_dns_ip", host: "api.example.com", chain: "mitm_tls_dns_ip_chain", domains: []string{"api.example.com", "127.0.0.1"}, tls: true},
	{name: "mitm_ip", host: "127.0.0.1", chain: "mitm_tls_ip_chain", domains: []string{"127.0.0.1"}, tls: true},
	{name: "h2c", host: "api.example.com", chain: "http_chain", h2: true},
	{name: "mitm_h2", host: "api.example.com", chain: "mitm_tls_dns_chain", domains: []string{"api.example.com"}, tls: true, h2: true},
}

// customMethodProxy uses the production bootstrap, including runtime layers.
// Only the transport is adapted: local certificates, sockets and STATIC
// loopback backends replace Kubernetes paths and ORIGINAL_DST routing.
func customMethodProxy(t *testing.T, mode customMethodMode, e *varmor.NetworkProxyEgress, upstreamPort int) (*http.Client, string, string, func() []observedEvent) {
	t.Helper()
	binary := envoyBinary(t)
	dir := t.TempDir()
	cert, key, roots := testCertificate(t, dir, mode.host)
	socket, events := startAuditCollector(t)
	proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
	for adminPort == proxyPort {
		adminPort = freePort(t, "127.0.0.1")
	}
	var mitm *profile.MITMInput
	if len(mode.domains) != 0 {
		mitm = &profile.MITMInput{Domains: mode.domains, CertificateSDSPath: certificateSDS(t, cert, key)}
	}
	result, err := profile.TranslateEgressRules(e, 1, uint16(proxyPort), mitm, profile.IPStackConfig{IPv4: true}, profile.AuditSinkConfig{ProfileName: "custom-methods", ALSUDSPath: socket})
	require.NoError(t, err)
	var lds, cds map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(result.LDS), &lds))
	require.NoError(t, yaml.Unmarshal([]byte(result.CDS), &cds))
	listener := lds["resources"].([]any)[0].(map[string]any)
	delete(listener, "@type")
	listener["address"] = socketAddress(proxyPort)
	var filters []any
	for _, raw := range listener["listener_filters"].([]any) {
		if raw.(map[string]any)["name"] != "envoy.filters.listener.original_dst" {
			filters = append(filters, raw)
		}
	}
	listener["listener_filters"] = filters
	var clusters []any
	for _, raw := range cds["resources"].([]any) {
		cluster := raw.(map[string]any)
		delete(cluster, "@type")
		if cluster["type"] == "ORIGINAL_DST" {
			name := cluster["name"]
			cluster = map[string]any{"name": name, "type": "STATIC", "connect_timeout": "1s",
				"load_assignment": map[string]any{"cluster_name": name, "endpoints": []any{
					map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": socketAddress(upstreamPort)}}}},
				}},
			}
		}
		clusters = append(clusters, cluster)
	}
	setALSFlushInterval(listener)
	policy := &varmor.VarmorPolicy{Spec: varmor.VarmorPolicySpec{Policy: varmor.Policy{Enforcer: "NetworkProxy", Mode: varmor.AlwaysAllowMode}}}
	secret, err := proxy.GenerateEnvoySecret(nil, policy, "default", false)
	require.NoError(t, err)
	require.NotNil(t, secret)
	var bootstrap map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(secret.StringData[proxy.SecretKeyBootstrap]), &bootstrap))
	delete(bootstrap, "dynamic_resources")
	bootstrap["admin"] = map[string]any{"address": socketAddress(adminPort)}
	bootstrap["static_resources"] = map[string]any{"listeners": []any{listener}, "clusters": clusters}
	data, err := json.Marshal(bootstrap)
	require.NoError(t, err)
	config := filepath.Join(dir, "bootstrap.json")
	atomicWrite(t, config, data)
	output := startEnvoy(t, binary, config)
	waitEnvoyReady(t, adminPort, output)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: mode.host, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: mode.h2}
	var rt http.RoundTripper = transport
	if mode.h2 && !mode.tls {
		h2transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dial(ctx, network, addr)
		}}
		t.Cleanup(h2transport.CloseIdleConnections)
		rt = h2transport
	}
	client := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	scheme := "http"
	if mode.tls {
		scheme = "https"
	}
	return client, scheme + "://" + mode.host, address, events
}

type customMethodEvent struct {
	action, method string
}

func checkCustomMethodEvents(t *testing.T, events func() []observedEvent, expected map[string]customMethodEvent, chain string) {
	t.Helper()
	if len(expected) > 0 {
		awaitCondition(t, "custom method audit events", func() bool { return len(events()) >= len(expected) })
	}
	// Include several flush periods to detect duplicate and unexpected events.
	time.Sleep(300 * time.Millisecond)
	got := events()
	require.Len(t, got, len(expected), "events=%+v", got)
	seen := make(map[string]bool)
	for _, event := range got {
		want, ok := expected[event.Path]
		assert.True(t, ok, "unexpected event: %+v", event)
		assert.False(t, seen[event.Path], "duplicate event: %+v", event)
		seen[event.Path] = true
		assert.Equal(t, want.action, event.Action)
		assert.Equal(t, want.method, event.Method, "path=%s", event.Path)
		assert.Equal(t, chain, event.FilterChain)
	}
}

func TestCustomMethodsEnvoyAudit(t *testing.T) {
	envoyBinary(t)
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
	methods := []string{"GET", "POST", "PROPFIND", "FOO", "get", "X-CUSTOM", "FOO!BAR"}
	for _, mode := range customMethodModes {
		for _, row := range rows {
			t.Run(mode.name+"/"+row.name, func(t *testing.T) {
				var calls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					body, err := io.ReadAll(r.Body)
					if !assert.NoError(t, err) {
						return
					}
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"method": r.Method, "body": string(body), "path": r.URL.Path}))
				}))
				t.Cleanup(upstream.Close)
				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction, HTTPRules: []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"audit"}, Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{{Exact: "/unmatched"}}}}}}
				for _, q := range row.qualifiers {
					e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: q, Match: varmor.HTTPMatch{Hosts: []string{mode.host}, Paths: []varmor.HTTPPathMatch{{Prefix: "/secret/"}}}})
				}
				client, base, _, events := customMethodProxy(t, mode, e, upstream.Listener.Addr().(*net.TCPAddr).Port)
				expected := make(map[string]customMethodEvent)
				var wantCalls int32
				for i, method := range methods {
					path := fmt.Sprintf("/secret/%d", i)
					t.Run(method, func(t *testing.T) {
						if row.action != "" {
							expected[path] = customMethodEvent{row.action, method}
						}
						if row.status == 200 {
							wantCalls++
						}
						req, err := http.NewRequest(method, base+path, strings.NewReader("payload"))
						require.NoError(t, err)
						resp, err := client.Do(req)
						require.NoError(t, err)
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						assert.Equal(t, row.status, resp.StatusCode, "response=%s", body)
						major := 1
						if mode.h2 {
							major = 2
						}
						assert.Equal(t, major, resp.ProtoMajor)
						if row.status == 200 {
							var got map[string]string
							require.NoError(t, json.Unmarshal(body, &got))
							assert.Equal(t, map[string]string{"method": method, "body": "payload", "path": path}, got)
						}
					})
				}
				assert.Equal(t, wantCalls, calls.Load())
				checkCustomMethodEvents(t, events, expected, mode.chain)
			})
		}
	}
}

// An explicit FOO rule must match FOO, while foo remains a distinct method.
// A broad L4 allow must not bypass a matching HTTP denial after inspection.
func TestCustomMethodsMatchingAndFragments(t *testing.T) {
	envoyBinary(t)
	for _, mode := range []customMethodMode{customMethodModes[0], customMethodModes[1], customMethodModes[3]} {
		t.Run(mode.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, err := io.WriteString(w, r.Method)
				assert.NoError(t, err)
			}))
			t.Cleanup(upstream.Close)
			e := &varmor.NetworkProxyEgress{DefaultAction: "deny", Rules: []varmor.NetworkProxyEgressRule{{Qualifiers: []string{"allow"}, IP: "127.0.0.1"}}, HTTPRules: []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"deny", "audit"}, Match: varmor.HTTPMatch{Methods: []string{"FOO"}, Paths: []varmor.HTTPPathMatch{{Prefix: "/blocked/"}}}}}}
			client, base, address, events := customMethodProxy(t, mode, e, upstream.Listener.Addr().(*net.TCPAddr).Port)
			expected := make(map[string]customMethodEvent)
			for i, tc := range []struct {
				method, path string
				status       int
			}{{"FOO", "/blocked/exact", 403}, {"foo", "/blocked/lowercase", 200}, {"FOO", "/open", 200}, {"GET", "/blocked/standard", 200}} {
				req, err := http.NewRequest(tc.method, base+tc.path, nil)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.NoError(t, err)
				assert.Equal(t, tc.status, resp.StatusCode, "case %d", i)
				if tc.status == 403 {
					expected[tc.path] = customMethodEvent{"DENIED", tc.method}
				} else {
					assert.Equal(t, tc.method, string(body))
				}
			}
			if !mode.tls {
				conn, err := net.DialTimeout("tcp", address, time.Second)
				require.NoError(t, err)
				defer conn.Close()
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				for _, part := range []string{"F", "OO /blocked/fragment HTTP/1.1\r", "\nHost: api.example.com\r\nConnection: close\r\n\r\n"} {
					_, err := io.WriteString(conn, part)
					require.NoError(t, err)
					time.Sleep(30 * time.Millisecond)
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				require.NoError(t, err)
				assert.Equal(t, 403, resp.StatusCode)
				expected["/blocked/fragment"] = customMethodEvent{"DENIED", "FOO"}
			}
			assert.Equal(t, int32(3), calls.Load())
			checkCustomMethodEvents(t, events, expected, mode.chain)
		})
	}
}

// Custom-method recognition must preserve non-HTTP TCP fallback and its RBAC.
func TestCustomMethodsTCPFallback(t *testing.T) {
	envoyBinary(t)
	for _, mode := range []customMethodMode{customMethodModes[0], customMethodModes[1]} {
		for _, row := range []struct {
			name, defaultAction, action string
			qualifiers                  []string
			allowed                     bool
		}{
			{"allow", "allow", "", nil, true},
			{"allow_audit", "deny", "AUDIT", []string{"allow", "audit"}, true},
			{"deny", "deny", "DENIED", nil, false},
			{"deny_audit", "allow", "DENIED", []string{"deny", "audit"}, false},
		} {
			t.Run(mode.name+"/"+row.name, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				var calls atomic.Int32
				done := make(chan struct{})
				go func() {
					defer close(done)
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					calls.Add(1)
					if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Error(err)
						return
					}
					data, err := bufio.NewReader(conn).ReadBytes('\n')
					if err != nil {
						t.Error(err)
						return
					}
					_, err = conn.Write(data)
					assert.NoError(t, err)
				}()
				t.Cleanup(func() { listener.Close(); <-done })
				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
				if len(row.qualifiers) != 0 {
					e.Rules = []varmor.NetworkProxyEgressRule{{Qualifiers: row.qualifiers, IP: "127.0.0.1"}}
				}
				_, _, address, events := customMethodProxy(t, mode, e, listener.Addr().(*net.TCPAddr).Port)
				conn, err := net.DialTimeout("tcp", address, time.Second)
				require.NoError(t, err)
				defer conn.Close()
				require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
				payload := "\x00varmor-tcp-probe\r\n"
				_, writeErr := io.WriteString(conn, payload)
				data, readErr := bufio.NewReader(conn).ReadBytes('\n')
				if row.allowed {
					require.NoError(t, writeErr)
					require.NoError(t, readErr)
					assert.Equal(t, payload, string(data))
					assert.Equal(t, int32(1), calls.Load())
				} else {
					require.Error(t, readErr)
					if netErr, ok := readErr.(net.Error); ok {
						assert.False(t, netErr.Timeout(), "denial should close the connection")
					}
					assert.Empty(t, data)
					assert.Zero(t, calls.Load())
				}
				conn.Close()
				expected := make(map[string]customMethodEvent)
				if row.action != "" {
					expected[""] = customMethodEvent{action: row.action}
				}
				// Listener-level TCP ALS does not carry the HCM filter-chain tag.
				checkCustomMethodEvents(t, events, expected, "")
			})
		}
	}
}
