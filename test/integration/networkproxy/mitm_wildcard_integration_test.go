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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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
	runMITMWildcardEnvoyAudit(t, false)
}

func TestMITMWildcardIPOverlapEnvoyAudit(t *testing.T) {
	runMITMWildcardEnvoyAudit(t, true)
}

func runMITMWildcardEnvoyAudit(t *testing.T, ipOverlap bool) {
	binary := envoyBinary(t)
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
		headerValue                                              string
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
		// Literal header values must survive Envoy formatter and YAML parsing.
		{name: "header_percent_single", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", headerValue: "Bearer ab%cd"},
		{name: "header_percent_pair", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", headerValue: "Bearer ab%%cd"},
		{name: "header_formatter", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", headerValue: "%REQ(X-Client-Token)%"},
		{name: "header_percent_only", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", headerValue: "%"},
		{name: "header_percent_url", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", headerValue: "https://api.example.com/a%2Fb?q=100%25"},
		{name: "header_percent_yaml", host: "api.example.com", domain: "api.example.com", requestHost: "api.example.com", headerValue: "quoted \"ab%cd\" \\ path"},
	}
	for _, overlap := range overlaps {
		for _, row := range rows {
			t.Run(overlap.name+"/"+row.name, func(t *testing.T) {
				dir := t.TempDir()
				headerValue := overlap.headerValue
				if headerValue == "" {
					headerValue = "Bearer static-token"
				}
				serverName := overlap.serverName
				if serverName == "" {
					serverName = overlap.requestHost
				}
				cert, key, roots := testCertificate(t, dir, serverName)
				requestPort := overlap.requestPort
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
				socket, events := startAuditCollector(t)
				var upstreamCalls atomic.Int32
				upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					if r.Host != overlap.requestHost+requestPort {
						t.Errorf("upstream Host=%q want %q", r.Host, overlap.requestHost+requestPort)
					}
					if got := r.Header.Get("X-MITM-Probe"); got != "injected" {
						t.Errorf("upstream X-MITM-Probe=%q want injected", got)
					}
					if values := r.Header.Values("Authorization"); len(values) != 1 || values[0] != headerValue {
						t.Errorf("upstream Authorization=%q want one literal %q", values, headerValue)
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(upstream.Close)
				upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
				// Reserve the upstream socket before choosing Envoy ports, so the
				// backend cannot reuse adminPort and answer its readiness probe.
				proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
				for adminPort == proxyPort {
					adminPort = freePort(t, "127.0.0.1")
				}
				rulePort := proxyPort
				if overlap.unmatchedPort {
					rulePort = adminPort
				}
				if overlap.checkPort {
					// Match the authority's port but independently verify the actual
					// destination (the proxy socket in this transport-only fixture).
					requestPort = ":" + strconv.Itoa(rulePort)
				}
				upstream.Start()
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
				domains := []string{overlap.domain}
				expectedChain := "mitm_tls_dns_chain"
				if ipOverlap {
					domains = append(domains, "127.0.0.1")
					expectedChain = "mitm_tls_dns_ip_chain"
				}
				result, err := profile.TranslateEgressRules(e, 1, uint16(proxyPort), &profile.MITMInput{Domains: domains, CertificateSDSPath: certificateSDS(t, cert, key), HeadersByDomain: map[string][]profile.HeaderToAdd{overlap.domain: {{Name: "X-MITM-Probe", Value: "injected"}, {Name: "Authorization", Value: headerValue}}}}, profile.IPStackConfig{IPv4: true}, profile.AuditSinkConfig{ProfileName: "wildcard-test", ALSUDSPath: socket})
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
				envoyListener["address"] = socketAddress(proxyPort)
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
								map[string]interface{}{"lb_endpoints": []interface{}{map[string]interface{}{"endpoint": map[string]interface{}{"address": socketAddress(upstreamPort)}}}},
							}},
						}
					}
					clusters = append(clusters, cluster)
				}
				// Shorten ALS batching, not audit selection, for bounded silent checks.
				setALSFlushInterval(envoyListener)
				bootstrap := map[string]interface{}{
					"node":             map[string]interface{}{"id": "wildcard-test", "cluster": "wildcard-test"},
					"admin":            map[string]interface{}{"address": socketAddress(adminPort)},
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
				output := startEnvoy(t, binary, configPath)
				waitEnvoyReady(t, adminPort, output)
				transport := &http.Transport{
					Proxy:           nil,
					TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12},
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)))
					},
				}
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				t.Cleanup(client.CloseIdleConnections)
				request, err := http.NewRequest(http.MethodGet, "https://"+overlap.requestHost+requestPort+"/secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "forged-client-value")
				request.Header.Set("X-Client-Token", "client-controlled")
				resp, err := client.Do(request)
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
				deadline := time.Now().Add(3 * time.Second)
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
				if wantCount == 1 && (got[0].Action != wantAction || got[0].Path != "/secret" || got[0].FilterChain != expectedChain) {
					t.Fatalf("event=%+v; want action=%s on MITM /secret", got[0], wantAction)
				}
			})
		}
	}
}
