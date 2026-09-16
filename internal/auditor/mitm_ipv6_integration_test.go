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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// TestMITMIPv6EnvoyAudit exercises generated IPv6 virtual hosts and RBAC
// through real TLS and ALS. It reuses the local-only Envoy plumbing from
// TestMITMEgressEnvoyAudit; ENVOY_BINARY opts in. Virtual hosts and HTTP
// filters are never rewritten by the test.
func TestMITMIPv6EnvoyAudit(t *testing.T) {
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
		action, mismatch    string
	}{
		{"allow_unmatched", "allow", nil, 200, "", ""},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}, 403, "", ""},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}, 403, "DENIED", ""},
		{"allow_audit", "allow", [][]string{{"audit"}}, 200, "AUDIT", ""},
		{"deny_unmatched", "deny", nil, 403, "DENIED", ""},
		{"deny_allow", "deny", [][]string{{"allow"}}, 200, "", ""},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}, 200, "AUDIT", ""},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}, 403, "DENIED", ""},
		{"allow_wrong_host", "allow", nil, 404, "", "host"},
		{"allow_wrong_method", "allow", [][]string{{"deny", "audit"}}, 200, "", "method"},
		{"deny_wrong_method", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", "method"},
		{"allow_wrong_path", "allow", [][]string{{"deny", "audit"}}, 200, "", "path"},
		{"deny_wrong_path", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", "path"},
		{"allow_wrong_port", "allow", [][]string{{"deny", "audit"}}, 200, "", "port"},
		{"deny_wrong_port", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", "port"},
	}
	type destination struct {
		name, domain, authorityMode, ruleKind string
		bracketedHost                         bool
		originalPort                          uint16
	}
	var destinations []destination
	for _, domain := range []string{"::1", "::1/128"} {
		label := "bare"
		if strings.Contains(domain, "/") {
			label = "host_cidr"
		}
		for _, mode := range []string{"no_port", "default_port", "nondefault_port"} {
			for _, kind := range []string{"l4", "http"} {
				destinations = append(destinations, destination{label + "_" + mode + "_" + kind, domain, mode, kind, false, 0})
			}
		}
		destinations = append(destinations, destination{label + "_nondefault_port_http_exact", domain, "nondefault_port", "http_exact", false, 0})
		destinations = append(destinations, destination{label + "_nondefault_port_http_range", domain, "nondefault_port", "http_range", false, 0})
		for _, port := range []uint16{80, 443} {
			for _, mode := range []string{"no_port", "default_port"} {
				destinations = append(destinations, destination{
					fmt.Sprintf("%s_bound_%d_%s_bracketed_host", label, port, mode),
					domain, mode, "http_exact", true, port,
				})
			}
		}
	}
	// Repeat HTTP scenarios with bracketed policy hosts, not just bracketed
	// request authorities. L4 rules have no HTTP host spelling to vary.
	for _, dst := range append([]destination(nil), destinations...) {
		if dst.ruleKind != "l4" && !dst.bracketedHost {
			dst.name += "_bracketed_host"
			dst.bracketedHost = true
			destinations = append(destinations, dst)
		}
	}
	for _, dst := range destinations {
		for _, row := range rows {
			if dst.originalPort != 0 && row.mismatch != "" && row.mismatch != "host" && row.mismatch != "port" {
				continue
			}
			// Check method, path and port constraints on both HTTP port
			// translation paths without repeating them for every authority.
			if row.mismatch != "" && row.mismatch != "host" &&
				dst.ruleKind != "http_exact" && dst.ruleKind != "http_range" {
				continue
			}
			t.Run(dst.name+"/"+row.name, func(t *testing.T) {
				dir := t.TempDir()
				cert, key, roots := mitmEgressTestCertificate(t, dir, "::1")
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
				service, events := mitmEgressTestConsumer(t)
				server := grpc.NewServer()
				accesslogv3.RegisterAccessLogServiceServer(server, service)
				go server.Serve(listener)
				t.Cleanup(func() { server.Stop(); listener.Close() })
				var upstreamCalls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					if r.Header.Get("X-MITM-Probe") != "injected" {
						t.Error("MITM header injection missing")
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(upstream.Close)
				upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
				proxyPort, adminPort := mitmEgressFreePort(t, "::1"), mitmEgressFreePort(t, "127.0.0.1")
				for adminPort == proxyPort {
					adminPort = mitmEgressFreePort(t, "127.0.0.1")
				}
				destinationPort := proxyPort
				if dst.originalPort != 0 {
					destinationPort = int(dst.originalPort)
				}

				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
				wrongPort := uint16(1)
				if destinationPort == 1 {
					wrongPort = 2
				}
				// A nonmatching audited rule keeps the logger present for
				// silent rows and detects accidental removal of port limits.
				e.Rules = []varmor.NetworkProxyEgressRule{{
					Qualifiers: []string{"allow", "audit"},
					IP:         "::1", Ports: []varmor.Port{{Port: wrongPort}},
				}}

				// Every matrix row uses the same HTTP host, method and path.
				// Only qualifiers change. The nonmatching shadow rule above
				// keeps silent cases meaningful even when ALS is configured.
				for _, q := range row.qualifiers {
					if dst.ruleKind == "l4" {
						e.Rules = append(e.Rules, varmor.NetworkProxyEgressRule{
							Qualifiers: q, CIDR: "::/64",
							Ports: []varmor.Port{{Port: uint16(proxyPort - 1), EndPort: uint16(proxyPort)}},
						})
					} else {
						match := varmor.HTTPMatch{Hosts: []string{"::1"}, Methods: []string{"GET"}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}}}
						if dst.bracketedHost {
							match.Hosts = []string{"[::1]"}
						}
						if dst.ruleKind == "http_exact" {
							match.Ports = []varmor.Port{{Port: uint16(destinationPort)}}
						} else if dst.ruleKind == "http_range" {
							match.Ports = []varmor.Port{{Port: uint16(proxyPort - 1), EndPort: uint16(proxyPort)}}
						}
						switch row.mismatch {
						case "method":
							match.Methods = []string{"POST"}
						case "path":
							match.Paths = []varmor.HTTPPathMatch{{Exact: "/other"}}
						case "port":
							match.Ports = []varmor.Port{{Port: wrongPort}}
							if dst.ruleKind == "http_range" {
								match.Ports[0].EndPort = wrongPort + 1
							}
						}
						e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: q, Match: match})
					}
				}
				ipStack := profile.IPStackConfig{IPv6: true}
				result, err := profile.TranslateEgressRules(e, 1, uint16(proxyPort), &profile.MITMInput{Domains: []string{dst.domain}, CertificateSDSPath: mitmCertificateSDS(t, cert, key), HeadersByDomain: map[string][]profile.HeaderToAdd{dst.domain: {{Name: "X-MITM-Probe", Value: "injected"}}}}, ipStack, profile.AuditSinkConfig{ProfileName: "mitm-ipv6-test", ALSUDSPath: socket})
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
				envoyListener["address"] = mitmEgressSocketAddress(proxyPort)
				envoyListener["address"].(map[string]interface{})["socket_address"].(map[string]interface{})["address"] = "::1"
				// The test connects directly rather than via transparent redirection.
				var filters []interface{}
				for _, raw := range envoyListener["listener_filters"].([]interface{}) {
					if raw.(map[string]interface{})["name"] != "envoy.filters.listener.original_dst" {
						filters = append(filters, raw)
					}
				}
				if dst.originalPort != 0 {
					// Supply the original destination via PROXY protocol so
					// RBAC actually sees port 80/443 without binding privileged
					// ports or rewriting any generated permission.
					filters = append([]interface{}{map[string]interface{}{
						"name": "envoy.filters.listener.proxy_protocol",
						"typed_config": map[string]interface{}{
							"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol",
						},
					}}, filters...)
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
								map[string]interface{}{"lb_endpoints": []interface{}{map[string]interface{}{"endpoint": map[string]interface{}{"address": mitmEgressSocketAddress(upstreamPort)}}}},
							}},
						}
					}
					clusters = append(clusters, cluster)
				}
				// Shorten ALS batching, not audit selection, for bounded silent checks.
				mitmEgressSetFlushInterval(envoyListener)
				bootstrap := map[string]interface{}{
					"node":             map[string]interface{}{"id": "mitm-ipv6-test", "cluster": "mitm-ipv6-test"},
					"admin":            map[string]interface{}{"address": mitmEgressSocketAddress(adminPort)},
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
				var output mitmEgressLockedBuffer
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
					TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "::1", MinVersion: tls.VersionTLS12},
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("::1", strconv.Itoa(proxyPort)))
						if err != nil {
							return nil, err
						}
						if dst.originalPort != 0 {
							_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
							_, err = fmt.Fprintf(conn, "PROXY TCP6 ::1 ::1 %d %d\r\n", conn.LocalAddr().(*net.TCPAddr).Port, destinationPort)
							if err != nil {
								conn.Close()
								return nil, err
							}
							_ = conn.SetWriteDeadline(time.Time{})
						}
						return conn, nil
					},
				}
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				t.Cleanup(client.CloseIdleConnections)

				authority := "[::1]"
				switch dst.authorityMode {
				case "default_port":
					port := 443
					if dst.originalPort != 0 {
						port = destinationPort
					}
					authority = net.JoinHostPort("::1", strconv.Itoa(port))
				case "nondefault_port":
					authority = net.JoinHostPort("::1", strconv.Itoa(proxyPort))
				}
				if dst.originalPort != 0 && row.mismatch == "port" {
					// Match the rule's authority but not its destination port.
					// This detects accidentally dropping destination_port from
					// the conjunction, independently of the Host matcher.
					authority = net.JoinHostPort("::1", strconv.Itoa(int(wrongPort)))
				}
				request, err := http.NewRequest("GET", "https://"+authority+"/secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				if row.mismatch == "host" {
					request.Host = "other.example.com"
				}
				resp, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if resp.StatusCode != row.status {
					t.Errorf("HTTP=%d want %d", resp.StatusCode, row.status)
				}
				wantCalls := int32(0)
				if row.status == 200 {
					wantCalls = 1
				}
				if got := upstreamCalls.Load(); got != wantCalls {
					t.Errorf("upstream calls=%d want %d", got, wantCalls)
				}
				// Poll for expected delivery, then observe several extra flush periods
				// to detect duplicates. Silent rows observe the same bounded window.
				deadline = time.Now().Add(3 * time.Second)
				if row.action != "" {
					for len(events()) == 0 && time.Now().Before(deadline) {
						time.Sleep(20 * time.Millisecond)
					}
				}
				time.Sleep(300 * time.Millisecond)
				got := events()
				t.Logf("HTTP=%d upstream=%d events=%+v", resp.StatusCode, upstreamCalls.Load(), got)
				wantCount := 0
				if row.action != "" {
					wantCount = 1
				}
				if len(got) != wantCount {
					t.Fatalf("events=%+v; want count=%d", got, wantCount)
				}
				if wantCount == 1 && (got[0].Action != row.action || got[0].Path != "/secret" || got[0].FilterChain != "mitm_tls_ip_chain" || got[0].DstAddress != net.JoinHostPort("::1", strconv.Itoa(destinationPort))) {
					t.Fatalf("event=%+v; want action=%s on MITM /secret", got[0], row.action)
				}
			})
		}
	}
}
