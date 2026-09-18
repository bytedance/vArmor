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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// TestMITMEgressEnvoyAudit is opt-in: ENVOY_BINARY must name an installed
// Envoy executable. It exercises actual TLS, RBAC, CEL, gRPC ALS and this
// package's production consumer. No Docker, Kubernetes or iptables is needed.
// Only transport plumbing is adapted: listen on loopback and replace
// ORIGINAL_DST upstream clusters with a local HTTP server. Generated MITM
// chains, virtual hosts, RBAC predicates and access loggers remain in use.
// The listener's actual loopback destination is used in IP/CIDR/port rules;
// DNS cases keep SNI independent of that address. No DNS lookup is needed.
func TestMITMEgressEnvoyAudit(t *testing.T) {
	runMITMEgressEnvoyAudit(t, httpHostTestOptions{})
}

// Exercise all eight audit rows with mixed-case HTTP authorities after TLS
// termination. SNI stays lowercase so the test isolates HTTP RBAC matching.
func TestHTTPHostCaseEnvoyAudit(t *testing.T) {
	for _, tc := range []struct {
		name, pattern           string
		bindPort, authorityPort bool
	}{
		{"exact", "api.example.com", false, false},
		{"prefix", "Api.Example.COM", false, true},
		{"exact_nondefault", "api.example.com", true, true},
		{"suffix", "*.Example.COM", true, true},
		{"regex", "*.Example.COM", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runMITMEgressEnvoyAudit(t, httpHostTestOptions{pattern: tc.pattern, bindPort: tc.bindPort, authorityPort: tc.authorityPort})
		})
	}
}

// Supply the original destination using PROXY protocol without changing RBAC
// predicates or binding privileged ports. Port 80 uses HTTP; 443 uses MITM TLS.
func TestHTTPDefaultPortEnvoyAudit(t *testing.T) {
	for _, host := range []struct{ name, pattern string }{
		{"dns", "Api.Example.COM"}, {"ipv4", "127.0.0.1"}, {"wildcard", "*.Example.COM"},
	} {
		for _, port := range []uint16{80, 443} {
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/explicit_%t", host.name, port, explicit), func(t *testing.T) {
					runMITMEgressEnvoyAudit(t, httpHostTestOptions{pattern: host.pattern, bindPort: true, authorityPort: explicit, defaultPort: port})
				})
			}
		}
	}
}

// Selection options exercise the same IP branch with different protocols and
// authorities. An empty DNS target deliberately configures IP-only MITM.
type mitmIPSelectionOptions struct {
	ip, dns         string
	expectedChain   string
	plaintext, ipv6 bool
}

type httpHostTestOptions struct {
	mitmIPSelection         *mitmIPSelectionOptions
	hostCIDRCertificate     bool
	pattern                 string
	bindPort, authorityPort bool
	defaultPort             uint16
}

func runMITMEgressEnvoyAudit(t *testing.T, options httpHostTestOptions) {
	binary := envoyBinary(t)
	type auditRow struct {
		name, defaultAction string
		qualifiers          [][]string
		status              int
		action, mismatch    string
	}
	rows := []auditRow{
		{"allow_unmatched", "allow", nil, 200, "", ""},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}, 403, "", ""},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}, 403, "DENIED", ""},
		{"allow_audit", "allow", [][]string{{"audit"}}, 200, "AUDIT", ""},
		{"deny_unmatched", "deny", nil, 403, "DENIED", ""},
		{"deny_allow", "deny", [][]string{{"allow"}}, 200, "", ""},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}, 200, "AUDIT", ""},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}, 403, "DENIED", ""},
		{"allow_wrong_ip", "allow", [][]string{{"deny", "audit"}}, 200, "", "ip"},
		{"deny_wrong_ip", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", "ip"},
		{"allow_wrong_port", "allow", [][]string{{"deny", "audit"}}, 200, "", "port"},
		{"deny_wrong_port", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", "port"},
	}
	if options.pattern == "" {
		rows = append(rows,
			auditRow{"allow_same_prefix_ip", "allow", [][]string{{"deny", "audit"}}, 200, "", "same_prefix_ip"},
			auditRow{"deny_same_prefix_ip", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", "same_prefix_ip"},
		)
	}
	// Exercise IPv6 destinations through DNS/SNI here. Direct bracketed
	// IPv6 authorities are covered by TestMITMIPv6EnvoyAudit.
	destinations := []struct{ name, localIP, domain, ruleIP, ruleCIDR, chain string }{
		{"dns_ipv4_ip", "127.0.0.1", "api.example.com", "127.0.0.1", "", "mitm_tls_dns_chain"},
		{"dns_ipv4_cidr", "127.0.0.1", "api.example.com", "", "127.0.0.0/8", "mitm_tls_dns_chain"},
		{"ip_ipv4_cidr", "127.0.0.1", "127.0.0.1", "", "127.0.0.0/8", "mitm_tls_ip_chain"},
		{"dns_ipv6_ip", "::1", "api.example.com", "::1", "", "mitm_tls_dns_chain"},
		{"dns_ipv6_cidr", "::1", "api.example.com", "", "::/64", "mitm_tls_dns_chain"},
	}
	if options.hostCIDRCertificate {
		ipDestination := destinations[0]
		destinations = destinations[:0]
		for _, host := range []string{"127.0.0.1", "::1"} {
			dst := ipDestination
			dst.name, dst.localIP, dst.domain = "host_cidr_"+host, host, host
			dst.ruleIP, dst.ruleCIDR, dst.chain = host, "", "mitm_tls_ip_chain"
			destinations = append(destinations, dst)
		}
		rows = rows[:8]
	}
	if options.pattern != "" {
		destinations = destinations[:1]
		if options.defaultPort == 0 {
			rows = rows[:8]
		} else {
			if net.ParseIP(options.pattern) != nil {
				destinations[0].domain = options.pattern
				destinations[0].chain = "mitm_tls_ip_chain"
			}
			if options.defaultPort == 80 {
				destinations[0].chain = "http_chain"
			}
			for i := range rows {
				if rows[i].mismatch == "ip" {
					rows[i].name = strings.ReplaceAll(rows[i].name, "ip", "host")
					rows[i].mismatch = "host"
				}
			}
			for _, mismatch := range []string{"authority_port", "method", "path"} {
				rows = append(rows,
					auditRow{"allow_wrong_" + mismatch, "allow", [][]string{{"deny", "audit"}}, 200, "", mismatch},
					auditRow{"deny_wrong_" + mismatch, "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", mismatch},
				)
			}
		}
	}
	if sel := options.mitmIPSelection; sel != nil {
		destinations = destinations[:1]
		dst := &destinations[0]
		if sel.ipv6 {
			dst.localIP = "::1"
		}
		dst.name = "selection"
		dst.ruleIP = dst.localIP
		if net.ParseIP(options.pattern) != nil {
			dst.domain = options.pattern
		}
		if sel.plaintext {
			dst.chain = "http_ip_chain"
		} else if sel.dns != "" {
			dst.chain = "mitm_tls_dns_ip_chain"
		} else {
			dst.chain = "mitm_tls_ip_chain"
		}
		if sel.expectedChain != "" {
			dst.chain = sel.expectedChain
		}
	}
	for _, dst := range destinations {
		for _, row := range rows {
			t.Run(dst.name+"/"+row.name, func(t *testing.T) {
				dir := t.TempDir()
				var cert, key string
				var roots *x509.CertPool
				var expectedLeaf []byte
				mitmDomain := dst.domain
				if options.hostCIDRCertificate {
					prefix := "/128"
					if net.ParseIP(dst.domain).To4() != nil {
						prefix = "/32"
					}
					mitmDomain += prefix
					cert, key, roots, expectedLeaf = hostCIDRCertificate(t, dir, mitmDomain)
				} else {
					cert, key, roots = testCertificate(t, dir, dst.domain)
				}
				// Keep the UDS path short even for long subtest names.
				socket, events := startAuditCollector(t)
				var upstreamCalls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(upstream.Close)
				upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
				proxyPort, adminPort := freePort(t, dst.localIP), freePort(t, "127.0.0.1")
				for adminPort == proxyPort {
					adminPort = freePort(t, "127.0.0.1")
				}

				rulePort, destinationPort := proxyPort, proxyPort
				if options.defaultPort != 0 {
					rulePort, destinationPort = int(options.defaultPort), int(options.defaultPort)
					if row.mismatch == "port" {
						destinationPort++
					}
				}

				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
				wrongPort := uint16(1)
				if proxyPort == 1 {
					wrongPort = 2
				}
				// A nonmatching audited rule keeps the logger present for
				// silent rows and detects accidental removal of port limits.
				e.Rules = []varmor.NetworkProxyEgressRule{{
					Qualifiers: []string{"allow", "audit"},
					IP:         dst.localIP, Ports: []varmor.Port{{Port: wrongPort}},
				}}
				for _, q := range row.qualifiers {
					rule := varmor.NetworkProxyEgressRule{
						Qualifiers: q, IP: dst.ruleIP, CIDR: dst.ruleCIDR,
						Ports: []varmor.Port{{Port: uint16(proxyPort - 1), EndPort: uint16(proxyPort)}},
					}
					switch row.mismatch {
					case "ip":
						rule.IP, rule.CIDR = "192.0.2.1", ""
						if net.ParseIP(dst.localIP).To4() == nil {
							rule.IP = "2001:db8::1"
						}
					case "same_prefix_ip":
						// ::2 and ::1 share /32, but are distinct host addresses.
						rule.IP, rule.CIDR = "127.0.0.2", ""
						if net.ParseIP(dst.localIP).To4() == nil {
							rule.IP = "::2"
						}
					case "port":
						rule.Ports = []varmor.Port{{Port: wrongPort}}
					}
					e.Rules = append(e.Rules, rule)
				}
				if options.pattern != "" {
					for _, rule := range e.Rules[1:] {
						match := varmor.HTTPMatch{Hosts: []string{options.pattern}}
						if options.bindPort {
							match.Ports = []varmor.Port{{Port: uint16(rulePort)}}
						}
						if options.defaultPort != 0 {
							match.Methods = []string{"GET"}
							match.Paths = []varmor.HTTPPathMatch{{Exact: "/secret"}}
							switch row.mismatch {
							case "host":
								match.Hosts = []string{"other.example.com"}
							case "method":
								match.Methods = []string{"POST"}
							case "path":
								match.Paths = []varmor.HTTPPathMatch{{Exact: "/Secret"}}
							}
						}
						e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: rule.Qualifiers, Match: match})
					}
					e.Rules = e.Rules[:1] // Keep only the nonmatching audit control.
				}
				ipStack := profile.IPStackConfig{IPv4: true}
				if net.ParseIP(dst.localIP).To4() == nil {
					ipStack = profile.IPStackConfig{IPv6: true}
				}
				mitm := &profile.MITMInput{Domains: []string{mitmDomain}, CertificateSDSPath: certificateSDS(t, cert, key)}
				if options.defaultPort == 80 {
					mitm = nil
				}
				if sel := options.mitmIPSelection; sel != nil {
					mitm = &profile.MITMInput{Domains: []string{sel.ip}, CertificateSDSPath: certificateSDS(t, cert, key)}
					if sel.dns != "" {
						mitm.Domains = append(mitm.Domains, sel.dns)
					}
				}
				result, err := profile.TranslateEgressRules(e, 1, uint16(proxyPort), mitm, ipStack, profile.AuditSinkConfig{ProfileName: "mitm-egress-test", ALSUDSPath: socket})
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
				envoyListener["address"].(map[string]interface{})["socket_address"].(map[string]interface{})["address"] = dst.localIP
				// The test connects directly rather than via transparent redirection.
				var filters []interface{}
				for _, raw := range envoyListener["listener_filters"].([]interface{}) {
					if raw.(map[string]interface{})["name"] != "envoy.filters.listener.original_dst" {
						filters = append(filters, raw)
					}
				}
				if options.defaultPort != 0 {
					filters = append([]interface{}{map[string]interface{}{
						"name":         "envoy.filters.listener.proxy_protocol",
						"typed_config": map[string]interface{}{"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol"},
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
								map[string]interface{}{"lb_endpoints": []interface{}{map[string]interface{}{"endpoint": map[string]interface{}{"address": socketAddress(upstreamPort)}}}},
							}},
						}
					}
					clusters = append(clusters, cluster)
				}
				// Shorten ALS batching, not audit selection, for bounded silent checks.
				setALSFlushInterval(envoyListener)
				bootstrap := map[string]interface{}{
					"node":             map[string]interface{}{"id": "mitm-egress-test", "cluster": "mitm-egress-test"},
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
					TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: dst.domain, MinVersion: tls.VersionTLS12},
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(dst.localIP, strconv.Itoa(proxyPort)))
						if err != nil {
							return nil, err
						}
						if options.defaultPort != 0 {
							if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
								conn.Close()
								return nil, err
							}
							_, err = fmt.Fprintf(conn, "PROXY TCP4 127.0.0.1 %s %d %d\r\n", dst.localIP, conn.LocalAddr().(*net.TCPAddr).Port, destinationPort)
							if err != nil {
								conn.Close()
								return nil, err
							}
							if err := conn.SetWriteDeadline(time.Time{}); err != nil {
								conn.Close()
								return nil, err
							}
						}
						return conn, nil
					},
				}
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				t.Cleanup(client.CloseIdleConnections)
				scheme, urlPort := "https", 443
				if options.defaultPort != 0 {
					urlPort = rulePort
				}
				if options.defaultPort == 80 || (options.mitmIPSelection != nil && options.mitmIPSelection.plaintext) {
					scheme = "http"
				}
				req, err := http.NewRequest(http.MethodGet, scheme+"://"+net.JoinHostPort(dst.domain, strconv.Itoa(urlPort))+"/secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				if options.pattern != "" {
					req.Host = strings.ToUpper(dst.domain)
					if options.authorityPort || row.mismatch == "authority_port" {
						port := rulePort
						if row.mismatch == "authority_port" {
							port++
						}
						req.Host = net.JoinHostPort(req.Host, strconv.Itoa(port))
					}
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if options.hostCIDRCertificate && (resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 || len(resp.TLS.PeerCertificates) == 0 || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, expectedLeaf)) {
					t.Error("Envoy did not present the verified production-issued certificate")
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
				deadline := time.Now().Add(3 * time.Second)
				if row.action != "" {
					for len(events()) == 0 && time.Now().Before(deadline) {
						time.Sleep(20 * time.Millisecond)
					}
				}
				time.Sleep(300 * time.Millisecond)
				got := events()
				wantCount := 0
				if row.action != "" {
					wantCount = 1
				}
				if len(got) != wantCount {
					t.Fatalf("events=%+v; want count=%d", got, wantCount)
				}
				if wantCount == 1 && (got[0].Action != row.action || got[0].Path != "/secret" || got[0].FilterChain != dst.chain || got[0].DstAddress != net.JoinHostPort(dst.localIP, strconv.Itoa(destinationPort))) {
					t.Fatalf("event=%+v; want action=%s chain=%s on /secret", got[0], row.action, dst.chain)
				}
			})
		}
	}
}
