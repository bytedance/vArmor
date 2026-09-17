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

import "testing"

// TestMITMIPSelectionEnvoyAudit covers the destination-IP branch that Envoy
// chooses before SNI and transport protocol. Every variant runs the eight-row
// audit matrix against actual HTTP RBAC and the production ALS consumer.
func TestMITMIPSelectionEnvoyAudit(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		selection  mitmIPSelectionOptions
	}{
		{"plain_ip_only_dns_host", "api.example.com", mitmIPSelectionOptions{ip: "127.0.0.1", plaintext: true}},
		{"plain_ip_host", "127.0.0.1", mitmIPSelectionOptions{ip: "127.0.0.1/32", plaintext: true}},
		{"plain_mixed", "api.example.com", mitmIPSelectionOptions{ip: "127.0.0.1", dns: "api.example.com", plaintext: true}},
		{"tls_dns_overlap", "api.example.com", mitmIPSelectionOptions{ip: "127.0.0.1", dns: "api.example.com"}},
		{"tls_wildcard_overlap", "*.example.com", mitmIPSelectionOptions{ip: "127.0.0.1/32", dns: "*.example.com"}},
		{"tls_ip_no_sni_mixed", "127.0.0.1", mitmIPSelectionOptions{ip: "127.0.0.1", dns: "api.example.com", expectedChain: "mitm_tls_ip_chain"}},
		{"tls_ip_no_sni", "127.0.0.1", mitmIPSelectionOptions{ip: "127.0.0.1/32"}},
		{"plain_ipv6_dns_host", "api.example.com", mitmIPSelectionOptions{ip: "::1/128", plaintext: true, ipv6: true}},
		{"plain_ipv6_ip_host", "::1", mitmIPSelectionOptions{ip: "::1", plaintext: true, ipv6: true}},
		{"tls_ipv6_ip_no_sni", "::1", mitmIPSelectionOptions{ip: "::1/128", ipv6: true}},
		{"plain_outside_ip", "api.example.com", mitmIPSelectionOptions{ip: "127.0.0.2", plaintext: true, expectedChain: "http_chain"}},
		{"tls_dns_outside_ip", "api.example.com", mitmIPSelectionOptions{ip: "127.0.0.2", dns: "api.example.com", expectedChain: "mitm_tls_dns_chain"}},
		{"tls_ipv6_dns_overlap", "api.example.com", mitmIPSelectionOptions{ip: "::1/128", dns: "api.example.com", ipv6: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runMITMEgressEnvoyAudit(t, httpHostTestOptions{pattern: tc.host, bindPort: true, authorityPort: true, mitmIPSelection: &tc.selection})
		})
	}
}

// Default-port cases also test nonmatching Host, destination/authority port,
// method and path, while custom ports are covered by the main selection matrix.
func TestMITMIPDefaultPortEnvoyAudit(t *testing.T) {
	for _, tc := range []struct {
		name string
		port uint16
	}{{"http", 80}, {"https", 443}} {
		t.Run(tc.name, func(t *testing.T) {
			runMITMEgressEnvoyAudit(t, httpHostTestOptions{pattern: "api.example.com", bindPort: true, defaultPort: tc.port,
				mitmIPSelection: &mitmIPSelectionOptions{ip: "127.0.0.1", dns: "api.example.com", plaintext: tc.port == 80}})
		})
	}
}

// Both new candidates must retain destination IP and port constraints from L4 rules.
func TestMITMIPSelectionL4EnvoyAudit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection mitmIPSelectionOptions
	}{
		{"plain_ipv4", mitmIPSelectionOptions{ip: "127.0.0.1", plaintext: true}},
		{"tls_dns_ipv4", mitmIPSelectionOptions{ip: "127.0.0.1", dns: "api.example.com"}},
		{"plain_ipv6", mitmIPSelectionOptions{ip: "::1/128", plaintext: true, ipv6: true}},
		{"tls_dns_ipv6", mitmIPSelectionOptions{ip: "::1/128", dns: "api.example.com", ipv6: true}},
	} {
		t.Run(tc.name, func(t *testing.T) { runMITMEgressEnvoyAudit(t, httpHostTestOptions{mitmIPSelection: &tc.selection}) })
	}
}
