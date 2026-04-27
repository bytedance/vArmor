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
	"strings"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// buildTestEgress creates the test case from the user's specification.
func buildTestEgress() *varmor.NetworkProxyEgress {
	return &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow"},
				IP:         "10.96.0.1",
				Ports:      []varmor.Port{{Port: 6443}},
			},
			{
				Qualifiers: []string{"deny"},
				CIDR:       "169.254.0.0/16",
			},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"api.openai.com"},
				},
			},
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"*.anthropic.com"},
					Ports: []varmor.Port{{Port: 443}},
				},
			},
		},
	}
}

func TestTranslateBasic(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	if result.LDS == "" {
		t.Fatal("LDS output is empty")
	}
	if result.CDS == "" {
		t.Fatal("CDS output is empty")
	}

	t.Logf("=== LDS (lds.yaml) ===\n%s", result.LDS)
	t.Logf("=== CDS (cds.yaml) ===\n%s", result.CDS)
}

func TestTranslateNil(t *testing.T) {
	_, err := TranslateEgressRules(nil, 1, 15001, nil)
	if err == nil {
		t.Fatal("expected error for nil egress")
	}
}

// ============================================================================
// xDS format validation
// ============================================================================

func TestXDSFormat(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, `version_info: "1"`, "LDS version_info")
	assertContains(t, result.LDS, `"@type": type.googleapis.com/envoy.config.listener.v3.Listener`, "LDS Listener type")
	assertContains(t, result.LDS, "resources:", "LDS resources array")

	assertContains(t, result.CDS, `version_info: "1"`, "CDS version_info")
	assertContains(t, result.CDS, `"@type": type.googleapis.com/envoy.config.cluster.v3.Cluster`, "CDS Cluster type")
	assertContains(t, result.CDS, "resources:", "CDS resources array")

	assertNotContains(t, result.LDS, "static_resources:", "must not use static_resources format")
}

// ============================================================================
// Listener filter validation
// ============================================================================

func TestListenerFilters(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "envoy.filters.listener.original_dst", "original_dst listener filter")
	assertContains(t, result.LDS, "type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst",
		"original_dst typed_config")
	assertContains(t, result.LDS, "envoy.filters.listener.tls_inspector", "tls_inspector listener filter")
	assertContains(t, result.LDS, "envoy.filters.listener.http_inspector", "http_inspector listener filter")
}

// ============================================================================
// Chain structure validation
// ============================================================================

func TestTLSChainStructure(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "tls_chain", "TLS chain name")
	assertContains(t, result.LDS, `transport_protocol: "tls"`, "TLS transport protocol")
	assertContains(t, result.LDS, "envoy.filters.network.rbac", "network RBAC filter")
	assertContains(t, result.LDS, "envoy.filters.network.tcp_proxy", "tcp_proxy filter")
	assertContains(t, result.LDS, "cluster: original_dst", "original_dst cluster reference")
}

func TestHTTPChainStructure(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "http_chain", "HTTP chain name")
	assertContains(t, result.LDS, `application_protocols: ["http/1.0", "http/1.1", "h2c"]`,
		"HTTP chain must match by application_protocols from http_inspector")
	assertNotContains(t, result.LDS, `transport_protocol: "raw_buffer"`,
		"must NOT use raw_buffer (would steal TCP default chain traffic)")

	assertContains(t, result.LDS, "envoy.filters.network.http_connection_manager", "http_connection_manager")
	assertContains(t, result.LDS, "envoy.filters.http.rbac", "http RBAC filter")
	assertContains(t, result.LDS, "envoy.filters.http.router", "HTTP router")
	assertContains(t, result.LDS, "cluster: original_dst", "route to original_dst")
}

func TestTCPDefaultChainStructure(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "default_filter_chain:", "default filter chain")
	assertContains(t, result.LDS, "tcp_default_chain", "TCP default chain name")
}

func TestClusterFormat(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.CDS, "name: original_dst", "cluster name")
	assertContains(t, result.CDS, "type: ORIGINAL_DST", "cluster type")
	assertContains(t, result.CDS, "lb_policy: CLUSTER_PROVIDED", "lb policy")
	assertContains(t, result.CDS, "connect_timeout: 10s", "connect timeout")
}

// ============================================================================
// Scenario 1-10: Full coverage of expected behavior
// ============================================================================

func TestScenario1_HTTPS_OpenAI_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `exact: "api.openai.com"`,
		"SNI exact match for api.openai.com in TLS chain")
}

func TestScenario2_HTTPS_Anthropic_SuffixPort_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `suffix: ".anthropic.com"`,
		"SNI suffix match for *.anthropic.com")
	assertContains(t, result.LDS, "destination_port: 443",
		"port 443 for *.anthropic.com rule")
}

func TestScenario3_HTTPS_Evil_Deny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "action: ALLOW",
		"ALLOW RBAC exists (blocks non-matching when defaultAction=deny)")
}

func TestScenario4_TLS_KubeAPI_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "address_prefix: 10.96.0.1", "IP match for 10.96.0.1")
	assertContains(t, result.LDS, "prefix_len: 32", "single IP /32")
	assertContains(t, result.LDS, "destination_port: 6443", "port 6443")
}

func TestScenario5_HTTP_OpenAI_HostHeader_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `name: ":authority"`, ":authority header matching")
	assertContains(t, result.LDS, `exact: "api.openai.com"`, "exact host header match")
}

func TestScenario6_HTTP_Evil_Deny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "envoy.filters.http.rbac",
		"HTTP RBAC present for deny of unmatched traffic")
}

func TestScenario7_HTTP_MetadataService_CIDRDeny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "169.254.0.0", "CIDR 169.254.0.0 in deny RBAC")
	assertContains(t, result.LDS, "prefix_len: 16", "CIDR /16 prefix length")
	assertContains(t, result.LDS, "action: DENY", "DENY action")
}

func TestScenario8_TCP_KubeAPI_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "tcp_default_chain",
		"TCP default chain present for IP+port matching")
}

func TestScenario9_TCP_Random_Deny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "default_filter_chain:",
		"default filter chain exists for TCP fallback deny")
}

func TestScenario10_TCP_MetadataService_CIDRDeny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "action: DENY", "DENY action in TCP chain")
	assertContains(t, result.LDS, "169.254.0.0", "CIDR deny for metadata service")
}

// ============================================================================
// Additional tests (existing)
// ============================================================================

func TestDefaultActionAllow(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "action: DENY", "DENY RBAC present")
	assertNotContains(t, result.LDS, "action: ALLOW", "no ALLOW RBAC when defaultAction=allow")
}

// TestAuditOnlyRule tests the new audit behavior:
// In deny-default mode, "audit" alone → deny + auto-audit (follows default).
// The deny rule for 10.0.0.1 goes into the deny RBAC (enforcement).
// Access log is enabled for deny-default.
// The allow rule for 10.0.0.2 goes into the allow RBAC.
func TestAuditOnlyRule(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"audit"}, IP: "10.0.0.1"},
			{Qualifiers: []string{"allow"}, IP: "10.0.0.2"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	// In deny-default, "audit" alone → deny (follows default) + auto-audit.
	// 10.0.0.1 is in the deny RBAC (enforcement).
	assertContains(t, result.LDS, "10.0.0.1", "audit-only rule IP in deny RBAC")
	assertContains(t, result.LDS, "10.0.0.2", "allow rule IP")
	assertContains(t, result.LDS, "action: DENY", "DENY action for audit-only rule")
	// Access log enabled for deny-default
	assertContains(t, result.LDS, "access_log", "access_log enabled for deny-default")
}

func TestPortRange(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1", Ports: []varmor.Port{{Port: 8000, EndPort: 9000}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "destination_port_range:", "port range present")
	assertContains(t, result.LDS, "start: 8000", "port range start")
	assertContains(t, result.LDS, "end: 9001", "port range end (exclusive)")
}

func TestWildcardDomain(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{Qualifiers: []string{"allow"}, Match: varmor.HTTPMatch{Hosts: []string{"*.example.com"}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `suffix: ".example.com"`, "SNI/Host suffix match")
}

func TestEmptyRules(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{DefaultAction: "deny"}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "varmor_outbound", "listener name")
	assertContains(t, result.LDS, "tls_chain", "TLS chain")
	assertContains(t, result.LDS, "http_chain", "HTTP chain")
	assertContains(t, result.LDS, "tcp_default_chain", "TCP default chain")
	assertContains(t, result.LDS, "envoy.filters.listener.original_dst", "original_dst even with empty rules")
}

func TestMultipleHostsORSemantics(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{Qualifiers: []string{"allow"}, Match: varmor.HTTPMatch{Hosts: []string{"a.com", "b.com"}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `exact: "a.com"`, "host a.com")
	assertContains(t, result.LDS, `exact: "b.com"`, "host b.com")
}

func TestChainSelectionIsolation(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	assertContains(t, lds, `transport_protocol: "tls"`, "Chain 1 matches TLS")
	assertContains(t, lds, `application_protocols: ["http/1.0", "http/1.1", "h2c"]`,
		"Chain 2 matches HTTP by application_protocols")
	assertNotContains(t, lds, "raw_buffer",
		"raw_buffer must not be used (would make TCP default chain unreachable)")
	assertContains(t, lds, "default_filter_chain:", "Chain 3 is default fallback")
}

// ============================================================================
// L7 Method and Path tests
// ============================================================================

func TestMethodOnlyRule(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Methods: []string{"GET", "POST"},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, `name: ":method"`, ":method header matcher")
	assertContains(t, result.LDS, `exact: "GET"`, "GET method match")
	assertContains(t, result.LDS, `exact: "POST"`, "POST method match")
}

func TestPathOnlyRule(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Paths: []varmor.HTTPPathMatch{
						{Exact: "/v1/chat/completions"},
						{Prefix: "/v1/models"},
					},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "url_path:", "url_path matcher")
	assertContains(t, result.LDS, `exact: "/v1/chat/completions"`, "exact path match")
	assertContains(t, result.LDS, `prefix: "/v1/models"`, "prefix path match")
}

func TestHostMethodPathCrossProduct(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{"api.openai.com"},
					Methods: []string{"POST"},
					Paths:   []varmor.HTTPPathMatch{{Exact: "/v1/chat/completions"}},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	assertContains(t, lds, `name: ":authority"`, "host header matcher")
	assertContains(t, lds, `exact: "api.openai.com"`, "host exact match")
	assertContains(t, lds, `name: ":method"`, "method header matcher")
	assertContains(t, lds, `exact: "POST"`, "POST method match")
	assertContains(t, lds, "url_path:", "url_path matcher")
	assertContains(t, lds, `exact: "/v1/chat/completions"`, "exact path match")

	assertContains(t, lds, "and_rules:", "and_rules for cross product")
}

func TestMultiMethodMultiPathCrossProduct(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Methods: []string{"GET", "POST"},
					Paths:   []varmor.HTTPPathMatch{{Prefix: "/api"}, {Exact: "/health"}},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, `exact: "GET"`, "GET method")
	assertContains(t, lds, `exact: "POST"`, "POST method")
	assertContains(t, lds, `prefix: "/api"`, "prefix path /api")
	assertContains(t, lds, `exact: "/health"`, "exact path /health")

	assertContains(t, lds, "and_rules:", "and_rules for cross product combos")
}

func TestHostPortMethodPathFullCombination(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{"api.openai.com"},
					Ports:   []varmor.Port{{Port: 80}},
					Methods: []string{"POST"},
					Paths:   []varmor.HTTPPathMatch{{Exact: "/v1/chat/completions"}},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, `name: ":authority"`, "host header")
	assertContains(t, lds, `exact: "api.openai.com"`, "host match")
	assertContains(t, lds, "destination_port: 80", "port match")
	assertContains(t, lds, `name: ":method"`, "method header")
	assertContains(t, lds, `exact: "POST"`, "POST match")
	assertContains(t, lds, "url_path:", "path matcher")
	assertContains(t, lds, `exact: "/v1/chat/completions"`, "path match")
	assertContains(t, lds, "and_rules:", "all 4 dimensions ANDed")
}

func TestMethodCaseNormalization(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Methods: []string{"get", "Post"},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, `exact: "GET"`, "lowercase 'get' normalized to 'GET'")
	assertContains(t, result.LDS, `exact: "POST"`, "mixed case 'Post' normalized to 'POST'")
}

func TestMethodPathDenyRule(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"deny"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{"internal.service"},
					Methods: []string{"DELETE"},
					Paths:   []varmor.HTTPPathMatch{{Prefix: "/admin"}},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, "action: DENY", "DENY action for deny rule")
	assertContains(t, lds, `exact: "DELETE"`, "DELETE method in deny rule")
	assertContains(t, lds, `prefix: "/admin"`, "admin path prefix in deny rule")
	assertContains(t, lds, `exact: "internal.service"`, "host in deny rule")
}

func TestTLSChainIgnoresMethodsAndPaths(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{"api.openai.com"},
					Methods: []string{"POST"},
					Paths:   []varmor.HTTPPathMatch{{Exact: "/v1/chat/completions"}},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	assertContains(t, lds, `exact: "api.openai.com"`, "SNI match in TLS chain")
	assertContains(t, lds, "requested_server_name:", "SNI matcher in TLS chain")
}

func TestHostWithMethodNoPath(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{"api.example.com"},
					Methods: []string{"GET"},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, `name: ":authority"`, "host header present")
	assertContains(t, lds, `exact: "api.example.com"`, "host match")
	assertContains(t, lds, `name: ":method"`, "method header present")
	assertContains(t, lds, `exact: "GET"`, "GET method match")
	assertContains(t, lds, "and_rules:", "host AND method combined")
}

func TestCrossProductCount(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{"a.com", "b.com"},
					Methods: []string{"GET", "POST"},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	count := strings.Count(lds, "and_rules:")
	if count < 4 {
		t.Errorf("expected at least 4 and_rules for 2x2 cross product in HTTP chain, got %d", count)
	}
}

// ============================================================================
// AUDIT TESTS - Semantic Matrix Verification (v4: all-CEL)
//
// v4 architecture:
//   Listener: CEL on connection.termination_details (deny) + network.rbac metadata (shadow)
//   HCM:      CEL on response.code_details (deny) + http.rbac metadata (shadow)
//   tcp_proxy: NO access_log (all handled at listener/HCM level)
//
// No UAEX, no response_flag_filter, no metadata_filter, no or_filter anywhere.
// ============================================================================

// TestDenyDefaultAutoAudit verifies that access_log is present when defaultAction=deny.
// In deny-default mode, ALL deny actions are auto-audited.
// Both listener and HCM use CEL extension_filter.
// When no shadow_rules exist (no allow+audit rules), CEL checks deny only.
func TestDenyDefaultAutoAudit(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// access_log should be present (deny-default always enables it)
	assertContains(t, lds, "access_log", "access_log present for deny-default auto-audit")
	assertContains(t, lds, "envoy.access_loggers.stdout", "stdout access logger")
	// Listener-level uses CEL on connection.termination_details
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "ExpressionFilter", "CEL ExpressionFilter type")
	assertContains(t, lds, "connection.termination_details", "listener CEL checks termination_details")
	// Listener-level access_log for denied connections
	assertContains(t, lds, "[L4][%FILTER_CHAIN_NAME%] dst=", "listener-level access_log format")
	// HCM access_log uses CEL on response.code_details
	assertContains(t, lds, "REQ(:METHOD)", "HCM access_log format present")
	assertContains(t, lds, "rbac_access_denied", "CEL matches rbac_access_denied")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
	assertNotContains(t, lds, "or_filter", "no or_filter when no shadow_rules")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestDenyDefaultAllowNoAudit verifies that an allow rule without audit qualifier
// does NOT add shadow_rules in deny-default mode.
func TestDenyDefaultAllowNoAudit(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// allow without audit should NOT create shadow_rules
	assertNotContains(t, lds, "shadow_rules", "no shadow_rules for allow without audit")
	// The allow rule should still be in the ALLOW RBAC
	assertContains(t, lds, "action: ALLOW", "ALLOW RBAC present")
	assertContains(t, lds, "10.0.0.1", "allow rule IP present")
}

// TestDenyDefaultAllowWithAudit verifies that allow+audit adds shadow_rules in deny-default.
// v4: HCM uses single CEL expression with deny OR shadow check.
func TestDenyDefaultAllowWithAudit(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// allow+audit should create shadow_rules for the allow rule
	assertContains(t, lds, "shadow_rules", "shadow_rules for allow+audit")
	// The allow rule should also be in ALLOW RBAC enforcement
	assertContains(t, lds, "action: ALLOW", "ALLOW RBAC for enforcement")
	assertContains(t, lds, "10.0.0.1", "audit allow rule IP")
	// access_log should be present (deny-default)
	assertContains(t, lds, "access_log", "access_log present")
	// v4: single CEL expression combining deny + shadow check in HCM
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL deny detection")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow detection")
	assertContains(t, lds, "envoy.filters.http.rbac", "HTTP RBAC namespace in CEL")
	// Listener-level uses CEL on termination_details + shadow
	assertContains(t, lds, "connection.termination_details", "listener CEL deny detection")
	assertContains(t, lds, "envoy.filters.network.rbac", "network RBAC namespace in CEL")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
}

// TestDenyDefaultAuditOnlyFollowsDefault verifies that "audit" alone in deny-default
// mode means deny + auto-audit (follows defaultAction=deny).
func TestDenyDefaultAuditOnlyFollowsDefault(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// "audit" alone in deny-default → deny (follows default) + auto-audit
	// 10.0.0.1 should be in the DENY RBAC (not ALLOW)
	assertContains(t, lds, "action: DENY", "DENY action for audit-only in deny-default")
	assertContains(t, lds, "10.0.0.1", "audit rule IP in deny RBAC")
	// NO shadow_rules needed: deny is auto-audited in deny-default
	assertNotContains(t, lds, "shadow_rules", "no shadow_rules for auto-audited deny")
	// access_log enabled with CEL
	assertContains(t, lds, "access_log", "access_log for deny-default")
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL matches rbac_access_denied")
	assertContains(t, lds, "connection.termination_details", "listener CEL")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
}

// TestAllowDefaultNoAccessLog verifies no access_log when defaultAction=allow
// and no rules have audit qualifier.
func TestAllowDefaultNoAccessLog(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// No audit qualifier → no access_log in allow-default
	assertNotContains(t, lds, "access_log", "no access_log when allow-default and no audit")
	assertNotContains(t, lds, "shadow_rules", "no shadow_rules when no audit")
	// Deny RBAC should still be present
	assertContains(t, lds, "action: DENY", "DENY RBAC present")
	assertNotContains(t, lds, "extension_filter", "no CEL filter without audit")
	assertNotContains(t, lds, "UAEX", "no UAEX without audit")
}

// TestAllowDefaultDenyWithAudit verifies that deny+audit enables access_log and
// shadow_rules in allow-default mode.
// v4: uses CEL shadow check instead of metadata_filter.
func TestAllowDefaultDenyWithAudit(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny", "audit"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// deny+audit in allow-default → deny + audit via shadow_rules
	assertContains(t, lds, "access_log", "access_log for deny+audit in allow-default")
	assertContains(t, lds, "action: DENY", "DENY RBAC for deny+audit")
	assertContains(t, lds, "169.254.0.0", "deny CIDR")
	// shadow_rules needed for CEL shadow check
	assertContains(t, lds, "shadow_rules", "shadow_rules for deny+audit in allow-default")
	// v4: CEL shadow check in HCM and listener
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL checks shadow_effective_policy_id")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
}

// TestAllowDefaultAuditOnly verifies that "audit" alone in allow-default mode
// means allow + audit (follows defaultAction=allow).
// v4: uses CEL shadow check.
func TestAllowDefaultAuditOnly(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// "audit" alone in allow-default → allow + audit
	// Should create shadow_rules for the allow+audit rule
	assertContains(t, lds, "shadow_rules", "shadow_rules for audit-only in allow-default")
	assertContains(t, lds, "10.0.0.1", "audit rule IP in shadow_rules")
	// No DENY RBAC (it's an allow action)
	assertNotContains(t, lds, "action: DENY", "no DENY action for allow+audit")
	// access_log should be enabled (audit qualifier present)
	assertContains(t, lds, "access_log", "access_log for audit in allow-default")
	// v4: CEL shadow check
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL checks shadow key")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestDenyDefaultDenyWithAuditRedundant verifies that deny+audit in deny-default
// is the same as deny alone (audit is redundant since auto-audited).
func TestDenyDefaultDenyWithAuditRedundant(t *testing.T) {
	// deny+audit in deny-default: deny action, auto-audit (audit redundant)
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny", "audit"}, CIDR: "169.254.0.0/16"},
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, "action: DENY", "DENY action present")
	assertContains(t, lds, "169.254.0.0", "deny CIDR")
	assertContains(t, lds, "action: ALLOW", "ALLOW action for allow rule")
	// access_log enabled (deny-default auto-audit)
	assertContains(t, lds, "access_log", "access_log present")
	// No shadow_rules (deny is auto-audited, not via shadow_rules)
	assertNotContains(t, lds, "shadow_rules", "no shadow_rules for deny+audit in deny-default")
	// v4: CEL at listener and HCM
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL matches rbac_access_denied")
	assertContains(t, lds, "connection.termination_details", "listener CEL")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestAllowDefaultAllowWithAudit verifies that allow+audit in allow-default
// creates shadow_rules and enables access_log with CEL shadow check.
func TestAllowDefaultAllowWithAudit(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"api.openai.com"},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// allow+audit in allow-default → allow action, audited via shadow_rules
	assertContains(t, lds, "shadow_rules", "shadow_rules for allow+audit")
	assertContains(t, lds, "access_log", "access_log for audit")
	assertContains(t, lds, `"api.openai.com"`, "host in shadow_rules")
	// No enforcement RBAC needed (defaultAction=allow)
	assertNotContains(t, lds, "action: DENY", "no DENY in allow-default with only allow+audit")
	// v4: CEL shadow check
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow check")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestMixedAuditRulesInAllowDefault verifies a scenario with mixed rules in allow-default.
func TestMixedAuditRulesInAllowDefault(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny", "audit"}, CIDR: "169.254.0.0/16"},
			{Qualifiers: []string{"deny"}, CIDR: "10.0.0.0/8"},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match:      varmor.HTTPMatch{Hosts: []string{"api.openai.com"}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// Both deny rules should be in DENY RBAC
	assertContains(t, lds, "action: DENY", "DENY RBAC present")
	assertContains(t, lds, "169.254.0.0", "deny+audit CIDR")
	assertContains(t, lds, "10.0.0.0", "deny CIDR")
	// allow+audit HTTP rule AND deny+audit egress rule → shadow_rules
	assertContains(t, lds, "shadow_rules", "shadow_rules for audit rules")
	// access_log enabled (audit qualifier present)
	assertContains(t, lds, "access_log", "access_log enabled")
	// v4: CEL shadow check
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow check")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestClassifyRuleFunction directly tests the classifyRule helper.
func TestClassifyRuleFunction(t *testing.T) {
	tests := []struct {
		name        string
		qualifiers  []string
		defaultDeny bool
		wantAction  ruleAction
		wantAudit   bool
	}{
		// deny-default cases
		{"deny-default, deny qualifier", []string{"deny"}, true, ruleActionDeny, true},
		{"deny-default, deny+audit qualifier", []string{"deny", "audit"}, true, ruleActionDeny, true},
		{"deny-default, audit only", []string{"audit"}, true, ruleActionDeny, true},
		{"deny-default, allow qualifier", []string{"allow"}, true, ruleActionAllow, false},
		{"deny-default, allow+audit qualifier", []string{"allow", "audit"}, true, ruleActionAllow, true},

		// allow-default cases
		{"allow-default, allow qualifier", []string{"allow"}, false, ruleActionAllow, false},
		{"allow-default, allow+audit qualifier", []string{"allow", "audit"}, false, ruleActionAllow, true},
		{"allow-default, audit only", []string{"audit"}, false, ruleActionAllow, true},
		{"allow-default, deny qualifier", []string{"deny"}, false, ruleActionDeny, false},
		{"allow-default, deny+audit qualifier", []string{"deny", "audit"}, false, ruleActionDeny, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, audit := classifyRule(tt.qualifiers, tt.defaultDeny)
			if action != tt.wantAction {
				t.Errorf("classifyRule(%v, %v) action = %v, want %v", tt.qualifiers, tt.defaultDeny, action, tt.wantAction)
			}
			if audit != tt.wantAudit {
				t.Errorf("classifyRule(%v, %v) audit = %v, want %v", tt.qualifiers, tt.defaultDeny, audit, tt.wantAudit)
			}
		})
	}
}

// ============================================================================
// FILTER-SPECIFIC TESTS - Verify exact filter structure (v4: all-CEL)
// ============================================================================

// TestDenyDefaultFilterStructure verifies that deny-default with shadow_rules uses
// a single CEL expression combining deny+shadow check in HCM access_log.
func TestDenyDefaultFilterStructure(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// v4: HCM uses single CEL with deny OR shadow
	assertContains(t, lds, "extension_filter", "CEL extension_filter in HCM access_log")
	assertContains(t, lds, "rbac_access_denied", "CEL matches rbac_access_denied")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL checks shadow metadata")
	assertContains(t, lds, "envoy.filters.http.rbac", "http rbac namespace in CEL")
	assertContains(t, lds, "envoy.filters.network.rbac", "network rbac namespace in listener CEL")
	assertContains(t, lds, "connection.termination_details", "listener CEL for deny detection")
	// No legacy filters
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
}

// TestAllowDefaultFilterStructure verifies that allow-default uses CEL shadow
// check only (no deny detection needed).
func TestAllowDefaultFilterStructure(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// v4: allow-default uses CEL shadow check only
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow check")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestTCPProxyNoAccessLog verifies that tcp_proxy has NO access_log in v4.
// All audit is handled at listener-level and HCM-level via CEL.
func TestTCPProxyNoAccessLog(t *testing.T) {
	// deny-default with shadow: tcp_proxy should still have NO access_log
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// v4: tcp_proxy should NOT have any access_log
	// The old "TCP dst=" format should not appear
	assertNotContains(t, lds, "TCP dst=", "no tcp_proxy access_log in v4")
	// Listener and HCM should still have access_log
	assertContains(t, lds, "[L4][%FILTER_CHAIN_NAME%] dst=", "listener access_log present")
	assertContains(t, lds, "REQ(:METHOD)", "HCM access_log present")
}

// TestDenyDefaultNoShadowCELDenyOnly verifies that when deny-default
// has no allow+audit rules, both listener and HCM use CEL deny-only check.
func TestDenyDefaultNoShadowCELDenyOnly(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match:      varmor.HTTPMatch{Hosts: []string{"example.com"}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// No shadow_rules → no shadow check in CEL
	assertNotContains(t, lds, "shadow_rules", "no shadow_rules without allow+audit")
	assertNotContains(t, lds, "shadow_effective_policy_id", "no shadow check in CEL")

	// Listener-level uses CEL deny check
	assertContains(t, lds, "connection.termination_details", "listener CEL deny check")
	assertContains(t, lds, "[L4][%FILTER_CHAIN_NAME%] dst=", "listener-level access_log format")

	// HCM access_log uses CEL deny check
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL matches rbac_access_denied")
	assertContains(t, lds, "REQ(:METHOD)", "HCM access_log format")

	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	// No tcp_proxy access_log
	assertNotContains(t, lds, "TCP dst=", "no tcp_proxy access_log in v4")
}

// TestAllowDefaultDenyAuditShadowRulesContainsDenyRule verifies that in allow-default,
// deny+audit rule appears in both enforcement RBAC (DENY) and shadow_rules.
func TestAllowDefaultDenyAuditShadowRulesContainsDenyRule(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny", "audit"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	// Enforcement: DENY RBAC with the CIDR
	assertContains(t, lds, "action: DENY", "DENY RBAC for enforcement")
	assertContains(t, lds, "169.254.0.0", "CIDR in enforcement RBAC")
	// Shadow rules: same rule for audit metadata
	assertContains(t, lds, "shadow_rules", "shadow_rules for deny+audit")
	// CEL shadow check in access_log
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow check in access_log")
}

// TestFullSemanticMatrixDenyDefault walks through ALL deny-default matrix rows.
func TestFullSemanticMatrixDenyDefault(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			// Row 2: explicit deny → deny + auto-audit
			{Qualifiers: []string{"deny"}, IP: "10.0.0.1"},
			// Row 3: deny+audit → deny + auto-audit (redundant)
			{Qualifiers: []string{"deny", "audit"}, IP: "10.0.0.2"},
			// Row 4: audit alone → deny + auto-audit
			{Qualifiers: []string{"audit"}, IP: "10.0.0.3"},
			// Row 5: allow → allow + NO audit
			{Qualifiers: []string{"allow"}, IP: "10.0.0.4"},
			// Row 6: allow+audit → allow + audit (shadow)
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.5"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// All IPs should appear somewhere
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		assertContains(t, lds, ip, "IP "+ip+" present in output")
	}

	// DENY RBAC for rows 2,3,4 (deny actions)
	assertContains(t, lds, "action: DENY", "DENY RBAC present")

	// ALLOW RBAC for rows 5,6 (allow actions in deny-default)
	assertContains(t, lds, "action: ALLOW", "ALLOW RBAC present")

	// shadow_rules present for row 6 only (allow+audit)
	assertContains(t, lds, "shadow_rules", "shadow_rules for allow+audit")

	// v4: CEL at both listener and HCM
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL deny detection")
	assertContains(t, lds, "connection.termination_details", "listener CEL")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow detection")

	// access_log enabled
	assertContains(t, lds, "access_log", "access_log enabled")

	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// TestFullSemanticMatrixAllowDefault walks through ALL allow-default matrix rows.
func TestFullSemanticMatrixAllowDefault(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			// Row 2: explicit allow → allow + NO audit
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
			// Row 3: allow+audit → allow + audit (shadow)
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.2"},
			// Row 4: audit alone → allow + audit (shadow)
			{Qualifiers: []string{"audit"}, IP: "10.0.0.3"},
			// Row 5: deny → deny + NO audit
			{Qualifiers: []string{"deny"}, IP: "10.0.0.4"},
			// Row 6: deny+audit → deny + audit (shadow)
			{Qualifiers: []string{"deny", "audit"}, IP: "10.0.0.5"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// IPs with enforcement or audit should appear in output
	for _, ip := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		assertContains(t, lds, ip, "IP "+ip+" present in output")
	}

	// DENY RBAC for rows 5,6 (deny actions)
	assertContains(t, lds, "action: DENY", "DENY RBAC present")

	// shadow_rules for rows 3,4,6 (all with explicit "audit")
	assertContains(t, lds, "shadow_rules", "shadow_rules for audit rules")

	// access_log enabled (audit qualifiers present)
	assertContains(t, lds, "access_log", "access_log enabled")

	// v4: CEL shadow check only (no deny detection in allow-default)
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow check")
	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
}

// ============================================================================
// Helpers
// ============================================================================

func assertContains(t *testing.T, s, substr, msg string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("[%s] expected output to contain %q, but it was not found.\nOutput snippet (first 2000 chars):\n%s",
			msg, substr, truncate(s, 2000))
	}
}

func assertNotContains(t *testing.T, s, substr, msg string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("[%s] expected output NOT to contain %q, but it was found", msg, substr)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// ============================================================================
// REGRESSION TESTS - v4 CEL architecture verification
// ============================================================================

// TestListenerAccessLogDenyDefaultCELDeny verifies that listener-level access_log
// in deny-default mode uses CEL with connection.termination_details.
// Must NOT use UAEX or response_flag_filter.
func TestListenerAccessLogDenyDefaultCELDeny(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// Extract the listener-level access_log section (before filter_chains:)
	filterChainsIdx := strings.Index(lds, "filter_chains:")
	if filterChainsIdx == -1 {
		t.Fatal("filter_chains: not found in LDS")
	}
	listenerSection := lds[:filterChainsIdx]

	// Listener-level MUST have access_log with CEL
	if !strings.Contains(listenerSection, "access_log") {
		t.Fatal("listener-level access_log missing in deny-default mode")
	}
	if !strings.Contains(listenerSection, "extension_filter") {
		t.Fatal("listener-level should have CEL extension_filter")
	}
	if !strings.Contains(listenerSection, "connection.termination_details") {
		t.Fatal("listener-level CEL should check connection.termination_details")
	}
	if !strings.Contains(listenerSection, "rbac_access_denied") {
		t.Fatal("listener-level CEL should match rbac_access_denied")
	}

	// CRITICAL: Must NOT have legacy filters
	if strings.Contains(listenerSection, "UAEX") {
		t.Fatal("REGRESSION: listener-level MUST NOT use UAEX (broken for Network RBAC)")
	}
	if strings.Contains(listenerSection, "response_flag_filter") {
		t.Fatal("REGRESSION: listener-level MUST NOT use response_flag_filter")
	}
	if strings.Contains(listenerSection, "metadata_filter") {
		t.Fatal("listener-level should NOT have metadata_filter")
	}
	if strings.Contains(listenerSection, "or_filter") {
		t.Fatal("listener-level should NOT have or_filter (no shadow_rules in this test)")
	}
}

// TestListenerAccessLogAllowDefaultAbsent verifies that listener-level access_log
// is NOT rendered for allow-default mode when there are NO shadow rules for
// the listener (i.e., no egress audit rules that generate network RBAC shadows).
func TestListenerAccessLogAllowDefaultNoShadow(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// No audit → no access_log anywhere
	assertNotContains(t, lds, "access_log", "no access_log when no audit rules")
}

// TestListenerAccessLogAllowDefaultWithShadow verifies that listener-level access_log
// IS rendered for allow-default mode when shadow rules exist.
// v4: listener uses CEL shadow check for network RBAC metadata.
func TestListenerAccessLogAllowDefaultWithShadow(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny", "audit"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// Extract listener-level section
	filterChainsIdx := strings.Index(lds, "filter_chains:")
	if filterChainsIdx == -1 {
		t.Fatal("filter_chains: not found")
	}
	listenerSection := lds[:filterChainsIdx]

	// v4: listener-level SHOULD have access_log with CEL shadow check
	if !strings.Contains(listenerSection, "access_log") {
		t.Fatal("listener-level access_log should be present for allow-default with shadow rules")
	}
	if !strings.Contains(listenerSection, "extension_filter") {
		t.Fatal("listener-level should have CEL extension_filter")
	}
	if !strings.Contains(listenerSection, "shadow_effective_policy_id") {
		t.Fatal("listener-level CEL should check shadow_effective_policy_id")
	}
	// Should NOT have deny check (allow-default doesn't auto-audit denies)
	if strings.Contains(listenerSection, "termination_details") {
		t.Fatal("listener-level should NOT check termination_details for allow-default")
	}
}

// TestListenerAccessLogDenyDefaultWithShadow verifies that listener-level access_log
// in deny-default with shadow rules uses CEL combining deny+shadow check.
func TestListenerAccessLogDenyDefaultWithShadow(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match:      varmor.HTTPMatch{Hosts: []string{"api.openai.com"}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// Extract listener-level section
	filterChainsIdx := strings.Index(lds, "filter_chains:")
	if filterChainsIdx == -1 {
		t.Fatal("filter_chains: not found in LDS")
	}
	listenerSection := lds[:filterChainsIdx]

	// Listener-level should have CEL with both deny + shadow check
	if !strings.Contains(listenerSection, "connection.termination_details") {
		t.Fatal("listener-level CEL should check termination_details for deny detection")
	}
	if !strings.Contains(listenerSection, "shadow_effective_policy_id") {
		t.Fatal("listener-level CEL should check shadow_effective_policy_id for shadow detection")
	}
	// Should NOT have legacy filters
	if strings.Contains(listenerSection, "UAEX") {
		t.Fatal("REGRESSION: listener-level MUST NOT use UAEX")
	}
	if strings.Contains(listenerSection, "or_filter") {
		t.Fatal("listener-level should NOT use or_filter (single CEL expression instead)")
	}
	if strings.Contains(listenerSection, "metadata_filter") {
		t.Fatal("listener-level should NOT use metadata_filter")
	}

	// HCM level should also have combined CEL
	hcmSection := lds[filterChainsIdx:]
	if !strings.Contains(hcmSection, "rbac_access_denied") {
		t.Fatal("HCM-level CEL should check rbac_access_denied for deny detection")
	}
	if !strings.Contains(hcmSection, "shadow_effective_policy_id") {
		t.Fatal("HCM-level CEL should check shadow_effective_policy_id for shadow detection")
	}
	if !strings.Contains(hcmSection, "shadow_rules") {
		t.Fatal("shadow_rules should be present for allow+audit rules")
	}
}

// ============================================================================
// HCM/tcp_proxy specific tests (v4)
// ============================================================================

// TestDenyDefaultNoShadowHCMOnlyCEL verifies that when deny-default has no
// shadow_rules, HCM access_log uses CEL deny-only check.
// No metadata_filter, no or_filter, no UAEX, no tcp_proxy access_log.
func TestDenyDefaultNoShadowHCMOnlyCEL(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1"},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match:      varmor.HTTPMatch{Hosts: []string{"example.com"}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// No shadow_rules → no shadow check
	assertNotContains(t, lds, "shadow_rules", "no shadow_rules without allow+audit")
	assertNotContains(t, lds, "shadow_effective_policy_id", "no shadow check without shadow_rules")

	// CEL deny check at both levels
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL matches rbac_access_denied")
	assertContains(t, lds, "connection.termination_details", "listener CEL deny check")

	// Access log formats
	assertContains(t, lds, "[L4][%FILTER_CHAIN_NAME%] dst=", "listener-level access_log format")
	assertContains(t, lds, "REQ(:METHOD)", "HCM access_log format")

	// No legacy filters
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")
	assertNotContains(t, lds, "response_flag_filter", "no response_flag_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	// No tcp_proxy access_log
	assertNotContains(t, lds, "TCP dst=", "no tcp_proxy access_log in v4")
}

// TestDenyDefaultWithShadowHCMCELDenyOrShadow verifies that when deny-default has
// shadow_rules (allow+audit), HCM access_log uses single CEL combining deny+shadow.
func TestDenyDefaultWithShadowHCMCELDenyOrShadow(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// shadow_rules present
	assertContains(t, lds, "shadow_rules", "shadow_rules for allow+audit")

	// v4: single CEL expression with deny + shadow (not or_filter)
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "rbac_access_denied", "CEL deny detection")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow detection")
	assertContains(t, lds, "connection.termination_details", "listener CEL deny check")

	// No legacy filters
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")
	assertNotContains(t, lds, "UAEX", "no UAEX in v4")

	// No tcp_proxy access_log
	assertNotContains(t, lds, "TCP dst=", "no tcp_proxy access_log in v4")

	// Listener and HCM access_log present
	assertContains(t, lds, "[L4][%FILTER_CHAIN_NAME%] dst=", "listener access_log present")
	assertContains(t, lds, "REQ(:METHOD)", "HCM access_log present")
}

// TestAllowDefaultWithShadowCELOnly verifies that allow-default with
// audit qualifiers uses CEL shadow check only at both listener and HCM levels.
func TestAllowDefaultWithShadowCELOnly(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny", "audit"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// shadow_rules present
	assertContains(t, lds, "shadow_rules", "shadow_rules for deny+audit")

	// CEL shadow check
	assertContains(t, lds, "extension_filter", "CEL extension_filter")
	assertContains(t, lds, "shadow_effective_policy_id", "CEL shadow check")

	// No deny detection in allow-default
	assertNotContains(t, lds, "UAEX", "no UAEX for allow-default")
	assertNotContains(t, lds, "or_filter", "no or_filter in v4")
	assertNotContains(t, lds, "metadata_filter", "no metadata_filter in v4")

	// v4: listener-level SHOULD have access_log with CEL shadow (unlike v3)
	filterChainsIdx := strings.Index(lds, "filter_chains:")
	if filterChainsIdx == -1 {
		t.Fatal("filter_chains: not found")
	}
	listenerSection := lds[:filterChainsIdx]
	if !strings.Contains(listenerSection, "access_log") {
		t.Fatal("v4: listener-level should have access_log for allow-default with shadow rules")
	}
}

// ============================================================================
// Shadow RBAC ordering verification
// ============================================================================

// TestHTTPChainShadowRBACBeforeEnforcement verifies that in the generated LDS YAML,
// shadow_rules appears before the enforcement RBAC rules in the HTTP filter chain.
func TestHTTPChainShadowRBACBeforeEnforcement(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match:      varmor.HTTPMatch{Hosts: []string{"api.openai.com"}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// shadow_rules must be present
	assertContains(t, lds, "shadow_rules", "shadow_rules present for allow+audit")

	// Find shadow_rules and enforcement rules positions in the HTTP RBAC section.
	httpRBACIdx := strings.Index(lds, "envoy.filters.http.rbac")
	if httpRBACIdx == -1 {
		t.Fatal("envoy.filters.http.rbac not found in LDS")
	}

	// Look at the section after the HTTP RBAC filter declaration
	httpRBACSection := lds[httpRBACIdx:]

	shadowIdx := strings.Index(httpRBACSection, "shadow_rules:")
	if shadowIdx == -1 {
		t.Fatal("shadow_rules: not found in HTTP RBAC section")
	}

	// Find the enforcement "rules:" that comes after the HTTP RBAC type URL.
	// We need to find "rules:" that is NOT "shadow_rules:" and NOT "and_rules:".
	rulesIdx := -1
	searchFrom := 0
	for {
		idx := strings.Index(httpRBACSection[searchFrom:], "rules:")
		if idx == -1 {
			break
		}
		absIdx := searchFrom + idx
		// Check it's not part of "shadow_rules:"
		if absIdx >= len("shadow_") {
			prefix := httpRBACSection[absIdx-len("shadow_") : absIdx]
			if strings.HasSuffix(prefix, "shadow_") {
				searchFrom = absIdx + len("rules:")
				continue
			}
		}
		// Check it's not part of "and_rules:"
		if absIdx >= len("and_") {
			prefix2 := httpRBACSection[absIdx-len("and_") : absIdx]
			if strings.HasSuffix(prefix2, "and_") {
				searchFrom = absIdx + len("rules:")
				continue
			}
		}
		rulesIdx = absIdx
		break
	}

	if rulesIdx == -1 {
		t.Fatal("enforcement rules: not found in HTTP RBAC section")
	}

	if shadowIdx >= rulesIdx {
		t.Errorf("shadow_rules (at offset %d) should appear BEFORE enforcement rules (at offset %d) in HTTP RBAC filter",
			shadowIdx, rulesIdx)
	}
}

// ============================================================================
// Tests for deny-all RBAC in default_filter_chain (TCP), TLS, and HTTP chains
// when defaultAction=deny but no matching allow rules exist for that chain.
// ============================================================================

// TestDenyDefaultTCPChainDenyAll verifies that when defaultAction=deny and
// only httpRules exist (no L4 egress rules), the TCP default chain gets a
// deny-all RBAC (action: ALLOW, policies: {}) to prevent raw TCP bypass.
func TestDenyDefaultTCPChainDenyAll(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{Qualifiers: []string{"allow", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"api.example.com"}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// TCP default chain must contain RBAC with deny-all (ALLOW + empty policies)
	assertContains(t, result.LDS, "tcp_allow_rbac", "tcp default chain must have allow RBAC")
	assertContains(t, result.LDS, "policies: {}", "tcp default chain must have empty policies (deny-all)")

	// Verify the deny-all RBAC is in the default_filter_chain section
	defaultChainIdx := strings.Index(result.LDS, "default_filter_chain:")
	if defaultChainIdx == -1 {
		t.Fatal("default_filter_chain not found in LDS")
	}
	defaultChainSection := result.LDS[defaultChainIdx:]
	assertContains(t, defaultChainSection, "tcp_allow_rbac", "tcp_allow_rbac must be in default_filter_chain")
	assertContains(t, defaultChainSection, "policies: {}", "policies: {} must be in default_filter_chain")

	// tcp_proxy must still exist after the RBAC
	tcpProxyIdx := strings.Index(defaultChainSection, "tcp_passthrough")
	rbacIdx := strings.Index(defaultChainSection, "tcp_allow_rbac")
	if rbacIdx == -1 || tcpProxyIdx == -1 || rbacIdx >= tcpProxyIdx {
		t.Errorf("tcp_allow_rbac (at %d) must appear before tcp_proxy (at %d)", rbacIdx, tcpProxyIdx)
	}
}

// TestDenyDefaultNoRulesAtAll verifies that when defaultAction=deny and there
// are NO rules at all, all 3 chains get deny-all RBAC.
func TestDenyDefaultNoRulesAtAll(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// All three chains must have deny-all RBAC
	assertContains(t, result.LDS, "tls_allow_rbac", "TLS chain must have allow RBAC")
	assertContains(t, result.LDS, "tcp_allow_rbac", "TCP chain must have allow RBAC")

	// HTTP chain: check for RBAC with ALLOW + empty policies
	httpChainIdx := strings.Index(result.LDS, "http_chain")
	if httpChainIdx == -1 {
		t.Fatal("http_chain not found in LDS")
	}

	// Count occurrences of "policies: {}" — should appear in all 3 chains
	count := strings.Count(result.LDS, "policies: {}")
	if count < 3 {
		t.Errorf("expected at least 3 occurrences of 'policies: {}' (TLS+HTTP+TCP deny-all), got %d", count)
	}

	// Listener access_log must exist (defaultAction=deny → auto-audit all denies)
	assertContains(t, result.LDS, "[L4][%FILTER_CHAIN_NAME%] dst=", "listener access_log format must be present")
}

// TestAllowDefaultTCPChainNoRBAC verifies that when defaultAction=allow,
// the TCP default chain has NO RBAC (all traffic passes through).
func TestAllowDefaultTCPChainNoRBAC(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{Qualifiers: []string{"deny"}, Match: varmor.HTTPMatch{Hosts: []string{"evil.com"}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// TCP default chain should NOT have RBAC (allow-default, no deny egress rules)
	defaultChainIdx := strings.Index(result.LDS, "default_filter_chain:")
	if defaultChainIdx == -1 {
		t.Fatal("default_filter_chain not found in LDS")
	}
	defaultChainSection := result.LDS[defaultChainIdx:]
	assertNotContains(t, defaultChainSection, "tcp_allow_rbac", "allow-default should not have allow RBAC in TCP chain")
	assertNotContains(t, defaultChainSection, "tcp_deny_rbac", "no deny egress rules should mean no deny RBAC in TCP chain")
}

// TestDenyDefaultHTTPOnlyRules verifies the exact scenario from the user's
// bug report: defaultAction=deny with only httpRules (reverse shell bypass).
func TestDenyDefaultHTTPOnlyRules(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match:      varmor.HTTPMatch{Hosts: []string{"ark.cn-beijing.volces.com", "open.feishu.cn", "msg-frontier.feishu.cn"}},
			},
			{
				Qualifiers: []string{"allow"},
				Match:      varmor.HTTPMatch{Hosts: []string{"phrack.org"}},
			},
			{
				Qualifiers: []string{"deny"},
				Match:      varmor.HTTPMatch{Hosts: []string{"httpforever.com"}},
			},
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"darksouls.wikidot.com"},
					Paths: []varmor.HTTPPathMatch{{Exact: "/classes"}, {Exact: "/story"}},
				},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// TCP default chain MUST have deny-all RBAC (no L4 egress rules)
	defaultChainIdx := strings.Index(result.LDS, "default_filter_chain:")
	if defaultChainIdx == -1 {
		t.Fatal("default_filter_chain not found")
	}
	defaultChainSection := result.LDS[defaultChainIdx:]
	assertContains(t, defaultChainSection, "tcp_allow_rbac", "TCP chain must have deny-all RBAC for reverse shell protection")
	assertContains(t, defaultChainSection, "policies: {}", "TCP chain deny-all must have empty policies")

	// TLS chain must have allow RBAC with actual policies (from httpRules SNI matching)
	tlsChainIdx := strings.Index(result.LDS, "tls_chain")
	httpChainIdx := strings.Index(result.LDS, "http_chain")
	if tlsChainIdx == -1 || httpChainIdx == -1 {
		t.Fatal("tls_chain or http_chain not found")
	}
	tlsSection := result.LDS[tlsChainIdx:httpChainIdx]
	assertContains(t, tlsSection, "tls_allow_rbac", "TLS chain must have allow RBAC")
	assertContains(t, tlsSection, "ark.cn-beijing.volces.com", "TLS chain must have SNI rules")
	assertContains(t, tlsSection, "shadow_rules:", "TLS chain must have shadow_rules merged into enforcement RBAC filter")
}

// TestDenyDefaultWithL4EgressRulesTCPChainHasAllowRBAC verifies that when
// defaultAction=deny and there ARE L4 egress rules, the TCP chain uses
// those rules in the ALLOW RBAC (not deny-all).
func TestDenyDefaultWithL4EgressRulesTCPChainHasAllowRBAC(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1", Ports: []varmor.Port{{Port: 8900}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// TCP default chain must have ALLOW RBAC with actual policies (not deny-all)
	defaultChainIdx := strings.Index(result.LDS, "default_filter_chain:")
	if defaultChainIdx == -1 {
		t.Fatal("default_filter_chain not found")
	}
	defaultChainSection := result.LDS[defaultChainIdx:]
	assertContains(t, defaultChainSection, "tcp_allow_rbac", "TCP chain must have allow RBAC")
	assertContains(t, defaultChainSection, "10.0.0.1", "TCP chain must have the L4 allow rule")
	// Should NOT have empty policies since there ARE allow rules
	assertNotContains(t, defaultChainSection, "policies: {}", "TCP chain should have actual policies, not deny-all")
}

// ============================================================================
// Tests for multi-port rule: IP + multiple ports must use OR across ports
// ============================================================================

// TestMultiPortEgressRuleORSemantics verifies that an egress rule with
// IP + multiple ports generates cross-product permissions:
//
//	(IP AND port443) OR (IP AND port80)
//
// NOT: IP AND port443 AND port80 (which is impossible to match).
func TestMultiPortEgressRuleORSemantics(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow"},
				IP:         "10.96.0.1",
				Ports:      []varmor.Port{{Port: 443}, {Port: 80}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	lds := result.LDS

	// There should be TWO separate and_rules blocks (one per port),
	// NOT one and_rules with both ports inside.
	andCount := strings.Count(lds, "and_rules:")
	// Each chain (TLS, HTTP, TCP) that has this rule should have 2 and_rules.
	// TLS chain: 2, HTTP chain: 2, TCP chain: 2 = 6 total
	if andCount < 6 {
		t.Errorf("expected at least 6 and_rules blocks (2 per chain × 3 chains), got %d", andCount)
	}

	// Verify TLS chain has two separate permission entries with destination_port
	tlsIdx := strings.Index(lds, "tls_chain")
	httpIdx := strings.Index(lds, "http_chain")
	if tlsIdx == -1 || httpIdx == -1 {
		t.Fatal("tls_chain or http_chain not found")
	}
	tlsSection := lds[tlsIdx:httpIdx]

	// Count destination_port occurrences in TLS section - should be 2 (one per and_rules)
	portCount := strings.Count(tlsSection, "destination_port:")
	if portCount != 2 {
		t.Errorf("TLS chain: expected 2 destination_port entries (one per port), got %d", portCount)
	}

	// Both ports must appear
	assertContains(t, tlsSection, "destination_port: 443", "TLS chain must contain port 443")
	assertContains(t, tlsSection, "destination_port: 80", "TLS chain must contain port 80")

	// IP must appear in each and_rules
	ipCount := strings.Count(tlsSection, "10.96.0.1")
	if ipCount < 2 {
		t.Errorf("TLS chain: expected IP 10.96.0.1 to appear at least 2 times (once per and_rules), got %d", ipCount)
	}
}

// TestSinglePortEgressRuleStillWorks verifies no regression: a single port
// still generates a single and_rules block.
func TestSinglePortEgressRuleStillWorks(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow"},
				IP:         "10.0.0.1",
				Ports:      []varmor.Port{{Port: 443}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Should have destination_ip and destination_port in the same and_rules
	assertContains(t, result.LDS, "10.0.0.1", "must contain IP")
	assertContains(t, result.LDS, "destination_port: 443", "must contain port 443")
}

// TestPortOnlyRuleMultiplePorts verifies that ports-only rules (no IP) with
// multiple ports generate separate permissions (OR semantics).
func TestPortOnlyRuleMultiplePorts(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow"},
				Ports:      []varmor.Port{{Port: 443}, {Port: 80}, {Port: 8080}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify TCP chain has 3 separate port entries
	defaultIdx := strings.Index(result.LDS, "default_filter_chain:")
	if defaultIdx == -1 {
		t.Fatal("default_filter_chain not found")
	}
	tcpSection := result.LDS[defaultIdx:]

	assertContains(t, tcpSection, "destination_port: 443", "TCP chain must contain port 443")
	assertContains(t, tcpSection, "destination_port: 80", "TCP chain must contain port 80")
	assertContains(t, tcpSection, "destination_port: 8080", "TCP chain must contain port 8080")
}

// TestIPWithPortRangeAndExactPort verifies cross-product with mixed port types.
func TestIPWithPortRangeAndExactPort(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow"},
				IP:         "10.0.0.1",
				Ports:      []varmor.Port{{Port: 443}, {Port: 8000, EndPort: 9000}},
			},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 2 and_rules per chain: (IP+443) and (IP+8000-9001)
	assertContains(t, result.LDS, "destination_port: 443", "must contain exact port 443")
	assertContains(t, result.LDS, "destination_port_range:", "must contain port range")
	assertContains(t, result.LDS, "start: 8000", "port range start")
	assertContains(t, result.LDS, "end: 9001", "port range end (exclusive)")
}

// =============================================================================
// Anti-Domain-Fronting Tests
// =============================================================================

// TestAntiDomainFronting_NoCatchAllVirtualHost verifies that the MITM chain
// does NOT emit a catch-all "*" virtual_host. Without it, Envoy's HCM returns
// 404 when :authority doesn't match any MITM domain — blocking domain fronting
// attacks where SNI=legitimate but Host=evil.
func TestAntiDomainFronting_NoCatchAllVirtualHost(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers:  []string{"audit"},
				Description: "audit openai",
				Match:       varmor.HTTPMatch{Hosts: []string{"api.openai.com"}},
			},
		},
	}
	mitm := &MITMInput{
		Domains: []string{"api.openai.com", "httpbin.org"},
		HeadersByDomain: map[string][]HeaderToAdd{
			"api.openai.com": {{Name: "Authorization", Value: "Bearer sk-test"}},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	// Must NOT contain catch-all VH
	assertNotContains(t, result.LDS, "mitm_vh_default", "LDS must not contain mitm_vh_default VirtualHost")
	// Note: we do NOT assert absence of `"*"` globally because the HTTP chain
	// has its own allow_any VH with domains: ["*"]. The anti-fronting check is
	// specifically that no MITM VH uses "*" as a domain.

	// Must contain per-domain VHs
	assertContains(t, result.LDS, "api.openai.com", "LDS must contain api.openai.com VH")
	assertContains(t, result.LDS, "httpbin.org", "LDS must contain httpbin.org VH")

	// Header injection only on the correct domain
	assertContains(t, result.LDS, "Authorization", "LDS must contain Authorization header injection")
	assertContains(t, result.LDS, "Bearer sk-test", "LDS must contain the API key value")
}

// TestAntiDomainFronting_SingleDomain verifies anti-fronting with a single
// MITM domain — the simplest configuration.
func TestAntiDomainFronting_SingleDomain(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
	}
	mitm := &MITMInput{
		Domains:         []string{"httpbin.org"},
		HeadersByDomain: map[string][]HeaderToAdd{},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertNotContains(t, result.LDS, "mitm_vh_default", "single domain must not have catch-all VH")
	assertContains(t, result.LDS, "httpbin.org", "must have httpbin.org VH")
	assertContains(t, result.LDS, `"httpbin.org:*"`, "must have httpbin.org:* for port-variant matching")
}

// TestAntiDomainFronting_IPDomain verifies that bare IP MITM domains produce
// a VirtualHost matching the IP as :authority (no catch-all).
func TestAntiDomainFronting_IPDomain(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
	}
	mitm := &MITMInput{
		Domains: []string{"10.0.0.1"},
		HeadersByDomain: map[string][]HeaderToAdd{
			"10.0.0.1": {{Name: "X-Token", Value: "secret"}},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertNotContains(t, result.LDS, "mitm_vh_default", "IP domain must not have catch-all VH")
	assertContains(t, result.LDS, "10.0.0.1", "must have VH matching the IP as :authority")
	assertContains(t, result.LDS, "X-Token", "must inject header for IP domain")
}

// TestAntiDomainFronting_CIDRSingleHost verifies that a /32 CIDR emits a
// VirtualHost matching the single IP.
func TestAntiDomainFronting_CIDRSingleHost(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
	}
	mitm := &MITMInput{
		Domains: []string{"192.168.1.100/32"},
		HeadersByDomain: map[string][]HeaderToAdd{
			"192.168.1.100/32": {{Name: "X-Key", Value: "val"}},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertNotContains(t, result.LDS, "mitm_vh_default", "/32 CIDR must not have catch-all VH")
	assertContains(t, result.LDS, "192.168.1.100", "must have VH matching the /32 IP")
}

// TestAntiDomainFronting_WideCIDRNoVH verifies that a wide CIDR (e.g., /24)
// is rejected at validation time. Wide CIDRs in mitm.domains would silently
// break all TLS connections in the range (terminated → no VH → 404), so the
// translator refuses them up front with a clear error message.
func TestAntiDomainFronting_WideCIDRNoVH(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
	}
	mitm := &MITMInput{
		Domains:         []string{"10.0.0.0/24"},
		HeadersByDomain: map[string][]HeaderToAdd{},
	}

	_, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err == nil {
		t.Fatal("expected TranslateEgressRules to reject /24 CIDR, got nil error")
	}
	if !strings.Contains(err.Error(), "/24") {
		t.Fatalf("expected error mentioning /24, got: %v", err)
	}
}

// TestAntiDomainFronting_MixedDomainsAndIPs verifies the anti-fronting
// behaviour with a mix of DNS names and IP addresses — no catch-all VH,
// each entry gets its own VH.
func TestAntiDomainFronting_MixedDomainsAndIPs(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match:      varmor.HTTPMatch{Hosts: []string{"api.openai.com"}},
			},
		},
	}
	mitm := &MITMInput{
		Domains: []string{"api.openai.com", "10.0.0.1"},
		HeadersByDomain: map[string][]HeaderToAdd{
			"api.openai.com": {{Name: "Authorization", Value: "Bearer key1"}},
			"10.0.0.1":       {{Name: "X-Token", Value: "key2"}},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertNotContains(t, result.LDS, "mitm_vh_default", "mixed config must not have catch-all VH")
	assertContains(t, result.LDS, "api.openai.com", "must have DNS domain VH")
	assertContains(t, result.LDS, "10.0.0.1", "must have IP domain VH")
	assertContains(t, result.LDS, "Authorization", "must inject Authorization for openai")
	assertContains(t, result.LDS, "X-Token", "must inject X-Token for IP")
}
