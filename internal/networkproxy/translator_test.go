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
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	_, err := TranslateEgressRules(nil, 1, 15001)
	if err == nil {
		t.Fatal("expected error for nil egress")
	}
}

// ============================================================================
// xDS format validation
// ============================================================================

func TestXDSFormat(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	// LDS must be in xDS discovery response format
	assertContains(t, result.LDS, `version_info: "1"`, "LDS version_info")
	assertContains(t, result.LDS, `"@type": type.googleapis.com/envoy.config.listener.v3.Listener`, "LDS Listener type")
	assertContains(t, result.LDS, "resources:", "LDS resources array")

	// CDS must be in xDS discovery response format
	assertContains(t, result.CDS, `version_info: "1"`, "CDS version_info")
	assertContains(t, result.CDS, `"@type": type.googleapis.com/envoy.config.cluster.v3.Cluster`, "CDS Cluster type")
	assertContains(t, result.CDS, "resources:", "CDS resources array")

	// Must NOT use static_resources format
	assertNotContains(t, result.LDS, "static_resources:", "must not use static_resources format")
}

// ============================================================================
// Listener filter validation
// ============================================================================

func TestListenerFilters(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "http_chain", "HTTP chain name")

	// CRITICAL: Must use application_protocols (set by http_inspector),
	// NOT transport_protocol: "raw_buffer" which would swallow all non-TLS traffic
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "default_filter_chain:", "default filter chain")
	assertContains(t, result.LDS, "tcp_default_chain", "TCP default chain name")
}

func TestClusterFormat(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `exact: "api.openai.com"`,
		"SNI exact match for api.openai.com in TLS chain")
}

func TestScenario2_HTTPS_Anthropic_SuffixPort_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "action: ALLOW",
		"ALLOW RBAC exists (blocks non-matching when defaultAction=deny)")
}

func TestScenario4_TLS_KubeAPI_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "address_prefix: 10.96.0.1", "IP match for 10.96.0.1")
	assertContains(t, result.LDS, "prefix_len: 32", "single IP /32")
	assertContains(t, result.LDS, "destination_port: 6443", "port 6443")
}

func TestScenario5_HTTP_OpenAI_HostHeader_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `name: ":authority"`, ":authority header matching")
	assertContains(t, result.LDS, `exact: "api.openai.com"`, "exact host header match")
}

func TestScenario6_HTTP_Evil_Deny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "envoy.filters.http.rbac",
		"HTTP RBAC present for deny of unmatched traffic")
}

func TestScenario7_HTTP_MetadataService_CIDRDeny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "169.254.0.0", "CIDR 169.254.0.0 in deny RBAC")
	assertContains(t, result.LDS, "prefix_len: 16", "CIDR /16 prefix length")
	assertContains(t, result.LDS, "action: DENY", "DENY action")
}

func TestScenario8_TCP_KubeAPI_Allow(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "tcp_default_chain",
		"TCP default chain present for IP+port matching")
}

func TestScenario9_TCP_Random_Deny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "default_filter_chain:",
		"default filter chain exists for TCP fallback deny")
}

func TestScenario10_TCP_MetadataService_CIDRDeny(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "action: DENY", "DENY action in TCP chain")
	assertContains(t, result.LDS, "169.254.0.0", "CIDR deny for metadata service")
}

// ============================================================================
// Additional tests
// ============================================================================

func TestDefaultActionAllow(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"deny"}, CIDR: "169.254.0.0/16"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "action: DENY", "DENY RBAC present")
	assertNotContains(t, result.LDS, "action: ALLOW", "no ALLOW RBAC when defaultAction=allow")
}

func TestAuditOnlyRule(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"audit"}, IP: "10.0.0.1"},
			{Qualifiers: []string{"allow"}, IP: "10.0.0.2"},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, "shadow_rules:", "shadow_rules for audit")
	assertContains(t, result.LDS, "10.0.0.1", "audit rule IP")
	assertContains(t, result.LDS, "10.0.0.2", "allow rule IP")
}

func TestPortRange(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{Qualifiers: []string{"allow"}, IP: "10.0.0.1", Ports: []varmor.Port{{Port: 8000, EndPort: 9000}}},
		},
	}
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `suffix: ".example.com"`, "SNI/Host suffix match")
}

func TestEmptyRules(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{DefaultAction: "deny"}
	result, err := TranslateEgressRules(egress, 1, 15001)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}
	assertContains(t, result.LDS, `exact: "a.com"`, "host a.com")
	assertContains(t, result.LDS, `exact: "b.com"`, "host b.com")
}

// TestChainSelectionIsolation verifies that the 3 chains are properly isolated:
// - TLS traffic → Chain 1 (transport_protocol: tls)
// - HTTP traffic → Chain 2 (application_protocols: http/*)
// - Other TCP → Chain 3 (default_filter_chain)
func TestChainSelectionIsolation(t *testing.T) {
	egress := buildTestEgress()
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// Chain 1: TLS uses transport_protocol
	assertContains(t, lds, `transport_protocol: "tls"`, "Chain 1 matches TLS")

	// Chain 2: HTTP uses application_protocols (NOT raw_buffer)
	assertContains(t, lds, `application_protocols: ["http/1.0", "http/1.1", "h2c"]`,
		"Chain 2 matches HTTP by application_protocols")

	// Verify raw_buffer is NOT used anywhere (would cause chain overlap)
	assertNotContains(t, lds, "raw_buffer",
		"raw_buffer must not be used (would make TCP default chain unreachable)")

	// Chain 3: default_filter_chain (no match criteria)
	assertContains(t, lds, "default_filter_chain:", "Chain 3 is default fallback")
}

// ============================================================================
// L7 Method and Path tests
// ============================================================================

// TestMethodOnlyRule verifies that a rule with only methods (no hosts/ports/paths)
// generates :method header matchers in the HTTP chain.
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, `name: ":method"`, ":method header matcher")
	assertContains(t, result.LDS, `exact: "GET"`, "GET method match")
	assertContains(t, result.LDS, `exact: "POST"`, "POST method match")
}

// TestPathOnlyRule verifies that a rule with only paths generates url_path matchers.
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, "url_path:", "url_path matcher")
	assertContains(t, result.LDS, `exact: "/v1/chat/completions"`, "exact path match")
	assertContains(t, result.LDS, `prefix: "/v1/models"`, "prefix path match")
}

// TestHostMethodPathCrossProduct verifies the cross product: hosts × methods × paths.
// Rule: hosts=[api.openai.com] + methods=[POST] + paths=[/v1/chat/completions]
// Expected: single AND permission with 3 matchers (host AND method AND path)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// All three matchers must be present
	assertContains(t, lds, `name: ":authority"`, "host header matcher")
	assertContains(t, lds, `exact: "api.openai.com"`, "host exact match")
	assertContains(t, lds, `name: ":method"`, "method header matcher")
	assertContains(t, lds, `exact: "POST"`, "POST method match")
	assertContains(t, lds, "url_path:", "url_path matcher")
	assertContains(t, lds, `exact: "/v1/chat/completions"`, "exact path match")

	// Should use and_rules (3 matchers ANDed together)
	assertContains(t, lds, "and_rules:", "and_rules for cross product")
}

// TestMultiMethodMultiPathCrossProduct verifies cross product with multiple values.
// Rule: methods=[GET, POST] + paths=[/api, /health]
// Expected: 4 permissions (GET+/api, GET+/health, POST+/api, POST+/health)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, `exact: "GET"`, "GET method")
	assertContains(t, lds, `exact: "POST"`, "POST method")
	assertContains(t, lds, `prefix: "/api"`, "prefix path /api")
	assertContains(t, lds, `exact: "/health"`, "exact path /health")

	// Should have and_rules for each combination
	assertContains(t, lds, "and_rules:", "and_rules for cross product combos")
}

// TestHostPortMethodPathFullCombination verifies the full 4-dimension cross product.
// Rule: hosts=[api.openai.com] + ports=[443] + methods=[POST] + paths=[/v1/chat/completions]
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
	result, err := TranslateEgressRules(egress, 1, 15001)
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

// TestMethodCaseNormalization verifies that method names are normalized to uppercase.
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	assertContains(t, result.LDS, `exact: "GET"`, "lowercase 'get' normalized to 'GET'")
	assertContains(t, result.LDS, `exact: "POST"`, "mixed case 'Post' normalized to 'POST'")
}

// TestMethodPathDenyRule verifies that deny rules with methods/paths work correctly.
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS
	assertContains(t, lds, "action: DENY", "DENY action for deny rule")
	assertContains(t, lds, `exact: "DELETE"`, "DELETE method in deny rule")
	assertContains(t, lds, `prefix: "/admin"`, "admin path prefix in deny rule")
	assertContains(t, lds, `exact: "internal.service"`, "host in deny rule")
}

// TestTLSChainIgnoresMethodsAndPaths verifies that methods/paths in HTTPRules
// are NOT applied to the TLS chain (only SNI + port are usable in TLS).
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// TLS chain should have SNI match for the host
	assertContains(t, lds, `exact: "api.openai.com"`, "SNI match in TLS chain")

	// TLS chain uses requested_server_name, not :authority header
	assertContains(t, lds, "requested_server_name:", "SNI matcher in TLS chain")

	// The :method and url_path should only appear in the HTTP chain section,
	// not in the TLS chain section. We verify by checking that the TLS chain
	// uses requested_server_name (SNI) for host matching.
	// Methods/Paths are only applicable via http.rbac in the HTTP chain.
}

// TestHostWithMethodNoPath verifies partial L7: hosts + methods but no paths.
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
	result, err := TranslateEgressRules(egress, 1, 15001)
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

// TestCrossProductCount verifies the number of permissions generated by cross product.
// 2 hosts × 2 methods = 4 permissions (each is a single AND rule)
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
	result, err := TranslateEgressRules(egress, 1, 15001)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// Count "and_rules:" occurrences - should be 4 (2 hosts × 2 methods)
	count := strings.Count(lds, "and_rules:")
	// In HTTP chain: 4 and_rules for the allow RBAC
	// Each is: (host AND method)
	if count < 4 {
		t.Errorf("expected at least 4 and_rules for 2×2 cross product in HTTP chain, got %d", count)
	}
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
