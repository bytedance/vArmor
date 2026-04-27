package profile

import (
	"strings"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func extractHTTPRBACSection(lds string) string {
	lines := strings.Split(lds, "\n")
	var sb strings.Builder
	inHTTPChain := false
	for _, line := range lines {
		if strings.Contains(line, "http_chain") {
			inHTTPChain = true
		}
		if inHTTPChain && strings.Contains(line, "default_filter_chain") {
			break
		}
		if inHTTPChain {
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}

// TestBindingExactHostExactPorts verifies that exact hosts with exact ports
// use the binding approach: port baked into :authority matcher.
func TestBindingExactHostExactPorts(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"1.1.1.1"},
					Ports: []varmor.Port{
						{Port: 443},
						{Port: 6443},
					},
				},
			},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, &MITMInput{})
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	section := extractHTTPRBACSection(result.LDS)
	t.Log("=== Binding: exact host + exact ports ===")
	t.Log(section)

	// Verify: should have exact "1.1.1.1" + port 443, exact "1.1.1.1:6443" + port 6443
	if !strings.Contains(section, `exact: "1.1.1.1"`) {
		t.Error("Missing exact_match for 1.1.1.1 (default port)")
	}
	if !strings.Contains(section, `exact: "1.1.1.1:6443"`) {
		t.Error("Missing exact_match for 1.1.1.1:6443 (non-default port)")
	}
	// Should NOT have any regex
	if strings.Contains(section, "safe_regex") {
		t.Error("Unexpected safe_regex in binding path")
	}
	// Should NOT have prefix_match for :authority
	if strings.Contains(section, `prefix: "1.1.1.1:"`) {
		t.Error("Unexpected prefix_match for :authority in binding path")
	}
}

// TestBindingWildcardHostExactPorts verifies that wildcard hosts with exact
// ports use suffix_match with port baked in.
func TestBindingWildcardHostExactPorts(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"*.openai.com"},
					Ports: []varmor.Port{
						{Port: 443},
						{Port: 8443},
					},
				},
			},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, &MITMInput{})
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	section := extractHTTPRBACSection(result.LDS)
	t.Log("=== Binding: wildcard host + exact ports ===")
	t.Log(section)

	// Default port: suffix ".openai.com"
	if !strings.Contains(section, `suffix: ".openai.com"`) {
		t.Error("Missing suffix_match for .openai.com (default port)")
	}
	// Non-default port: suffix ".openai.com:8443"
	if !strings.Contains(section, `suffix: ".openai.com:8443"`) {
		t.Error("Missing suffix_match for .openai.com:8443 (non-default port)")
	}
	// Should NOT have any regex
	if strings.Contains(section, "safe_regex") {
		t.Error("Unexpected safe_regex in wildcard binding path")
	}
}

// TestFallbackExactHostNoPort verifies that exact hosts without ports
// use or_rules(exact, prefix).
func TestFallbackExactHostNoPort(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"api.openai.com"},
				},
			},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, &MITMInput{})
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	section := extractHTTPRBACSection(result.LDS)
	t.Log("=== Fallback: exact host, no port ===")
	t.Log(section)

	if !strings.Contains(section, "or_rules:") {
		t.Error("Missing or_rules for exact host without port")
	}
	if !strings.Contains(section, `exact: "api.openai.com"`) {
		t.Error("Missing exact_match in or_rules")
	}
	if !strings.Contains(section, `prefix: "api.openai.com:"`) {
		t.Error("Missing prefix_match in or_rules")
	}
}

// TestFallbackWildcardHostPortRange verifies that wildcard hosts with port
// ranges use safe_regex.
func TestFallbackWildcardHostPortRange(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"*.openai.com"},
					Ports: []varmor.Port{
						{Port: 8000, EndPort: 9000},
					},
				},
			},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, &MITMInput{})
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	section := extractHTTPRBACSection(result.LDS)
	t.Log("=== Fallback: wildcard host + port range ===")
	t.Log(section)

	if !strings.Contains(section, "safe_regex:") {
		t.Error("Missing safe_regex for wildcard + port range")
	}
	if !strings.Contains(section, "destination_port_range:") {
		t.Error("Missing destination_port_range")
	}
}

// TestMixedHostsExactPorts verifies mixed exact + wildcard hosts with exact ports.
func TestMixedHostsExactPorts(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"1.1.1.1", "*.openai.com"},
					Ports: []varmor.Port{
						{Port: 443},
						{Port: 6443},
					},
				},
			},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, &MITMInput{})
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	section := extractHTTPRBACSection(result.LDS)
	t.Log("=== Mixed: exact + wildcard hosts, exact ports ===")
	t.Log(section)

	// Exact host binding
	if !strings.Contains(section, `exact: "1.1.1.1"`) {
		t.Error("Missing exact for 1.1.1.1:443")
	}
	if !strings.Contains(section, `exact: "1.1.1.1:6443"`) {
		t.Error("Missing exact for 1.1.1.1:6443")
	}
	// Wildcard host binding
	if !strings.Contains(section, `suffix: ".openai.com"`) {
		t.Error("Missing suffix for .openai.com:443")
	}
	if !strings.Contains(section, `suffix: ".openai.com:6443"`) {
		t.Error("Missing suffix for .openai.com:6443")
	}
	// Should NOT have regex or prefix
	if strings.Contains(section, "safe_regex") {
		t.Error("Unexpected safe_regex in binding path")
	}
}
