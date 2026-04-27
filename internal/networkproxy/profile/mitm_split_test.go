package profile

import (
	"strings"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// TestMITMChainVHIsolation verifies that DNS and IP MITM chains have
// separate VirtualHosts: DNS chain should NOT contain IP-based VHs,
// and IP chain should NOT contain DNS-based VHs.
func TestMITMChainVHIsolation(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"httpbin.org", "1.1.1.1", "8.8.4.4"},
				},
			},
		},
	}

	mitm := &MITMInput{
		Domains: []string{"httpbin.org", "1.1.1.1", "8.8.4.4/32"},
		HeadersByDomain: map[string][]HeaderToAdd{
			"1.1.1.1": {
				{Name: "X-Source", Value: "mixed-ip"},
			},
			"8.8.4.4/32": {
				{Name: "X-Source", Value: "mixed-cidr32"},
			},
		},
	}

	result, err := TranslateEgressRules(egress, 3, 15001, mitm)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	lds := result.LDS

	// Extract each MITM chain section
	dnsChainStart := strings.Index(lds, "mitm_tls_dns_chain")
	dnsChainEnd := strings.Index(lds, "mitm_tls_ip_chain")
	ipChainStart := dnsChainEnd
	ipChainEnd := strings.Index(lds, "tls_chain")

	if dnsChainStart < 0 || ipChainStart < 0 || ipChainEnd < 0 {
		t.Fatalf("Could not find expected chain sections in LDS")
	}

	dnsSection := lds[dnsChainStart:dnsChainEnd]
	ipSection := lds[ipChainStart:ipChainEnd]

	// DNS chain should have httpbin.org VH, NOT 1.1.1.1 or 8.8.4.4
	if !strings.Contains(dnsSection, `"httpbin.org"`) {
		t.Error("DNS chain missing httpbin.org VirtualHost")
	}
	if strings.Contains(dnsSection, `"1.1.1.1"`) {
		t.Error("DNS chain should NOT contain 1.1.1.1 VirtualHost")
	}
	if strings.Contains(dnsSection, `"8.8.4.4"`) {
		t.Error("DNS chain should NOT contain 8.8.4.4 VirtualHost")
	}

	// IP chain should have 1.1.1.1 and 8.8.4.4 VHs, NOT httpbin.org
	if strings.Contains(ipSection, `"httpbin.org"`) {
		t.Error("IP chain should NOT contain httpbin.org VirtualHost")
	}
	if !strings.Contains(ipSection, `"1.1.1.1"`) {
		t.Error("IP chain missing 1.1.1.1 VirtualHost")
	}
	if !strings.Contains(ipSection, `"8.8.4.4"`) {
		t.Error("IP chain missing 8.8.4.4 VirtualHost")
	}

	// Verify header injection is in the correct chain
	if strings.Contains(dnsSection, "mixed-ip") {
		t.Error("DNS chain should NOT contain X-Source: mixed-ip header")
	}
	if !strings.Contains(ipSection, "mixed-ip") {
		t.Error("IP chain missing X-Source: mixed-ip header")
	}
	if !strings.Contains(ipSection, "mixed-cidr32") {
		t.Error("IP chain missing X-Source: mixed-cidr32 header")
	}
}

func TestMITMValidateRejectsWideCIDR(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		wantErr bool
		errSub  string // substring expected in error message
	}{
		{
			name:    "bare IP is valid",
			domains: []string{"1.1.1.1"},
			wantErr: false,
		},
		{
			name:    "/32 CIDR is valid",
			domains: []string{"8.8.4.4/32"},
			wantErr: false,
		},
		{
			name:    "DNS name is valid",
			domains: []string{"httpbin.org"},
			wantErr: false,
		},
		{
			name:    "mixed valid entries",
			domains: []string{"httpbin.org", "1.1.1.1", "8.8.4.4/32"},
			wantErr: false,
		},
		{
			name:    "/24 CIDR is rejected",
			domains: []string{"8.8.4.0/24"},
			wantErr: true,
			errSub:  "/24",
		},
		{
			name:    "/16 CIDR is rejected",
			domains: []string{"10.0.0.0/16"},
			wantErr: true,
			errSub:  "/16",
		},
		{
			name:    "/0 CIDR is rejected",
			domains: []string{"0.0.0.0/0"},
			wantErr: true,
			errSub:  "/0",
		},
		{
			name:    "valid + invalid mix rejects",
			domains: []string{"httpbin.org", "10.0.0.0/8"},
			wantErr: true,
			errSub:  "/8",
		},
		{
			name:    "IPv6 /128 is valid",
			domains: []string{"::1/128"},
			wantErr: false,
		},
		{
			name:    "IPv6 /64 is rejected",
			domains: []string{"fd00::/64"},
			wantErr: true,
			errSub:  "/64",
		},
		{
			name:    "nil input is valid",
			domains: nil,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mitm *MITMInput
			if tc.domains != nil {
				mitm = &MITMInput{Domains: tc.domains}
			}
			err := mitm.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSub, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			}
		})
	}
}


// TestMITMChainEgressRuleIsolation verifies that egress L4 rules not in
// mitm.domains are filtered out of MITM chain RBAC. Reproduces the bug
// where 10.0.0.0/24 leaked into the IP chain that only covers 8.8.8.8/32.
func TestMITMChainEgressRuleIsolation(t *testing.T) {
	egress := &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow"},
				CIDR:       "8.8.8.8/32",
				Ports:      []varmor.Port{{Port: 443}},
			},
			{
				Qualifiers: []string{"allow"},
				CIDR:       "10.0.0.0/24",
				Ports:      []varmor.Port{{Port: 443}},
			},
		},
	}
	mitm := &MITMInput{
		Domains: []string{"8.8.8.8/32"},
		HeadersByDomain: map[string][]HeaderToAdd{
			"8.8.8.8/32": {{Name: "X-Source", Value: "cidr32"}},
		},
	}

	result, err := TranslateEgressRules(egress, 1, 15001, mitm)
	if err != nil {
		t.Fatalf("TranslateEgressRules failed: %v", err)
	}

	lds := result.LDS

	// Extract the MITM IP chain section
	mitmStart := strings.Index(lds, "mitm_tls_ip_chain")
	if mitmStart < 0 {
		t.Fatal("mitm_tls_ip_chain not found in LDS")
	}
	// Find where the next chain starts (tls_chain or http_chain)
	nextChain := strings.Index(lds[mitmStart:], "# ---- tls_chain")
	if nextChain < 0 {
		nextChain = strings.Index(lds[mitmStart:], "# ---- http_chain")
	}
	var mitmSection string
	if nextChain > 0 {
		mitmSection = lds[mitmStart : mitmStart+nextChain]
	} else {
		mitmSection = lds[mitmStart:]
	}

	// MITM chain should contain 8.8.8.8 egress rule
	if !strings.Contains(mitmSection, "8.8.8.8") {
		t.Error("MITM IP chain should contain 8.8.8.8 egress rule")
	}

	// MITM chain should NOT contain 10.0.0.0/24 egress rule
	if strings.Contains(mitmSection, "10.0.0.0") {
		t.Error("MITM IP chain should NOT contain 10.0.0.0/24 egress rule — it is not in mitm.domains")
	}

	// tls_chain should still have BOTH rules (it is the passthrough chain)
	tlsStart := strings.Index(lds, "# ---- tls_chain")
	if tlsStart < 0 {
		t.Fatal("tls_chain not found")
	}
	tlsSection := lds[tlsStart:]
	if !strings.Contains(tlsSection, "10.0.0.0") {
		t.Error("tls_chain should still contain 10.0.0.0/24 rule")
	}
	if !strings.Contains(tlsSection, "8.8.8.8") {
		t.Error("tls_chain should still contain 8.8.8.8/32 rule")
	}
}
