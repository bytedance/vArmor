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
	"reflect"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestMITMIPCandidatesPreservePolicy(t *testing.T) {
	e := &varmor.NetworkProxyEgress{DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{{Qualifiers: []string{"deny", "audit"}, CIDR: "192.0.2.0/24"}},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{Qualifiers: []string{"allow", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"api.example.com"}, Paths: []varmor.HTTPPathMatch{{Prefix: "/api/"}}}},
			// Plaintext rules must survive even if their Host is outside MITM domains.
			{Qualifiers: []string{"deny", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"other.example.net"}, Methods: []string{"POST"}}},
		},
	}
	original := e.DeepCopy()
	cls := classifyEgress(e)
	for _, tc := range []struct {
		name          string
		domains       []string
		count         int
		prefixes, dns []string
	}{
		{"empty", nil, 0, nil, nil},
		{"dns", []string{"api.example.com"}, 1, nil, []string{"api.example.com"}},
		{"ip", []string{"192.0.2.1"}, 2, []string{"192.0.2.1"}, nil},
		{"mixed", []string{"*.example.com", "192.0.2.1/32", "2001:db8::1/128"}, 4, []string{"192.0.2.1/32", "2001:db8::1/128"}, []string{"*.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mitm := &MITMInput{Domains: tc.domains, CertificateSDSPath: "/test/sds.yaml", HeadersByDomain: map[string][]HeaderToAdd{"*.example.com": {{Name: "X-Source", Value: "dns"}}, "192.0.2.1/32": {{Name: "X-Source", Value: "ip"}}}}
			chains := buildMITMChains(cls, mitm, AuditSinkConfig{})
			if len(chains) != tc.count {
				t.Fatalf("chains=%d want %d", len(chains), tc.count)
			}
			names := map[string]bool{}
			for _, chain := range chains {
				if names[chain.Name] {
					t.Fatalf("duplicate chain %s", chain.Name)
				}
				names[chain.Name] = true
				cfg := chain.Filters[0].TypedConfig.(*HTTPConnManagerConfig)
				if cfg.FilterChainName != chain.Name {
					t.Fatalf("incorrect audit chain: %s", chain.Name)
				}
				match := chain.FilterChainMatch
				if chain.Name == FilterChainNameHTTPIP {
					if chain.TransportSocket != nil || match.TransportProtocol != "raw_buffer" || len(match.ServerNames) != 0 || !reflect.DeepEqual(match.ApplicationProtocols, []string{"http/1.0", "http/1.1", "h2c"}) {
						t.Fatal("IP HTTP chain must accept only inspected plaintext HTTP")
					}
					plain := buildHTTPChain(cls.defaultDeny, cls.denyEgressRules, cls.allowEgressRules, cls.denyHTTPRules, cls.allowHTTPRules, cls.auditCfg, AuditSinkConfig{})
					want := *plain.Filters[0].TypedConfig.(*HTTPConnManagerConfig)
					want.FilterChainName = chain.Name
					if !reflect.DeepEqual(*cfg, want) {
						t.Fatal("IP HTTP changed full policy, routing, or audit semantics")
					}
				} else {
					if chain.TransportSocket == nil || chain.TransportSocket.SecretPath != mitm.CertificateSDSPath || match.TransportProtocol != "tls" {
						t.Fatal("TLS context changed")
					}
					domains := tc.prefixes
					if chain.Name != FilterChainNameMITMTLSIP {
						domains = tc.dns
					}
					expected := buildMITMHCMFilter(cls, domains, mitm.HeadersByDomain, AuditSinkConfig{}, chain.Name).TypedConfig
					if !reflect.DeepEqual(cfg, expected) {
						t.Fatalf("%s changed domain-scoped policy or injection", chain.Name)
					}
					for _, vh := range cfg.RouteConfig.VirtualHosts {
						for _, host := range vh.Domains {
							if host == "*" {
								t.Fatal("TLS virtual-host boundary expanded")
							}
						}
					}
				}
				var prefixes, dns []string
				if chain.Name != FilterChainNameMITMTLSDNS {
					prefixes = tc.prefixes
				}
				if chain.Name == FilterChainNameMITMTLSDNS || chain.Name == FilterChainNameMITMTLSDNSIP {
					dns = tc.dns
				}
				if !reflect.DeepEqual(match.PrefixRanges, prefixes) || !reflect.DeepEqual(match.ServerNames, dns) {
					t.Fatalf("%s has incorrect IP/SNI match: %+v", chain.Name, match)
				}
			}
		})
	}
	if !reflect.DeepEqual(e, original) {
		t.Fatal("input policy mutated")
	}
}

func TestMITMIPCandidatesLeaveCDSUnchanged(t *testing.T) {
	e := &varmor.NetworkProxyEgress{DefaultAction: "allow"}
	var baseline string
	for _, domains := range [][]string{{"api.example.com"}, {"192.0.2.1"}, {"api.example.com", "192.0.2.1", "2001:db8::1"}} {
		result, err := TranslateEgressRules(e, 1, 15001, &MITMInput{Domains: domains}, IPStackConfig{IPv4: true, IPv6: true}, AuditSinkConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if baseline != "" && baseline != result.CDS {
			t.Fatal("IP selection changed CDS")
		}
		baseline = result.CDS
	}
}
