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

// L4 rules must not depend on how a connection enters a MITM chain.
// Compare every enforcement/shadow predicate with the plaintext HTTP path
// and verify that generation leaves the original API objects unchanged.
func TestMITMEgressRulesPreserved(t *testing.T) {
	destinations := []struct {
		name    string
		domains []string
	}{
		{"DNS", []string{"api.example.com"}},
		{"wildcard DNS", []string{"*.example.com"}},
		{"IPv4", []string{"10.0.0.1"}},
		{"IPv4 host CIDR", []string{"10.0.0.1/32"}},
		{"IPv6", []string{"2001:db8::1"}},
		{"IPv6 host CIDR", []string{"2001:db8::1/128"}},
		{"mixed chains", []string{"api.example.com", "10.0.0.1", "2001:db8::1"}},
	}
	matrix := []struct {
		name, defaultAction string
		qualifiers          [][]string
	}{
		{"allow unmatched", "allow", nil},
		{"allow deny silent", "allow", [][]string{{"deny"}}},
		{"allow deny audit", "allow", [][]string{{"deny", "audit"}}},
		{"allow audit", "allow", [][]string{{"audit"}}},
		{"deny unmatched", "deny", nil},
		{"deny allow", "deny", [][]string{{"allow"}}},
		{"deny allow audit", "deny", [][]string{{"allow", "audit"}}},
		{"deny overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}},
	}
	for _, dst := range destinations {
		for _, row := range matrix {
			t.Run(dst.name+"/"+row.name, func(t *testing.T) {
				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
				for _, q := range row.qualifiers {
					for _, rule := range []varmor.NetworkProxyEgressRule{
						{IP: "10.0.0.1"},
						{CIDR: "10.0.0.0/24", Ports: []varmor.Port{{Port: 443}, {Port: 8000, EndPort: 8080}}},
						{IP: "2001:0db8:0:0:0:0:0:1"},
						{CIDR: "2001:db8::/32"},
						{Ports: []varmor.Port{{Port: 443}}},
						// Even apparently unrelated destinations retain their constraints;
						// they must not turn into match-any rules at runtime.
						{CIDR: "192.0.2.0/24", Ports: []varmor.Port{{Port: 8443}}},
					} {
						rule.Qualifiers = q
						e.Rules = append(e.Rules, rule)
					}
				}
				original := e.DeepCopy()
				cls := classifyEgress(e)
				plain := buildHTTPChain(cls.defaultDeny, cls.denyEgressRules, cls.allowEgressRules, nil, nil, cls.auditCfg, AuditSinkConfig{})
				want := plain.Filters[0].TypedConfig.(*HTTPConnManagerConfig)
				chains := buildMITMChains(cls, &MITMInput{Domains: dst.domains}, AuditSinkConfig{})
				if len(chains) == 0 {
					t.Fatal("no MITM chains")
				}
				for _, chain := range chains {
					cfg := chain.Filters[0].TypedConfig.(*HTTPConnManagerConfig)
					if !reflect.DeepEqual(cfg.HTTPFilters, want.HTTPFilters) {
						t.Fatalf("%s changed L4 enforcement or audit predicates", chain.Name)
					}
					if cfg.AccessLogDenyCEL != want.AccessLogDenyCEL || cfg.AccessLogShadowCEL != want.AccessLogShadowCEL {
						t.Fatalf("%s changed audit selection", chain.Name)
					}
					for _, vh := range cfg.RouteConfig.VirtualHosts {
						for _, host := range vh.Domains {
							if chain.TransportSocket != nil && host == "*" {
								t.Fatal("MITM virtual host boundary expanded")
							}
						}
					}
				}
				if !reflect.DeepEqual(e, original) {
					t.Fatal("input egress rules mutated")
				}
			})
		}
	}
}

// L4 destination rules and overlapping HTTP host rules must coexist after
// combining the MITM egress and wildcard fixes.
func TestMITMEgressAndWildcardHTTPRulesPreserved(t *testing.T) {
	for _, domain := range []string{"api.example.com", "*.svc.example.com"} {
		for _, defaultAction := range []string{"allow", "deny"} {
			t.Run(domain+"/"+defaultAction, func(t *testing.T) {
				e := &varmor.NetworkProxyEgress{DefaultAction: defaultAction}
				for _, qualifiers := range [][]string{{"deny", "audit"}, {"allow", "audit"}} {
					e.Rules = append(e.Rules, varmor.NetworkProxyEgressRule{
						Qualifiers: qualifiers, CIDR: "10.0.0.0/24",
						Ports: []varmor.Port{{Port: 443}},
					})
					e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{
						Qualifiers: qualifiers,
						Match: varmor.HTTPMatch{
							Hosts: []string{"*.example.com"}, Methods: []string{"GET"},
							Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}},
						},
					})
				}
				original := e.DeepCopy()
				cls := classifyEgress(e)
				plain := buildHTTPChain(cls.defaultDeny, cls.denyEgressRules, cls.allowEgressRules, cls.denyHTTPRules, cls.allowHTTPRules, cls.auditCfg, AuditSinkConfig{})
				want := plain.Filters[0].TypedConfig.(*HTTPConnManagerConfig)
				chains := buildMITMChains(cls, &MITMInput{Domains: []string{domain}}, AuditSinkConfig{})
				if len(chains) != 1 {
					t.Fatalf("got %d MITM chains, want 1", len(chains))
				}
				cfg := chains[0].Filters[0].TypedConfig.(*HTTPConnManagerConfig)
				if !reflect.DeepEqual(cfg.HTTPFilters, want.HTTPFilters) {
					t.Fatal("MITM lost or changed combined L4 and wildcard HTTP enforcement/shadow predicates")
				}
				if cfg.AccessLogDenyCEL != want.AccessLogDenyCEL || cfg.AccessLogShadowCEL != want.AccessLogShadowCEL {
					t.Fatal("MITM changed combined audit selection")
				}
				if !reflect.DeepEqual(e, original) {
					t.Fatal("input egress rules mutated")
				}
			})
		}
	}
}
