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

func TestFilterHTTPRulesForDomains_WildcardOverlap(t *testing.T) {
	tests := []struct {
		name, host, domain string
		keep               bool
	}{
		{"exact", "api.example.com", "api.example.com", true},
		{"rule wildcard", "*.example.com", "api.example.com", true},
		{"MITM wildcard", "api.example.com", "*.example.com", true},
		{"same wildcard", "*.example.com", "*.example.com", true},
		{"nested rule wildcard", "*.svc.example.com", "*.example.com", true},
		{"nested MITM wildcard", "*.example.com", "*.svc.example.com", true},
		{"multi label suffix", "*.example.com", "a.b.example.com", true},
		{"catch all rule", "*", "api.example.com", true},
		{"case insensitive retention", "*.EXAMPLE.COM", "api.example.com", true},
		{"unrelated exact", "api.other.com", "api.example.com", false},
		{"unrelated wildcard", "*.other.com", "*.example.com", false},
		{"sibling wildcard", "*.foo.example.com", "*.bar.example.com", false},
		{"rule wildcard excludes parent", "*.example.com", "example.com", false},
		{"MITM wildcard excludes parent", "example.com", "*.example.com", false},
		{"suffix boundary", "*.example.com", "notexample.com", false},
		{"suffix spoof", "*.example.com", "api.example.com.evil", false},
		{"IP alias preserved", "10.0.0.1", "10.0.0.1/32", true},
		{"IPv6 alias preserved", "2001:db8::1", "2001:db8::1/128", true},
		{"DNS does not enter IP chain", "*.example.com", "10.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := varmor.NetworkProxyHTTPRule{
				Qualifiers: []string{"deny", "audit"},
				Match: varmor.HTTPMatch{
					Hosts:   []string{tt.host},
					Paths:   []varmor.HTTPPathMatch{{Exact: "/secret"}},
					Methods: []string{"GET"},
					Ports:   []varmor.Port{{Port: 443}},
				},
			}
			original := rule.DeepCopy()
			got := filterHTTPRulesForDomains([]varmor.NetworkProxyHTTPRule{rule}, []string{tt.domain})
			if tt.keep {
				if len(got) != 1 || !reflect.DeepEqual(got[0], rule) {
					t.Fatalf("retained rule = %+v; want original constraints %+v", got, rule)
				}
			} else if len(got) != 0 {
				t.Fatalf("unreachable rule retained: %+v", got)
			}
			if !reflect.DeepEqual(&rule, original) {
				t.Fatal("input rule was mutated")
			}
		})
	}
}

func TestFilterHTTPRulesForDomains_MixedHosts(t *testing.T) {
	rules := []varmor.NetworkProxyHTTPRule{
		{Qualifiers: []string{"allow", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"unrelated.net", "*.example.com", "api.example.com"}, Paths: []varmor.HTTPPathMatch{{Prefix: "/v1/"}}}},
		{Qualifiers: []string{"deny"}, Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}}}},
	}
	original := rules[0].DeepCopy()
	got := filterHTTPRulesForDomains(rules, []string{"api.example.com", "*.example.com"})
	if len(got) != 2 || !reflect.DeepEqual(got[0].Match.Hosts, []string{"*.example.com", "api.example.com"}) {
		t.Fatalf("unexpected filtered rules: %+v", got)
	}
	if !reflect.DeepEqual(got[1], rules[1]) || !reflect.DeepEqual(&rules[0], original) {
		t.Fatal("hostless rule or input constraints changed")
	}
}

func TestMITMWildcardAuditMatrix(t *testing.T) {
	matrix := []struct {
		name, defaultAction string
		qualifiers          [][]string
		denied, logged      bool
	}{
		{"allow unmatched", "allow", nil, false, false},
		{"allow deny silent", "allow", [][]string{{"deny"}}, true, false},
		{"allow deny audit", "allow", [][]string{{"deny", "audit"}}, true, true},
		{"allow audit", "allow", [][]string{{"audit"}}, false, true},
		{"deny unmatched", "deny", nil, true, true},
		{"deny allow", "deny", [][]string{{"allow"}}, false, false},
		{"deny allow audit", "deny", [][]string{{"allow", "audit"}}, false, true},
		{"deny overlapping deny and allow audit", "deny", [][]string{{"deny"}, {"allow", "audit"}}, true, true},
	}
	overlaps := []struct{ name, host, domain string }{
		{"wildcard rule", "*.example.com", "api.example.com"},
		{"wildcard MITM", "api.example.com", "*.example.com"},
		{"nested wildcard rule", "*.svc.example.com", "*.example.com"},
		{"nested wildcard MITM", "*.example.com", "*.svc.example.com"},
	}
	for _, overlap := range overlaps {
		for _, row := range matrix {
			t.Run(overlap.name+"/"+row.name, func(t *testing.T) {
				e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
				for _, q := range row.qualifiers {
					e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: q, Match: varmor.HTTPMatch{Hosts: []string{overlap.host}, Methods: []string{"GET"}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}}}})
				}
				cls := classifyEgress(e)
				cfg := buildMITMHCMFilter(cls, []string{overlap.domain}, nil, AuditSinkConfig{}, FilterChainNameMITMTLSDNS).TypedConfig.(*HTTPConnManagerConfig)
				// The MITM chain must retain exactly the same ordered RBAC filters as
				// plaintext HTTP. This checks original predicates as well as all
				// enforcement and shadow buckets; no synthetic matching is substituted.
				plain := buildHTTPChain(cls.defaultDeny, cls.denyEgressRules, cls.allowEgressRules, cls.denyHTTPRules, cls.allowHTTPRules, cls.auditCfg, AuditSinkConfig{})
				want := plain.Filters[0].TypedConfig.(*HTTPConnManagerConfig)
				if !reflect.DeepEqual(cfg.HTTPFilters, want.HTTPFilters) {
					t.Fatal("MITM lost or changed enforcement/shadow filters")
				}
				if cfg.AccessLogDenyCEL != want.AccessLogDenyCEL || cfg.AccessLogShadowCEL != want.AccessLogShadowCEL {
					t.Fatal("MITM audit selection differs from plaintext HTTP")
				}
				// All supplied rules match this row's request. The existing CEL
				// filter-tree tests and ALS tests separately verify selection/action.
				shadow := cfg.AccessLogShadowCEL != ""
				selected := (cfg.AccessLogDenyCEL != "" && row.denied) || shadow
				if selected != row.logged {
					t.Fatalf("selected=%t want %t", selected, row.logged)
				}
				for _, vh := range cfg.RouteConfig.VirtualHosts {
					for _, d := range vh.Domains {
						if d == "*" {
							t.Fatal("MITM gained a catch-all virtual host")
						}
					}
				}
			})
		}
	}
}
