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

func TestBracketedIPv6HostLiteral(t *testing.T) {
	for _, literal := range []string{"::1", "2001:db8::1", "2001:0DB8:0:0:0:0:0:1", "::ffff:192.0.2.1"} {
		for _, host := range []string{literal, "[" + literal + "]"} {
			got, ok := ipv6HostLiteral(host)
			if !ok || got != literal {
				t.Errorf("%q parsed as %q, %v", host, got, ok)
			}
			if got := httpAuthorityHost(host); got != "["+literal+"]" {
				t.Errorf("authority for %q = %q", host, got)
			}
		}
	}
	for _, host := range []string{"", "[]", "[", "]", "[[::1]]", "[::1", "::1]", "[::1]:443", "[::1]/128", "[::1%eth0]", "::1%eth0", "[127.0.0.1]", "127.0.0.1", "example.com", "*.example.com", "*", "[v1.fe80]"} {
		if literal, ok := ipv6HostLiteral(host); ok {
			t.Errorf("unexpected IPv6 recognition: %q -> %q", host, literal)
		}
		if got := httpAuthorityHost(host); got != host {
			t.Errorf("unexpected rewrite: %q -> %q", host, got)
		}
	}
}

func TestBracketedIPv6HTTPPermissions(t *testing.T) {
	for _, literal := range []string{"::1", "2001:db8::1", "::ffff:192.0.2.1"} {
		bracketed := "[" + literal + "]"
		for _, ports := range [][]varmor.Port{nil, {{Port: 80}}, {{Port: 443}}, {{Port: 8443}}, {{Port: 65535}}, {{Port: 8000, EndPort: 8443}}, {{Port: 80}, {Port: 443}}} {
			bare := varmor.NetworkProxyHTTPRule{Match: varmor.HTTPMatch{Hosts: []string{literal}, Ports: ports, Methods: []string{"GET"}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}}}}
			wrapped := bare.DeepCopy()
			wrapped.Match.Hosts = []string{bracketed}
			original := wrapped.DeepCopy()
			want := httpRuleToHTTPPermissions(bare)
			got := httpRuleToHTTPPermissions(*wrapped)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("host=%q ports=%+v: bracketed=%+v bare=%+v", literal, ports, got, want)
			}
			if !reflect.DeepEqual(wrapped, original) {
				t.Error("input HTTP rule mutated")
			}
		}
	}
}

func TestBracketedIPv6MITMRetention(t *testing.T) {
	expanded := "[2001:0DB8:0:0:0:0:0:1]"
	rules := []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"deny"}, Match: varmor.HTTPMatch{Hosts: []string{expanded}}}}
	for _, domain := range []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1/128"} {
		if got := filterHTTPRulesForDomains(rules, []string{domain}); !reflect.DeepEqual(got, rules) {
			t.Errorf("equivalent IP target %q dropped or rewrote %q: %+v", domain, expanded, got)
		}
	}
	for _, domain := range []string{"::1", "::1/128"} {
		for _, host := range []string{"::1", "[::1]"} {
			rules := []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"deny", "audit"}, Match: varmor.HTTPMatch{
				Hosts: []string{"unrelated.example.com", host, "[::2]"}, Ports: []varmor.Port{{Port: 443}},
				Methods: []string{"GET"}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}},
			}}}
			original := rules[0].DeepCopy()
			got := filterHTTPRulesForDomains(rules, []string{domain})
			want := original.DeepCopy()
			want.Match.Hosts = []string{host}
			if len(got) != 1 || !reflect.DeepEqual(got[0], *want) {
				t.Errorf("domain=%q host=%q retained=%+v", domain, host, got)
			}
			if !reflect.DeepEqual(&rules[0], original) {
				t.Error("input rule mutated")
			}
			dnsSet, ipSet := buildMITMDomainSet([]string{domain})
			got = filterHTTPRulesForTLSChain(rules, dnsSet, ipSet)
			want.Match.Hosts = []string{"unrelated.example.com", "[::2]"}
			if len(got) != 1 || !reflect.DeepEqual(got[0], *want) {
				t.Errorf("TLS pruning for domain=%q host=%q: %+v", domain, host, got)
			}
		}
	}
	for _, host := range []string{"[::2]", "[[::1]]", "[::1]:443", "[::1", "::1]", "not::1"} {
		if mitmHostPatternsOverlap(host, "::1") {
			t.Errorf("unrelated or malformed host %q retained as ::1", host)
		}
	}
}

func TestBracketedIPv6AuditMatrixTranslation(t *testing.T) {
	rows := []struct {
		name, defaultAction string
		qualifiers          [][]string
	}{
		{"allow_unmatched", "allow", nil},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}},
		{"allow_audit", "allow", [][]string{{"audit"}}},
		{"deny_unmatched", "deny", nil},
		{"deny_allow", "deny", [][]string{{"allow"}}},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}},
	}
	for _, domain := range []string{"::1", "::1/128"} {
		for _, row := range rows {
			t.Run(domain+"/"+row.name, func(t *testing.T) {
				var results []*TranslateResult
				for _, host := range []string{"::1", "[::1]"} {
					e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
					for _, q := range row.qualifiers {
						e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: q, Match: varmor.HTTPMatch{
							Hosts: []string{host}, Ports: []varmor.Port{{Port: 443}}, Methods: []string{"GET"}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}},
						}})
					}
					result, err := TranslateEgressRules(e, 1, 15001, &MITMInput{Domains: []string{domain}}, IPStackConfig{IPv6: true}, AuditSinkConfig{})
					if err != nil {
						t.Fatal(err)
					}
					results = append(results, result)
				}
				if !reflect.DeepEqual(results[0], results[1]) {
					t.Error("brackets changed the generated enforcement, shadow or access-log configuration")
				}
			})
		}
	}
}
