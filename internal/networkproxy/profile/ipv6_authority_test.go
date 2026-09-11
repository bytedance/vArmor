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
	"fmt"
	"reflect"
	"strconv"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestMITMIPv6VirtualHostDomains(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"::1", []string{"[::1]", "[::1]:*"}},
		{"2001:db8::1", []string{"[2001:db8::1]", "[2001:db8::1]:*"}},
		{"2001:0db8:0:0:0:0:0:1", []string{"[2001:0db8:0:0:0:0:0:1]", "[2001:0db8:0:0:0:0:0:1]:*"}},
		{"2001:db8::1/128", []string{"[2001:db8::1]", "[2001:db8::1]:*"}},
		{"::ffff:192.0.2.1", []string{"[::ffff:192.0.2.1]", "[::ffff:192.0.2.1]:*"}},
		{"192.0.2.1", []string{"192.0.2.1", "192.0.2.1:*"}},
		{"192.0.2.1/32", []string{"192.0.2.1", "192.0.2.1:*"}},
		{"api.example.com", []string{"api.example.com", "api.example.com:*"}},
		{"*.example.com", []string{"*.example.com"}},
		{"2001:db8::/64", nil},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			domains := []string{tt.domain}
			headers := []HeaderToAdd{{Name: "X-Test", Value: "value"}}
			got := buildMITMVirtualHosts(domains, map[string][]HeaderToAdd{tt.domain: headers})
			if tt.want == nil {
				if len(got) != 0 {
					t.Fatalf("unexpected virtual hosts: %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("virtual hosts=%+v", got)
			}
			if !reflect.DeepEqual(got[0].Domains, tt.want) {
				t.Errorf("domains=%v want %v", got[0].Domains, tt.want)
			}
			if !reflect.DeepEqual(got[0].RequestHeadersToAdd, headers) {
				t.Errorf("headers lost: %+v", got[0].RequestHeadersToAdd)
			}
			if domains[0] != tt.domain {
				t.Error("input domain mutated")
			}
		})
	}
}

func ipv6AuthorityHeader(kind, value string) PermissionRule {
	return PermissionRule{Type: "header", Value: map[string]string{"name": ":authority", kind: value}}
}

func TestIPv6HTTPPermissionConstraints(t *testing.T) {
	for _, port := range []varmor.Port{{Port: 80}, {Port: 443}, {Port: 8443}, {Port: 8000, EndPort: 8443}} {
		t.Run(fmt.Sprintf("%d-%d", port.Port, port.EndPort), func(t *testing.T) {
			rule := varmor.NetworkProxyHTTPRule{Match: varmor.HTTPMatch{
				Hosts: []string{"::1"}, Ports: []varmor.Port{port},
				Methods: []string{"GET"}, Paths: []varmor.HTTPPathMatch{{Exact: "/secret"}},
			}}
			original := rule.DeepCopy()
			hostRule := authorityMatcherForHostPort("::1", port.Port)
			portRule := PermissionRule{Type: "destination_port", Value: port.Port}
			if port.EndPort != 0 {
				hostRule = portAgnosticHostRules([]string{"::1"})[0]
				portRule = PermissionRule{Type: "destination_port_range", Value: map[string]uint32{
					"start": 8000, "end": 8444,
				}}
			}
			want := []Permission{{AndRules: []PermissionRule{
				hostRule, portRule,
				{Type: "header", Value: map[string]string{"name": ":method", "exact_match": "GET"}},
				{Type: "url_path", Value: map[string]string{"exact": "/secret"}},
			}}}
			if got := httpRuleToHTTPPermissions(rule); !reflect.DeepEqual(got, want) {
				t.Errorf("permissions=%+v want %+v", got, want)
			}
			if !reflect.DeepEqual(&rule, original) {
				t.Error("input HTTP rule mutated")
			}
		})
	}
}

func TestIPv6HTTPAuthorityRules(t *testing.T) {
	for _, host := range []string{"::1", "2001:db8::1", "2001:0db8:0:0:0:0:0:1", "::ffff:192.0.2.1"} {
		t.Run(host, func(t *testing.T) {
			authority := "[" + host + "]"
			wantAgnostic := []PermissionRule{{Type: "or_rules", Value: []PermissionRule{
				ipv6AuthorityHeader("exact_match", authority),
				ipv6AuthorityHeader("prefix_match", authority+":"),
			}}}
			if got := portAgnosticHostRules([]string{host}); !reflect.DeepEqual(got, wantAgnostic) {
				t.Errorf("port-agnostic matcher=%+v want %+v", got, wantAgnostic)
			}
			for _, port := range []uint16{80, 443, 8443} {
				withPort := ipv6AuthorityHeader("exact_match", authority+":"+strconv.Itoa(int(port)))
				want := withPort
				if port == 80 || port == 443 {
					want = PermissionRule{Type: "or_rules", Value: []PermissionRule{
						ipv6AuthorityHeader("exact_match", authority), withPort,
					}}
				}
				if got := authorityMatcherForHostPort(host, port); !reflect.DeepEqual(got, want) {
					t.Errorf("port %d matcher=%+v want %+v", port, got, want)
				}
			}
		})
	}
}
