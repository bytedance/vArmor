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
	"testing"

	"github.com/stretchr/testify/assert"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestHTTPDefaultPortAuthorityRules(t *testing.T) {
	for _, host := range []string{"Api.Example.COM", "192.0.2.1", "*.Example.COM", "::1", "[::1]"} {
		for _, port := range []uint16{80, 443, 8443} {
			t.Run(fmt.Sprintf("%s/%d", host, port), func(t *testing.T) {
				kind, value := "exact_match", host
				switch host {
				case "*.Example.COM":
					kind, value = "suffix_match", ".Example.COM"
				case "::1", "[::1]":
					value = "[::1]"
				}
				bare := PermissionRule{Type: "header", Value: map[string]string{"name": ":authority", kind: value}}
				explicit := PermissionRule{Type: "header", Value: map[string]string{"name": ":authority", kind: fmt.Sprintf("%s:%d", value, port)}}
				want := explicit
				if port == 80 || port == 443 {
					want = PermissionRule{Type: "or_rules", Value: []PermissionRule{bare, explicit}}
				}
				assert.Equal(t, want, authorityMatcherForHostPort(host, port))
				decodeHostCasePermission(t, authorityMatcherForHostPort(host, port))
			})
		}
	}
	for _, port := range []uint16{80, 443, 8443} {
		assert.Equal(t, PermissionRule{Type: "any", Value: true}, authorityMatcherForHostPort("*", port))
	}
}

func TestHTTPDefaultPortPermissionConstraints(t *testing.T) {
	for _, host := range []string{"api.example.com", "192.0.2.1", "*.example.com", "*"} {
		for _, port := range []uint16{80, 443} {
			t.Run(fmt.Sprintf("%s/%d", host, port), func(t *testing.T) {
				rule := varmor.NetworkProxyHTTPRule{Match: varmor.HTTPMatch{
					Hosts: []string{host}, Ports: []varmor.Port{{Port: port}}, Methods: []string{"GET"},
					Paths: []varmor.HTTPPathMatch{{Exact: "/Secret"}},
				}}
				original := rule.DeepCopy()
				want := []Permission{{AndRules: []PermissionRule{
					authorityMatcherForHostPort(host, port),
					{Type: "destination_port", Value: port},
					{Type: "header", Value: map[string]string{"name": ":method", "exact_match": "GET"}},
					{Type: "url_path", Value: map[string]string{"exact": "/Secret"}},
				}}}
				assert.Equal(t, want, httpRuleToHTTPPermissions(rule))
				assert.Equal(t, original, &rule, "translation must not mutate the policy")
			})
		}
	}
}
