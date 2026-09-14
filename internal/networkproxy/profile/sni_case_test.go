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
	"testing"

	"github.com/stretchr/testify/assert"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// Check the translated SNI permissions against Envoy's protobuf schema. Case
// folding must apply to DNS values without changing wildcard or port semantics.
func TestSNICaseMatchers(t *testing.T) {
	for _, tc := range []struct {
		name, host, exact, suffix string
		any                       bool
	}{
		{"lowercase_exact", "api.example.com", "api.example.com", "", false},
		{"uppercase_exact", "API.EXAMPLE.COM", "API.EXAMPLE.COM", "", false},
		{"mixed_exact", "Api.Example.COM", "Api.Example.COM", "", false},
		{"lowercase_wildcard", "*.example.com", "", ".example.com", false},
		{"uppercase_wildcard", "*.EXAMPLE.COM", "", ".EXAMPLE.COM", false},
		{"mixed_wildcard", "*.Example.COM", "", ".Example.COM", false},
		{"catch_all", "*", "", "", true},
	} {
		for _, bound := range []bool{false, true} {
			name := tc.name + "/any_port"
			rule := varmor.NetworkProxyHTTPRule{Match: varmor.HTTPMatch{Hosts: []string{tc.host}}}
			if bound {
				name = tc.name + "/port_443"
				rule.Match.Ports = []varmor.Port{{Port: 443}}
			}
			t.Run(name, func(t *testing.T) {
				original := rule.DeepCopy()
				permissions := httpRuleToSNIPermissions(rule)
				if !assert.Len(t, permissions, 1) {
					return
				}
				count := 1
				if bound {
					count++
				}
				if !assert.Len(t, permissions[0].AndRules, count) {
					return
				}
				permission := decodeHostCasePermission(t, permissions[0].AndRules[0])
				if tc.any {
					assert.True(t, permission.GetAny())
					assert.Nil(t, permission.GetRequestedServerName())
				} else {
					matcher := permission.GetRequestedServerName()
					if !assert.NotNil(t, matcher) {
						return
					}
					assert.True(t, matcher.GetIgnoreCase(), "SNI remains case-sensitive")
					assert.Equal(t, tc.exact, matcher.GetExact())
					assert.Equal(t, tc.suffix, matcher.GetSuffix())
				}
				if bound {
					port := decodeHostCasePermission(t, permissions[0].AndRules[1])
					assert.Equal(t, uint32(443), port.GetDestinationPort())
				}
				assert.Equal(t, original, &rule, "input policy was mutated")
			})
		}
	}
}
