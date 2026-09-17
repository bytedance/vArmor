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

func TestValidateMITMDomains_EquivalentIdentities(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		invalid bool
	}{
		{"bare IPv4 and CIDR", []string{"192.0.2.1", "192.0.2.1/32"}, true},
		{"reversed IPv4 aliases", []string{"192.0.2.1/32", "192.0.2.1"}, true},
		{"IPv6 aliases", []string{"2001:0DB8:0:0:0:0:0:1", "2001:db8::1/128"}, true},
		{"mapped IPv4", []string{"::ffff:192.0.2.1/128", "192.0.2.1/32"}, true},
		{"duplicate literal", []string{"192.0.2.1", "192.0.2.1"}, true},
		{"DNS case", []string{"API.example.com", "api.EXAMPLE.com"}, true},
		{"duplicate DNS", []string{"api.example.com", "api.example.com"}, true},
		{"wildcard case", []string{"*.EXAMPLE.com", "*.example.com"}, true},
		{"trimmed alias", []string{"192.0.2.1", " 192.0.2.1/32 "}, true},
		{"DNS and IP", []string{"api.example.com", "192.0.2.1"}, false},
		{"different IPs", []string{"192.0.2.1", "192.0.2.2/32", "2001:db8::1/128"}, false},
		{"wildcard and exact", []string{"*.example.com", "api.example.com"}, false},
		{"nested wildcards", []string{"*.example.com", "*.svc.example.com"}, false},
		{"single host CIDRs", []string{"192.0.2.1/32", "2001:db8::1/128"}, false},
		{"disabled", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.domains...)
			err := ValidateMITMDomains(tc.domains)
			if tc.invalid {
				assert.ErrorContains(t, err, "duplicates the identity")
				assert.ErrorContains(t, err, "mitm.domains[1]")
				assert.ErrorContains(t, err, "mitm.domains[0]")
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, before, tc.domains, "validation must not rewrite user input")
		})
	}
}

func TestTranslateEgressRules_RejectEquivalentMITMIdentities(t *testing.T) {
	for _, domains := range [][]string{{"192.0.2.1", "192.0.2.1/32"}, {"api.example.com", "API.example.com"}} {
		t.Run(domains[0], func(t *testing.T) {
			result, err := TranslateEgressRules(&varmor.NetworkProxyEgress{DefaultAction: "allow"}, 2, 15001,
				&MITMInput{Domains: domains}, testIPStack, AuditSinkConfig{})
			assert.ErrorContains(t, err, "duplicates the identity")
			assert.Nil(t, result, "invalid domains must not produce publishable xDS")
		})
	}
}

func TestResolveMITMInput_RejectAliasesBeforeSecretLookup(t *testing.T) {
	cfg := &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{
		Domains: []string{"192.0.2.1", "192.0.2.1/32"},
		HeaderMutations: []varmor.HeaderMutation{{Domain: "192.0.2.1", Headers: []varmor.HeaderAction{
			{Name: "Authorization", SecretRef: &varmor.SecretKeyRef{Name: "credentials", Key: "token"}},
		}}},
	}}
	input, err := ResolveMITMInput(nil, "default", cfg)
	assert.ErrorContains(t, err, "duplicates the identity")
	assert.Nil(t, input)
}
