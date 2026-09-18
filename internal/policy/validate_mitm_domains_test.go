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

package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestValidatePolicy_EquivalentMITMDomains(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		valid   bool
	}{
		{"IPv4 aliases", []string{"192.0.2.1", "192.0.2.1/32"}, false},
		{"IPv6 aliases", []string{"2001:0DB8::1", "2001:db8::1/128"}, false},
		{"mapped IPv4", []string{"::ffff:192.0.2.1", "192.0.2.1/32"}, false},
		{"DNS case", []string{"api.example.com", "API.EXAMPLE.COM"}, false},
		{"wildcard case", []string{"*.example.com", "*.EXAMPLE.COM"}, false},
		{"identical DNS", []string{"api.example.com", "api.example.com"}, false},
		{"DNS with IP", []string{"api.example.com", "192.0.2.1"}, true},
		{"overlapping wildcard", []string{"*.example.com", "api.example.com"}, true},
		{"single CIDRs", []string{"192.0.2.1/32", "2001:db8::1/128"}, true},
	}
	for _, tc := range cases {
		for _, clusterScope := range []bool{false, true} {
			kind := "VarmorPolicy"
			if clusterScope {
				kind = "VarmorClusterPolicy"
			}
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				cfg := &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: tc.domains,
					HeaderMutations: []varmor.HeaderMutation{{Domain: tc.domains[0], Headers: []varmor.HeaderAction{{Name: "X-Credential", Value: "first"}}},
						{Domain: tc.domains[1], Headers: []varmor.HeaderAction{{Name: "X-Credential", Value: "second"}}}},
				}}
				spec := varmor.VarmorPolicySpec{Target: varmor.Target{Kind: "Pod", Name: "sandbox"},
					Policy: varmor.Policy{Enforcer: "NetworkProxy", Mode: varmor.AlwaysAllowMode, NetworkProxyConfig: cfg}}
				meta := metav1.ObjectMeta{Name: "mitm-identities", Namespace: "default"}
				var obj interface{} = &varmor.VarmorPolicy{ObjectMeta: meta, Spec: spec}
				if clusterScope {
					obj = &varmor.VarmorClusterPolicy{ObjectMeta: meta, Spec: spec}
				}
				before, err := json.Marshal(obj)
				assert.NoError(t, err)
				check := func(valid bool, msg string) {
					t.Helper()
					assert.Equal(t, tc.valid, valid, msg)
					if !tc.valid {
						assert.Contains(t, msg, "duplicates the identity")
					}
				}
				check(ValidateAddPolicy(obj, true))
				check(ValidateUpdatePolicy(obj, "NetworkProxy", spec.Target, nil))
				check(ValidateUpdatePolicy(obj, "NetworkProxy", spec.Target, &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: tc.domains[:1]}}))
				after, err := json.Marshal(obj)
				assert.NoError(t, err)
				assert.Equal(t, string(before), string(after), "validation must not merge headers or rewrite domains")
			})
		}
	}
}

func TestValidatePolicy_MITMDomainReferences(t *testing.T) {
	for _, tc := range []struct {
		name, declared, mutation string
		withoutMutation          bool
		errorField, errorText    string
	}{
		{name: "lowercase", declared: "api.example.com", mutation: "api.example.com"},
		{name: "uppercase", declared: "API.example.com", mutation: "API.example.com"},
		{name: "wildcard", declared: "*.Example.COM", mutation: "*.Example.COM"},
		{name: "IPv4 CIDR", declared: "192.0.2.1/32", mutation: "192.0.2.1/32"},
		{name: "IPv6 CIDR", declared: "2001:DB8::1/128", mutation: "2001:DB8::1/128"},
		{name: "no mutation", declared: "API.example.com", withoutMutation: true},
		{name: "declaration leading space", declared: " api.example.com", mutation: "api.example.com", errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "declaration trailing space", declared: "api.example.com ", mutation: "api.example.com", errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "mutation leading space", declared: "api.example.com", mutation: " api.example.com", errorField: "mitm.headerMutations[0].domain", errorText: "remove leading and trailing whitespace"},
		{name: "mutation trailing space", declared: "api.example.com", mutation: "api.example.com ", errorField: "mitm.headerMutations[0].domain", errorText: "remove leading and trailing whitespace"},
		{name: "same padded strings", declared: " api.example.com ", mutation: " api.example.com ", errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "declaration tab newline", declared: "\tapi.example.com\n", mutation: "api.example.com", errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "mutation tab newline", declared: "api.example.com", mutation: "\tapi.example.com\n", errorField: "mitm.headerMutations[0].domain", errorText: "remove leading and trailing whitespace"},
		{name: "declaration Unicode whitespace", declared: "\u2003api.example.com\u00a0", withoutMutation: true, errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "mutation Unicode whitespace", declared: "api.example.com", mutation: "\u2003api.example.com\u00a0", errorField: "mitm.headerMutations[0].domain", errorText: "remove leading and trailing whitespace"},
		{name: "whitespace without mutation", declared: " api.example.com ", withoutMutation: true, errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "case mismatch", declared: "API.example.com", mutation: "api.example.com", errorField: "mitm.headerMutations[0].domain", errorText: "must exactly match an entry in mitm.domains (including case)"},
		{name: "wildcard case mismatch", declared: "*.Example.COM", mutation: "*.example.com", errorField: "mitm.headerMutations[0].domain", errorText: "must exactly match an entry in mitm.domains (including case)"},
		{name: "no wildcard expansion", declared: "*.example.com", mutation: "api.example.com", errorField: "mitm.headerMutations[0].domain", errorText: "must exactly match an entry in mitm.domains (including case)"},
		{name: "no IP alias expansion", declared: "192.0.2.1", mutation: "192.0.2.1/32", errorField: "mitm.headerMutations[0].domain", errorText: "must exactly match an entry in mitm.domains (including case)"},
		{name: "unrelated", declared: "api.example.com", mutation: "other.example.com", errorField: "mitm.headerMutations[0].domain", errorText: "must exactly match an entry in mitm.domains (including case)"},
		{name: "empty", declared: "", withoutMutation: true, errorField: "mitm.domains[0]", errorText: "must not be empty"},
		{name: "blank", declared: " \t ", withoutMutation: true, errorField: "mitm.domains[0]", errorText: "remove leading and trailing whitespace"},
		{name: "internal control", declared: "api.\nexample.com", mutation: "api.\nexample.com", errorField: "mitm.domains[0]", errorText: "contains control characters"},
	} {
		for _, clusterScope := range []bool{false, true} {
			kind := "VarmorPolicy"
			if clusterScope {
				kind = "VarmorClusterPolicy"
			}
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				mitm := &varmor.MITMConfig{Domains: []string{tc.declared}}
				if !tc.withoutMutation {
					mitm.HeaderMutations = []varmor.HeaderMutation{{Domain: tc.mutation,
						Headers: []varmor.HeaderAction{{Name: "Authorization", Value: " exact VALUE "}}}}
				}
				spec := varmor.VarmorPolicySpec{Target: varmor.Target{Kind: "Pod", Name: "sandbox"},
					Policy: varmor.Policy{Enforcer: "NetworkProxy", Mode: varmor.AlwaysAllowMode,
						NetworkProxyConfig: &varmor.NetworkProxyConfig{MITM: mitm}}}
				var obj interface{} = &varmor.VarmorPolicy{Spec: spec}
				if clusterScope {
					obj = &varmor.VarmorClusterPolicy{Spec: spec}
				}
				before, err := json.Marshal(obj)
				assert.NoError(t, err)
				check := func(valid bool, msg string) {
					t.Helper()
					assert.Equal(t, tc.errorText == "", valid, msg)
					if tc.errorText != "" {
						assert.Contains(t, msg, tc.errorField)
						assert.Contains(t, msg, tc.errorText)
					} else {
						assert.Empty(t, msg)
					}
				}
				check(ValidateAddPolicy(obj, true))
				check(ValidateUpdatePolicy(obj, "NetworkProxy", spec.Target, nil))
				check(ValidateUpdatePolicy(obj, "NetworkProxy", spec.Target,
					&varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: []string{"api.example.com"}}}))
				after, err := json.Marshal(obj)
				assert.NoError(t, err)
				assert.Equal(t, string(before), string(after), "validation must not rewrite domains or credentials")
			})
		}
	}
}
