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
