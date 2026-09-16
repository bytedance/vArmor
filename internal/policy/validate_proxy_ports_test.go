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

func TestValidatePolicy_EffectiveProxyPorts(t *testing.T) {
	port := func(v uint16) *uint16 { return &v }
	cases := []struct {
		name   string
		config *varmor.NetworkProxyConfig
		valid  bool
	}{
		{"omitted config", nil, true},
		{"empty config", &varmor.NetworkProxyConfig{}, true},
		{"proxy collides with default admin", &varmor.NetworkProxyConfig{ProxyPort: port(15000)}, false},
		{"admin collides with default proxy", &varmor.NetworkProxyConfig{ProxyAdminPort: port(15001)}, false},
		{"explicit equal ports", &varmor.NetworkProxyConfig{ProxyPort: port(16000), ProxyAdminPort: port(16000)}, false},
		{"explicit defaults", &varmor.NetworkProxyConfig{ProxyPort: port(15001), ProxyAdminPort: port(15000)}, true},
		{"explicit proxy default", &varmor.NetworkProxyConfig{ProxyPort: port(15001)}, true},
		{"explicit admin default", &varmor.NetworkProxyConfig{ProxyAdminPort: port(15000)}, true},
		{"custom proxy only", &varmor.NetworkProxyConfig{ProxyPort: port(16001)}, true},
		{"custom admin only", &varmor.NetworkProxyConfig{ProxyAdminPort: port(16000)}, true},
		{"custom pair", &varmor.NetworkProxyConfig{ProxyPort: port(16001), ProxyAdminPort: port(16000)}, true},
		{"swapped defaults", &varmor.NetworkProxyConfig{ProxyPort: port(15000), ProxyAdminPort: port(15001)}, true},
	}
	for _, tc := range cases {
		for _, kind := range []string{"VarmorPolicy", "VarmorClusterPolicy"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				spec := varmor.VarmorPolicySpec{
					Target: varmor.Target{Kind: "Pod", Name: "sandbox"},
					Policy: varmor.Policy{Enforcer: "NetworkProxy", Mode: varmor.AlwaysAllowMode, NetworkProxyConfig: tc.config.DeepCopy()},
				}
				meta := metav1.ObjectMeta{Name: "ports", Namespace: "default"}
				var p interface{} = &varmor.VarmorPolicy{ObjectMeta: meta, Spec: spec}
				if kind == "VarmorClusterPolicy" {
					p = &varmor.VarmorClusterPolicy{ObjectMeta: meta, Spec: spec}
				}
				before, err := json.Marshal(p)
				assert.NoError(t, err)
				check := func(t *testing.T, valid bool, msg string) {
					t.Helper()
					assert.Equal(t, tc.valid, valid, msg)
					if tc.valid {
						assert.Empty(t, msg)
					} else {
						assert.Equal(t, "proxyPort and proxyAdminPort must be different", msg)
					}
					after, err := json.Marshal(p)
					assert.NoError(t, err)
					assert.Equal(t, string(before), string(after), "validation must not default the input in place")
				}
				t.Run("create", func(t *testing.T) {
					valid, msg := ValidateAddPolicy(p, true)
					check(t, valid, msg)
				})
				t.Run("controller update", func(t *testing.T) {
					valid, msg := ValidateUpdatePolicy(p, "NetworkProxy", spec.Target, nil)
					check(t, valid, msg)
				})
				t.Run("unchanged ports update", func(t *testing.T) {
					old := tc.config.DeepCopy()
					if old == nil {
						old = &varmor.NetworkProxyConfig{}
					}
					valid, msg := ValidateUpdatePolicy(p, "NetworkProxy", spec.Target, old)
					check(t, valid, msg)
				})
			})
		}
	}
}

// Collision checks must not replace or weaken the existing update contract.
func TestValidateUpdatePolicy_EffectiveProxyPortsImmutable(t *testing.T) {
	port := func(v uint16) *uint16 { return &v }
	for _, kind := range []string{"VarmorPolicy", "VarmorClusterPolicy"} {
		for _, tc := range []struct {
			name     string
			old, new *varmor.NetworkProxyConfig
			valid    bool
		}{
			{"make defaults explicit", &varmor.NetworkProxyConfig{}, &varmor.NetworkProxyConfig{ProxyPort: port(15001), ProxyAdminPort: port(15000)}, true},
			{"remove explicit defaults", &varmor.NetworkProxyConfig{ProxyPort: port(15001), ProxyAdminPort: port(15000)}, nil, true},
			{"change proxy port", &varmor.NetworkProxyConfig{}, &varmor.NetworkProxyConfig{ProxyPort: port(16001)}, false},
			{"change admin port", &varmor.NetworkProxyConfig{}, &varmor.NetworkProxyConfig{ProxyAdminPort: port(16000)}, false},
			{"remove custom ports", &varmor.NetworkProxyConfig{ProxyPort: port(16001), ProxyAdminPort: port(16000)}, nil, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				spec := varmor.VarmorPolicySpec{
					Target: varmor.Target{Kind: "Pod", Name: "sandbox"},
					Policy: varmor.Policy{Enforcer: "NetworkProxy", Mode: varmor.AlwaysAllowMode, NetworkProxyConfig: tc.new},
				}
				var p interface{} = &varmor.VarmorPolicy{Spec: spec}
				if kind == "VarmorClusterPolicy" {
					p = &varmor.VarmorClusterPolicy{Spec: spec}
				}
				valid, msg := ValidateUpdatePolicy(p, "NetworkProxy", spec.Target, tc.old)
				assert.Equal(t, tc.valid, valid, msg)
				if tc.valid {
					assert.Empty(t, msg)
				} else {
					assert.Contains(t, msg, "Modifying proxyUID, proxyPort, or proxyAdminPort")
				}
			})
		}
	}
}
