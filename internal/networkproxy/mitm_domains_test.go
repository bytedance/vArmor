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

package networkproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestGenerateEnvoySecret_RejectEquivalentMITMDomains(t *testing.T) {
	for _, domains := range [][]string{{"192.0.2.1", "192.0.2.1/32"}, {"api.example.com", "API.EXAMPLE.COM"}} {
		for _, clusterScope := range []bool{false, true} {
			vp := newNetworkProxyPolicy("test", "aliases")
			vp.Spec.Policy.Mode = varmor.EnhanceProtectMode
			vp.Spec.Policy.EnhanceProtect = &varmor.EnhanceProtect{NetworkProxyRawRules: &varmor.NetworkProxyRules{Egress: &varmor.NetworkProxyEgress{DefaultAction: "deny"}}}
			vp.Spec.Policy.NetworkProxyConfig = &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: domains}}
			var obj interface{} = vp
			if clusterScope {
				obj = &varmor.VarmorClusterPolicy{ObjectMeta: vp.ObjectMeta, Spec: vp.Spec}
			}
			secret, err := GenerateEnvoySecret(nil, obj, "test", clusterScope)
			assert.ErrorContains(t, err, "duplicates the identity")
			assert.Nil(t, secret, "controller must not publish invalid xDS or new TLS material")
		}
	}
}
