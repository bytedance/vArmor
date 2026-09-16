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
	"strings"
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/go-logr/logr"
	"google.golang.org/protobuf/encoding/protojson"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"github.com/bytedance/vArmor/internal/networkproxy/profile"
)

func TestGenerateEnvoySecret_DynamicTLS(t *testing.T) {
	for _, clusterScope := range []bool{false, true} {
		vp := newNetworkProxyPolicy("test", "sds")
		vp.Spec.Policy.Mode = varmor.EnhanceProtectMode
		vp.Spec.Policy.EnhanceProtect = &varmor.EnhanceProtect{NetworkProxyRawRules: &varmor.NetworkProxyRules{Egress: &varmor.NetworkProxyEgress{DefaultAction: "allow"}}}
		vp.Spec.Policy.NetworkProxyConfig = &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: []string{"api.example.test"}}}
		var obj interface{} = vp
		if clusterScope {
			obj = &varmor.VarmorClusterPolicy{ObjectMeta: vp.ObjectMeta, Spec: vp.Spec}
		}
		secret, err := GenerateEnvoySecret(nil, obj, "test", clusterScope)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(secret.StringData[SecretKeyLDS], "tls_certificate_sds_secret_configs:") || !strings.Contains(secret.StringData[SecretKeyCDS], "validation_context_sds_secret_config:") {
			t.Fatal("generated xDS does not reference SDS")
		}
		for key, name := range map[string]string{profile.MITMCertSDSFile: profile.MITMCertSecretName, profile.MITMValidationSDSFile: profile.MITMValidationSecretName} {
			var response discoveryv3.DiscoveryResponse
			if err := protojson.Unmarshal([]byte(secret.StringData[key]), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Resources) != 1 {
				t.Fatal("missing TLS secret")
			}
			var s tlsv3.Secret
			if err := response.Resources[0].UnmarshalTo(&s); err != nil {
				t.Fatal(err)
			}
			if s.Name != name {
				t.Fatal("mismatched SDS resource name")
			}
			if key == profile.MITMCertSDSFile {
				if s.GetTlsCertificate().CertificateChain.GetInlineString() != secret.StringData[SecretKeyMITMLeafCert] || s.GetTlsCertificate().PrivateKey.GetInlineString() != secret.StringData[SecretKeyMITMLeafKey] {
					t.Fatal("SDS leaf differs from issued material")
				}
			} else if s.GetValidationContext().TrustedCa.GetInlineString() != secret.StringData[SecretKeyMITMCABundle] {
				t.Fatal("SDS trust differs from projected application trust")
			}
		}
		if err := checkSecretSize(secret, logr.Discard()); err != nil {
			t.Fatal(err)
		}
	}
}
