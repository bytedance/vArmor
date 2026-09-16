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
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// Every HTTP filter chain must authorize and forward the same normalized path.
func TestHTTPPathNormalizationConfig(t *testing.T) {
	for _, mitmEnabled := range []bool{false, true} {
		name := "plaintext"
		var mitm *MITMInput
		wantChains := []string{"http_chain"}
		if mitmEnabled {
			name = "mitm"
			mitm = &MITMInput{Domains: []string{"api.example.com", "127.0.0.1"}, CertificateSDSPath: "/cert.pem"}
			wantChains = append(wantChains, "mitm_tls_dns_chain", "mitm_tls_ip_chain")
		}
		t.Run(name, func(t *testing.T) {
			e := &varmor.NetworkProxyEgress{DefaultAction: "allow", HTTPRules: []varmor.NetworkProxyHTTPRule{{
				Qualifiers: []string{"deny", "audit"}, Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{{Exact: "/admin/secret"}}},
			}}}
			result, err := TranslateEgressRules(e, 1, 15001, mitm, IPStackConfig{IPv4: true}, AuditSinkConfig{})
			if !assert.NoError(t, err) {
				return
			}
			var lds struct {
				Resources []struct {
					FilterChains []struct {
						Name    string `json:"name"`
						Filters []struct {
							Name        string `json:"name"`
							TypedConfig struct {
								Normalize      bool   `json:"normalize_path"`
								Merge          bool   `json:"merge_slashes"`
								EscapedSlashes string `json:"path_with_escaped_slashes_action"`
							} `json:"typed_config"`
						} `json:"filters"`
					} `json:"filter_chains"`
				} `json:"resources"`
			}
			if !assert.NoError(t, yaml.Unmarshal([]byte(result.LDS), &lds)) {
				return
			}
			var chains []string
			for _, listener := range lds.Resources {
				for _, chain := range listener.FilterChains {
					for _, filter := range chain.Filters {
						if filter.Name != "envoy.filters.network.http_connection_manager" {
							continue
						}
						chains = append(chains, chain.Name)
						assert.True(t, filter.TypedConfig.Normalize, chain.Name)
						assert.True(t, filter.TypedConfig.Merge, chain.Name)
						assert.Equal(t, "UNESCAPE_AND_FORWARD", filter.TypedConfig.EscapedSlashes, chain.Name)
					}
				}
			}
			assert.ElementsMatch(t, wantChains, chains)
		})
	}
}
