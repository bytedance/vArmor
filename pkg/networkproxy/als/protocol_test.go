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

package als

import "testing"

// TestSharedConstants pins the wire-level constants that MUST stay
// byte-compatible across the shared gRPC ALS protocol between the NetworkProxy
// renderer and the agent's auditor. A change to any value here is a protocol
// break and requires coordinated changes on both ends.
func TestSharedConstants(t *testing.T) {
	cases := map[string]string{
		DefaultALSClusterName:     "varmor_audit_als",
		LogNameClassDeny:          "varmor_np_deny",
		LogNameClassAudit:         "varmor_np_audit",
		ALSFilterChainTagKey:      "filter_chain",
		FilterChainNameHTTP:       "http_chain",
		FilterChainNameMITMTLSDNS: "mitm_tls_dns_chain",
		FilterChainNameMITMTLSIP:  "mitm_tls_ip_chain",
		FilterChainNameTLS:        "tls_chain",
		FilterChainNameTCPDefault: "tcp_default_chain",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("shared constant = %q, want %q", got, want)
		}
	}
}
