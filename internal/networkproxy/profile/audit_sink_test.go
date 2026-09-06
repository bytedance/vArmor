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

import "testing"

func TestAuditSinkConfig_ClusterName(t *testing.T) {
	tests := []struct {
		name string
		cfg  AuditSinkConfig
		want string
	}{
		{"empty defaults", AuditSinkConfig{}, DefaultALSClusterName},
		{"override", AuditSinkConfig{ALSClusterName: "custom_als"}, "custom_als"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.clusterName(); got != tt.want {
				t.Errorf("clusterName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuditSinkConfig_LogNames(t *testing.T) {
	for _, name := range []string{"my-profile", ""} {
		cfg := AuditSinkConfig{ProfileName: name}
		if got, want := cfg.eventLogName(), LogNameClassEvent+":"+name; got != want {
			t.Errorf("eventLogName() = %q, want %q", got, want)
		}
	}
}

// TestAuditSinkConfig_SharedConstants pins the wire-level constants that MUST
// stay byte-compatible across the shared gRPC ALS protocol. A change here is
// a protocol break.
func TestAuditSinkConfig_SharedConstants(t *testing.T) {
	cases := map[string]string{
		DefaultALSClusterName: "varmor_audit_als",
		LogNameClassEvent:     "varmor_np_event",
		LogNameClassDeny:      "varmor_np_deny",
		LogNameClassAudit:     "varmor_np_audit",
		ALSFilterChainTagKey:  "filter_chain",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("shared constant = %q, want %q", got, want)
		}
	}
}
