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

func TestAuditSinkConfig_UsesGRPCALS(t *testing.T) {
	tests := []struct {
		name string
		cfg  AuditSinkConfig
		want bool
	}{
		{"zero value is stdout", AuditSinkConfig{}, false},
		{"explicit stdout", AuditSinkConfig{Sink: AuditSinkStdout}, false},
		{"grpc als", AuditSinkConfig{Sink: AuditSinkGRPCALS}, true},
		{"unknown sink", AuditSinkConfig{Sink: "garbage"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.usesGRPCALS(); got != tt.want {
				t.Errorf("usesGRPCALS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditSinkConfig_ClusterName(t *testing.T) {
	tests := []struct {
		name string
		cfg  AuditSinkConfig
		want string
	}{
		{"empty defaults", AuditSinkConfig{}, DefaultALSClusterName},
		{"empty with grpc als", AuditSinkConfig{Sink: AuditSinkGRPCALS}, DefaultALSClusterName},
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
	cfg := AuditSinkConfig{ProfileName: "my-profile"}
	if got, want := cfg.denyLogName(), LogNameClassDeny+":my-profile"; got != want {
		t.Errorf("denyLogName() = %q, want %q", got, want)
	}
	if got, want := cfg.auditLogName(), LogNameClassAudit+":my-profile"; got != want {
		t.Errorf("auditLogName() = %q, want %q", got, want)
	}

	// Empty profile name still yields a well-formed "<class>:" prefix.
	empty := AuditSinkConfig{}
	if got, want := empty.denyLogName(), LogNameClassDeny+":"; got != want {
		t.Errorf("denyLogName() empty = %q, want %q", got, want)
	}
	if got, want := empty.auditLogName(), LogNameClassAudit+":"; got != want {
		t.Errorf("auditLogName() empty = %q, want %q", got, want)
	}
}

// TestAuditSinkConfig_SharedConstants pins the wire-level constants that MUST
// stay byte-compatible across the shared gRPC ALS protocol. A change here is
// a protocol break.
func TestAuditSinkConfig_SharedConstants(t *testing.T) {
	cases := map[string]string{
		AuditSinkStdout:       "stdout",
		AuditSinkGRPCALS:      "grpc_als",
		DefaultALSClusterName: "varmor_audit_als",
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

// TestStdoutSinkRendersDefaultClusters verifies that the stdout sink (both the
// zero value and the explicit AuditSinkStdout) produces an identical CDS to
// the pre-audit rendering: this commit must not change any emitted bytes.
func TestStdoutSinkRendersDefaultClusters(t *testing.T) {
	base := renderClustersYAML(7, false, AuditSinkConfig{})
	explicit := renderClustersYAML(7, false, AuditSinkConfig{Sink: AuditSinkStdout})
	if base != explicit {
		t.Errorf("zero-value and explicit stdout CDS differ:\n--- zero ---\n%s\n--- stdout ---\n%s", base, explicit)
	}
}
