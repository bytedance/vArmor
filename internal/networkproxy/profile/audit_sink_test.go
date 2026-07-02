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

	als "github.com/bytedance/vArmor/pkg/networkproxy/als"
)

func TestAuditSinkConfig_ClusterName(t *testing.T) {
	tests := []struct {
		name string
		cfg  AuditSinkConfig
		want string
	}{
		{"empty defaults", AuditSinkConfig{}, als.DefaultALSClusterName},
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
	if got, want := cfg.denyLogName(), als.LogNameClassDeny+":my-profile"; got != want {
		t.Errorf("denyLogName() = %q, want %q", got, want)
	}
	if got, want := cfg.auditLogName(), als.LogNameClassAudit+":my-profile"; got != want {
		t.Errorf("auditLogName() = %q, want %q", got, want)
	}

	// Empty profile name still yields a well-formed "<class>:" prefix.
	empty := AuditSinkConfig{}
	if got, want := empty.denyLogName(), als.LogNameClassDeny+":"; got != want {
		t.Errorf("denyLogName() empty = %q, want %q", got, want)
	}
	if got, want := empty.auditLogName(), als.LogNameClassAudit+":"; got != want {
		t.Errorf("auditLogName() empty = %q, want %q", got, want)
	}
}
