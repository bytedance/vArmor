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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadAuditEventMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		expected map[string]interface{}
	}{
		{name: "empty"},
		{name: "empty object", metadata: `{}`},
		{name: "null", metadata: `null`},
		{name: "null with whitespace", metadata: " \t null\r\n"},
		{name: "invalid JSON", metadata: `invalid`},
		{
			name:     "preserve fields and use actual namespace",
			metadata: `{"clusterID":"cluster-1","custom":42,"varmorNamespace":"ignored"}`,
			expected: map[string]interface{}{"clusterID": "cluster-1", "custom": float64(42)},
		},
		{
			name:     "preserve null field",
			metadata: `{"custom":null}`,
			expected: map[string]interface{}{"custom": nil},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AUDIT_EVENT_METADATA", tt.metadata)
			t.Setenv("VARMOR_NAMESPACE", "test-namespace")
			want := map[string]interface{}{"varmorNamespace": "test-namespace"}
			for key, value := range tt.expected {
				want[key] = value
			}
			var got map[string]interface{}
			if assert.NotPanics(t, func() { got = loadAuditEventMetadata() }) {
				assert.Equal(t, want, got)
			}
		})
	}
}
