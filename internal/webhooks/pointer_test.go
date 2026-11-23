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

package webhooks

import (
	"testing"

	"gotest.tools/assert"
)

func TestTemplateAtPointer(t *testing.T) {
	root := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{"spec": map[string]interface{}{"containers": []interface{}{map[string]interface{}{"name": "c"}}}},
		},
		"array": []interface{}{map[string]interface{}{"name": "a"}, map[string]interface{}{"name": "b"}},
		"num":   float64(42),
	}
	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty", "", false},
		{"valid nested", "/spec/template", false},
		{"array index", "/array/1", false},
		{"missing field", "/spec/absent", true},
		{"non-slash prefix", "spec/template", true},
		{"contains backslash", "/spec/tem\\plate", true},
		{"contains quote", `/spec/"template"`, true},
		{"contains tab", "/spec/tem\tplate", true},
		{"contains NUL", "/spec/tem\x00plate", true},
		{"contains other C0 control", "/spec/a\x01b", true},
		{"contains DEL", "/spec/tem\x7fplate", true},
		{"non-object leaf", "/num", true},
		{"negative array index", "/array/-1", true},
		{"out-of-bounds array index", "/array/99", true},
		{"integer where map expected", "/num/sub", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := templateAtPointer(root, tc.path)
			if tc.wantErr {
				assert.Assert(t, err != nil, "path %q should error", tc.path)
				return
			}
			assert.NilError(t, err)
			assert.Assert(t, result != nil, "non-error path %q must yield a template", tc.path)
		})
	}
}
