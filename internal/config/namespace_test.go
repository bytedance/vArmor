// Copyright 2024 vArmor Authors
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

import "testing"

// Test_getVarmorNamespace verifies the resolution precedence that fixes the
// varmorNamespace attribution bug: in the in-sidecar (kata) path the sink runs
// inside the business Pod, where POD_NAMESPACE is the workload namespace, so
// the explicit VARMOR_NAMESPACE env (the manager's own namespace) must win.
func Test_getVarmorNamespace(t *testing.T) {
	// VARMOR_NAMESPACE set: it wins over POD_NAMESPACE (the in-sidecar case).
	t.Run("VARMOR_NAMESPACE takes precedence over POD_NAMESPACE", func(t *testing.T) {
		t.Setenv("VARMOR_NAMESPACE", "varmor")
		t.Setenv("POD_NAMESPACE", "demo")
		if got := getVarmorNamespace(); got != "varmor" {
			t.Fatalf("getVarmorNamespace() = %q, want %q", got, "varmor")
		}
	})

	// VARMOR_NAMESPACE unset: fall back to POD_NAMESPACE (the agent path where
	// POD_NAMESPACE already is the vArmor namespace).
	t.Run("falls back to POD_NAMESPACE when VARMOR_NAMESPACE is empty", func(t *testing.T) {
		t.Setenv("VARMOR_NAMESPACE", "")
		t.Setenv("POD_NAMESPACE", "custom-varmor")
		if got := getVarmorNamespace(); got != "custom-varmor" {
			t.Fatalf("getVarmorNamespace() = %q, want %q", got, "custom-varmor")
		}
	})

	// Neither set: fall back to the built-in default.
	t.Run("falls back to the built-in default when both are empty", func(t *testing.T) {
		t.Setenv("VARMOR_NAMESPACE", "")
		t.Setenv("POD_NAMESPACE", "")
		if got := getVarmorNamespace(); got != "varmor" {
			t.Fatalf("getVarmorNamespace() = %q, want %q", got, "varmor")
		}
	})
}
