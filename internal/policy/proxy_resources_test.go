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

package policy

import (
	"testing"

	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

func mustQ(t *testing.T, rl corev1.ResourceList, name corev1.ResourceName, want string) {
	t.Helper()
	got, ok := rl[name]
	assert.Assert(t, ok, "resource %s should be present", name)
	assert.Assert(t, got.Cmp(resource.MustParse(want)) == 0,
		"resource %s = %s, want %s", name, got.String(), want)
}

// TestResolveProxyResources_BuiltinOnly verifies that with no global config and
// no per-policy override, the built-in MITM-aware defaults are returned.
func TestResolveProxyResources_BuiltinOnly(t *testing.T) {
	// Non-MITM built-in defaults.
	r := ResolveProxyResources(nil, false)
	mustQ(t, r.Requests, corev1.ResourceCPU, "50m")
	mustQ(t, r.Requests, corev1.ResourceMemory, "64Mi")
	mustQ(t, r.Limits, corev1.ResourceCPU, "500m")
	mustQ(t, r.Limits, corev1.ResourceMemory, "256Mi")

	// MITM built-in defaults.
	rm := ResolveProxyResources(nil, true)
	mustQ(t, rm.Requests, corev1.ResourceCPU, "100m")
	mustQ(t, rm.Requests, corev1.ResourceMemory, "128Mi")
	mustQ(t, rm.Limits, corev1.ResourceCPU, "1000m")
	mustQ(t, rm.Limits, corev1.ResourceMemory, "512Mi")
}

// TestResolveProxyResources_GlobalOverlaysFieldLevel verifies the middle layer:
// global config overrides only the fields it sets; unset fields keep the
// built-in defaults.
func TestResolveProxyResources_GlobalOverlaysFieldLevel(t *testing.T) {
	restore := varmorconfig.SetDynamicConfigForTest(varmorconfig.DynamicConfig{
		NetworkProxy: varmorconfig.NetworkProxyDynamicConfig{
			DefaultResources: varmorconfig.ProxyDefaultResources{
				NonMITM: varmorconfig.ProxyResourceTier{
					Requests: map[string]string{"cpu": "70m"},      // only cpu; memory falls back
					Limits:   map[string]string{"memory": "300Mi"}, // only memory; cpu falls back
				},
			},
		},
	})
	defer restore()

	r := ResolveProxyResources(nil, false)
	mustQ(t, r.Requests, corev1.ResourceCPU, "70m")     // from global
	mustQ(t, r.Requests, corev1.ResourceMemory, "64Mi") // built-in fallback
	mustQ(t, r.Limits, corev1.ResourceCPU, "500m")      // built-in fallback
	mustQ(t, r.Limits, corev1.ResourceMemory, "300Mi")  // from global
}

// TestResolveProxyResources_MITMTierSelected verifies that the MITM tier of the
// global config is applied only for MITM policies, and the non-MITM tier only
// for non-MITM policies.
func TestResolveProxyResources_MITMTierSelected(t *testing.T) {
	restore := varmorconfig.SetDynamicConfigForTest(varmorconfig.DynamicConfig{
		NetworkProxy: varmorconfig.NetworkProxyDynamicConfig{
			DefaultResources: varmorconfig.ProxyDefaultResources{
				NonMITM: varmorconfig.ProxyResourceTier{
					Requests: map[string]string{"cpu": "70m"},
				},
				MITM: varmorconfig.ProxyResourceTier{
					Requests: map[string]string{"cpu": "200m"},
				},
			},
		},
	})
	defer restore()

	// Non-MITM policy sees the non-MITM tier only.
	r := ResolveProxyResources(nil, false)
	mustQ(t, r.Requests, corev1.ResourceCPU, "70m")

	// MITM policy sees the MITM tier only (non-MITM tier's cpu must NOT leak in).
	rm := ResolveProxyResources(nil, true)
	mustQ(t, rm.Requests, corev1.ResourceCPU, "200m")
	mustQ(t, rm.Requests, corev1.ResourceMemory, "128Mi") // MITM built-in fallback
}

// TestResolveProxyResources_OverrideWinsOverGlobal verifies the full three-layer
// precedence: per-policy override > global config > built-in default.
func TestResolveProxyResources_OverrideWinsOverGlobal(t *testing.T) {
	restore := varmorconfig.SetDynamicConfigForTest(varmorconfig.DynamicConfig{
		NetworkProxy: varmorconfig.NetworkProxyDynamicConfig{
			DefaultResources: varmorconfig.ProxyDefaultResources{
				NonMITM: varmorconfig.ProxyResourceTier{
					Requests: map[string]string{"cpu": "70m", "memory": "100Mi"},
					Limits:   map[string]string{"cpu": "700m"},
				},
			},
		},
	})
	defer restore()

	override := &varmor.ProxyResourceOverride{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("90m"), // beats global 70m
		},
	}

	r := ResolveProxyResources(override, false)
	mustQ(t, r.Requests, corev1.ResourceCPU, "90m")      // override wins
	mustQ(t, r.Requests, corev1.ResourceMemory, "100Mi") // global (no override)
	mustQ(t, r.Limits, corev1.ResourceCPU, "700m")       // global (no override)
	mustQ(t, r.Limits, corev1.ResourceMemory, "256Mi")   // built-in fallback
}

// TestResolveProxyResources_EmptyGlobalIsNoOp verifies that an empty global
// config leaves the built-in + override behaviour unchanged (backward compat).
func TestResolveProxyResources_EmptyGlobalIsNoOp(t *testing.T) {
	restore := varmorconfig.SetDynamicConfigForTest(varmorconfig.DynamicConfig{})
	defer restore()

	override := &varmor.ProxyResourceOverride{
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
	}
	r := ResolveProxyResources(override, false)
	mustQ(t, r.Requests, corev1.ResourceCPU, "50m")     // built-in
	mustQ(t, r.Requests, corev1.ResourceMemory, "64Mi") // built-in
	mustQ(t, r.Limits, corev1.ResourceCPU, "500m")      // built-in
	mustQ(t, r.Limits, corev1.ResourceMemory, "1Gi")    // override
}
