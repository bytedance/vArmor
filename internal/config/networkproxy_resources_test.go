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

	"github.com/go-logr/logr"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// quantityEqual asserts that a ResourceList entry equals the expected quantity
// string, reporting a helpful message on mismatch.
func quantityEqual(t *testing.T, rl corev1.ResourceList, name corev1.ResourceName, want string) {
	t.Helper()
	got, ok := rl[name]
	assert.Assert(t, ok, "resource %s should be present", name)
	assert.Assert(t, got.Cmp(resource.MustParse(want)) == 0,
		"resource %s = %s, want %s", name, got.String(), want)
}

func TestParseDynamicConfig_NetworkProxyDefaultResources(t *testing.T) {
	raw := `
networkProxy:
  defaultResources:
    nonMitm:
      requests:
        cpu: 60m
        memory: 80Mi
      limits:
        cpu: 600m
    mitm:
      requests:
        cpu: 120m
      limits:
        cpu: 1200m
        memory: 640Mi
`
	cfg := parseDynamicConfig(raw, logr.Discard())
	dr := cfg.NetworkProxy.DefaultResources
	assert.Equal(t, dr.NonMITM.Requests["cpu"], "60m")
	assert.Equal(t, dr.NonMITM.Requests["memory"], "80Mi")
	assert.Equal(t, dr.NonMITM.Limits["cpu"], "600m")
	assert.Equal(t, dr.MITM.Requests["cpu"], "120m")
	assert.Equal(t, dr.MITM.Limits["cpu"], "1200m")
	assert.Equal(t, dr.MITM.Limits["memory"], "640Mi")
}

func TestGetNetworkProxyDefaultResources_Empty(t *testing.T) {
	resetDynamicConfigToDefault()
	t.Cleanup(resetDynamicConfigToDefault)

	nonMITM, mitm := GetNetworkProxyDefaultResources()
	// Nothing configured: all resource lists are nil so the merge is a no-op.
	assert.Assert(t, nonMITM.Requests == nil, "nonMITM requests should be nil when unconfigured")
	assert.Assert(t, nonMITM.Limits == nil, "nonMITM limits should be nil when unconfigured")
	assert.Assert(t, mitm.Requests == nil, "mitm requests should be nil when unconfigured")
	assert.Assert(t, mitm.Limits == nil, "mitm limits should be nil when unconfigured")
}

func TestGetNetworkProxyDefaultResources_PartialAndTiers(t *testing.T) {
	withConfig(t, DynamicConfig{
		NetworkProxy: NetworkProxyDynamicConfig{
			DefaultResources: ProxyDefaultResources{
				NonMITM: ProxyResourceTier{
					Requests: map[string]string{"cpu": "60m"}, // memory intentionally absent
					Limits:   map[string]string{"cpu": "600m", "memory": "300Mi"},
				},
				MITM: ProxyResourceTier{
					Requests: map[string]string{"memory": "200Mi"},
					Limits:   map[string]string{"cpu": "1500m"},
				},
			},
		},
	})

	nonMITM, mitm := GetNetworkProxyDefaultResources()

	// Non-MITM tier: only configured leaves are present.
	quantityEqual(t, nonMITM.Requests, corev1.ResourceCPU, "60m")
	_, hasMem := nonMITM.Requests[corev1.ResourceMemory]
	assert.Assert(t, !hasMem, "unconfigured nonMITM requests.memory should be absent")
	quantityEqual(t, nonMITM.Limits, corev1.ResourceCPU, "600m")
	quantityEqual(t, nonMITM.Limits, corev1.ResourceMemory, "300Mi")

	// MITM tier is independent of the non-MITM tier.
	quantityEqual(t, mitm.Requests, corev1.ResourceMemory, "200Mi")
	_, hasCPU := mitm.Requests[corev1.ResourceCPU]
	assert.Assert(t, !hasCPU, "unconfigured mitm requests.cpu should be absent")
	quantityEqual(t, mitm.Limits, corev1.ResourceCPU, "1500m")
}

func TestGetNetworkProxyDefaultResources_InvalidValuesDropped(t *testing.T) {
	withConfig(t, DynamicConfig{
		NetworkProxy: NetworkProxyDynamicConfig{
			DefaultResources: ProxyDefaultResources{
				NonMITM: ProxyResourceTier{
					Requests: map[string]string{"cpu": "not-a-quantity", "memory": "80Mi"},
				},
			},
		},
	})

	nonMITM, _ := GetNetworkProxyDefaultResources()
	// The invalid cpu is dropped; the valid memory survives.
	_, hasCPU := nonMITM.Requests[corev1.ResourceCPU]
	assert.Assert(t, !hasCPU, "invalid cpu quantity should be dropped")
	quantityEqual(t, nonMITM.Requests, corev1.ResourceMemory, "80Mi")
}

func TestGetNetworkProxyDefaultResources_NegativeAndZeroDropped(t *testing.T) {
	withConfig(t, DynamicConfig{
		NetworkProxy: NetworkProxyDynamicConfig{
			DefaultResources: ProxyDefaultResources{
				// cpu is negative and memory is zero: both parse as valid
				// quantities but are meaningless as sidecar resources, so both
				// must be dropped (field falls back to the built-in default).
				NonMITM: ProxyResourceTier{
					Requests: map[string]string{"cpu": "-5m", "memory": "0"},
					Limits:   map[string]string{"cpu": "500m"},
				},
			},
		},
	})

	nonMITM, _ := GetNetworkProxyDefaultResources()
	_, hasCPU := nonMITM.Requests[corev1.ResourceCPU]
	assert.Assert(t, !hasCPU, "negative cpu request should be dropped")
	_, hasMem := nonMITM.Requests[corev1.ResourceMemory]
	assert.Assert(t, !hasMem, "zero memory request should be dropped")
	// A valid entry in the same block still survives.
	quantityEqual(t, nonMITM.Limits, corev1.ResourceCPU, "500m")
}

func TestGetNetworkProxyDefaultResources_UnknownResourceNameDropped(t *testing.T) {
	withConfig(t, DynamicConfig{
		NetworkProxy: NetworkProxyDynamicConfig{
			DefaultResources: ProxyDefaultResources{
				// "cpuu" is a typo: a valid quantity attached to an unknown
				// resource name. It must be dropped rather than injected as a
				// bogus resource, and the real cpu keeps falling back.
				NonMITM: ProxyResourceTier{
					Requests: map[string]string{"cpuu": "100m", "memory": "80Mi"},
				},
			},
		},
	})

	nonMITM, _ := GetNetworkProxyDefaultResources()
	_, hasTypo := nonMITM.Requests[corev1.ResourceName("cpuu")]
	assert.Assert(t, !hasTypo, "unknown resource name should be dropped")
	_, hasCPU := nonMITM.Requests[corev1.ResourceCPU]
	assert.Assert(t, !hasCPU, "the real cpu was never set, so it must be absent")
	quantityEqual(t, nonMITM.Requests, corev1.ResourceMemory, "80Mi")
}

func TestValidateProxyResourceEntry(t *testing.T) {
	cases := []struct {
		name, value string
		wantErr     bool
	}{
		{"cpu", "100m", false},
		{"memory", "64Mi", false},
		{"cpu", "-5m", true},   // negative
		{"memory", "0", true},  // zero
		{"cpu", "abc", true},   // unparseable
		{"cpuu", "100m", true}, // unknown resource name
	}
	for _, c := range cases {
		_, err := validateProxyResourceEntry(c.name, c.value)
		if c.wantErr {
			assert.Assert(t, err != nil, "%s=%s should be rejected", c.name, c.value)
		} else {
			assert.NilError(t, err, "%s=%s should be accepted", c.name, c.value)
		}
	}
}

// TestWarnInvalidProxyResourceValues_LimitBelowRequest exercises the load-time
// warner directly to ensure it does not panic and handles the limit<request and
// invalid-entry paths across both tiers. It is a smoke test: the warner only
// logs, so we assert it runs cleanly against a config that trips every branch.
func TestWarnInvalidProxyResourceValues_LimitBelowRequest(t *testing.T) {
	dr := ProxyDefaultResources{
		NonMITM: ProxyResourceTier{
			Requests: map[string]string{"cpu": "500m"},
			Limits:   map[string]string{"cpu": "200m"}, // limit < request (non-mitm)
		},
		MITM: ProxyResourceTier{
			Requests: map[string]string{"memory": "256Mi", "cpuu": "1"}, // typo entry
			Limits:   map[string]string{"memory": "128Mi"},              // limit < request (mitm)
		},
	}
	// Must not panic; all findings go to the logger.
	warnInvalidProxyResourceValues(dr, logr.Discard())
}
