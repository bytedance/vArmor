// Copyright 2025 vArmor Authors
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
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

// DefaultProxyResources returns the built-in resource requirements for the
// proxy sidecar container. MITM mode uses significantly higher defaults
// because the sidecar performs double TLS handshakes (one with the client,
// one with the upstream server) for every new connection.
//
// Non-MITM defaults:
//
//	Requests: 50m CPU,  64Mi memory
//	Limits:   500m CPU, 256Mi memory
//
// MITM defaults:
//
//	Requests: 100m CPU,  128Mi memory
//	Limits:   1000m CPU, 512Mi memory
func DefaultProxyResources(mitmEnabled bool) corev1.ResourceRequirements {
	if mitmEnabled {
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1000m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
		}
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
}

// ResolveProxyResources computes the final resource requirements for the proxy
// sidecar container using a three-layer, field-level merge chain. Each leaf
// scalar (requests.cpu, requests.memory, limits.cpu, limits.memory) is resolved
// independently: a value from a higher-priority layer wins, otherwise the value
// falls through to the next layer. This means a partially-specified global
// config or per-policy override only overrides the fields it sets; every other
// field keeps falling back to the built-in default.
//
// Merge chain (highest priority first):
//
//	Per-policy override
//	  > Cluster-global config (varmor-config ConfigMap, MITM-aware tier)
//	    > Built-in defaults (selected by mitmEnabled)
func ResolveProxyResources(override *varmor.ProxyResourceOverride, mitmEnabled bool) corev1.ResourceRequirements {
	// Layer 1 (lowest priority): built-in defaults.
	result := DefaultProxyResources(mitmEnabled)

	// Layer 2: cluster-global defaults from the varmor-config ConfigMap.
	// GetNetworkProxyDefaultResources returns two MITM-aware tiers; pick the
	// one matching this policy. Only non-nil resource lists overlay, and within
	// them only present keys apply (field-level fallback).
	nonMITMGlobal, mitmGlobal := varmorconfig.GetNetworkProxyDefaultResources()
	global := nonMITMGlobal
	if mitmEnabled {
		global = mitmGlobal
	}
	for k, v := range global.Requests {
		result.Requests[k] = v
	}
	for k, v := range global.Limits {
		result.Limits[k] = v
	}

	// Layer 3 (highest priority): per-policy override.
	if override != nil {
		for k, v := range override.Requests {
			result.Requests[k] = v
		}
		for k, v := range override.Limits {
			result.Limits[k] = v
		}
	}

	return result
}

// MarshalProxyResourcesJSON serializes corev1.ResourceRequirements to a JSON
// string suitable for embedding in JSON Patch operations. Returns the JSON
// string (e.g., `{"requests":{"cpu":"50m","memory":"64Mi"},"limits":{...}}`).
// On marshal error, falls back to a safe non-MITM default.
func MarshalProxyResourcesJSON(res corev1.ResourceRequirements) string {
	data, err := json.Marshal(res)
	if err != nil {
		// Fallback to hardcoded non-MITM defaults on marshal failure.
		return `{"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"cpu":"500m","memory":"256Mi"}}`
	}
	return string(data)
}
