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
// sidecar container by merging user-specified overrides on top of the built-in
// defaults. The merge is field-level: only the resource types (cpu, memory)
// explicitly specified in the override are applied; all others retain the
// default values.
//
// Merge chain:
//
//	Policy override > Built-in defaults (selected by mitmEnabled)
func ResolveProxyResources(override *varmor.ProxyResourceOverride, mitmEnabled bool) corev1.ResourceRequirements {
	result := DefaultProxyResources(mitmEnabled)
	if override == nil {
		return result
	}
	for k, v := range override.Requests {
		result.Requests[k] = v
	}
	for k, v := range override.Limits {
		result.Limits[k] = v
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
