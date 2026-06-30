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

package webhooks

import (
	"strings"
	"testing"

	"gotest.tools/assert"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

// Test_buildNetworkProxyPatch_AuditInjected asserts that NetworkProxy
// violations always stream over gRPC ALS: the webhook JSON-Patch
// unconditionally injects the Downward API Pod identity env vars and the
// shared ALS socket hostPath volume/mount.
func Test_buildNetworkProxyPatch_AuditInjected(t *testing.T) {
	patch := buildNetworkProxyPatch("varmor-testns-test", true, nil)

	// Sidecar carries the Downward API env array.
	assert.Assert(t, strings.Contains(patch, `"env": [`),
		"patch should contain the sidecar env array")
	assert.Assert(t, strings.Contains(patch, `{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}`),
		"patch should inject POD_NAME via Downward API")
	assert.Assert(t, strings.Contains(patch, `{"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}}`),
		"patch should inject POD_NAMESPACE via Downward API")
	assert.Assert(t, strings.Contains(patch, `{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}`),
		"patch should inject POD_UID via Downward API")

	// Sidecar args carry the node.metadata "--config-yaml" overlay so the Pod
	// identity is merged onto node.metadata at startup (kubelet expands the
	// $(POD_*) references from the Downward API env vars).
	assert.Assert(t, strings.Contains(patch, `"--config-yaml"`),
		"patch should pass the node.metadata overlay via --config-yaml")
	assert.Assert(t, strings.Contains(patch, `$(POD_UID)`),
		"overlay should reference the POD_UID env var")

	// Sidecar mounts the ALS socket directory (read-only).
	assert.Assert(t, strings.Contains(patch, `"name": "`+varmorconfig.AuditNetworkProxyVolumeName+`", "mountPath": "`+varmorconfig.AuditNetworkProxySocketDir+`", "readOnly": true`),
		"patch should mount the ALS socket directory into the sidecar")

	// PodSpec gains the ALS socket hostPath volume.
	assert.Assert(t, strings.Contains(patch, `"name": "`+varmorconfig.AuditNetworkProxyVolumeName+`", "hostPath": {"path": "`+varmorconfig.AuditNetworkProxySocketDir+`", "type": "DirectoryOrCreate"}`),
		"patch should add the ALS socket hostPath volume")
}

// Test_buildNetworkProxyPatch_AuditWithMITM asserts that audit and MITM
// injection are orthogonal: enabling MITM yields the MITM TLS mount/volume
// AND the audit env/mount/volume in the same patch.
func Test_buildNetworkProxyPatch_AuditWithMITM(t *testing.T) {
	proxyConfig := &varmor.NetworkProxyConfig{
		MITM: &varmor.MITMConfig{Domains: []string{"example.com"}},
	}
	patch := buildNetworkProxyPatch("varmor-testns-test", true, proxyConfig)

	// MITM injection intact.
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-tls"`),
		"patch should still contain the MITM TLS volume mount")
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-tls", "secret": {"secretName"`),
		"patch should still contain the MITM TLS volume definition")

	// Audit injection present alongside MITM.
	assert.Assert(t, strings.Contains(patch, `{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}`),
		"patch should inject POD_NAME alongside MITM")
	assert.Assert(t, strings.Contains(patch, `"name": "`+varmorconfig.AuditNetworkProxyVolumeName+`", "hostPath":`),
		"patch should add the ALS socket volume alongside MITM")
}
