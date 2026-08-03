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
	varmorpolicy "github.com/bytedance/vArmor/internal/policy"
)

// Test_buildNetworkProxyPatch_AuditInjected asserts that NetworkProxy
// violations always stream over gRPC ALS: the webhook JSON-Patch
// unconditionally injects the Downward API Pod identity env vars and the
// shared ALS socket hostPath volume/mount.
func Test_buildNetworkProxyPatch_AuditInjected(t *testing.T) {
	patch := buildNetworkProxyPatch("varmor-testns-test", varmorpolicy.AuditPolicyIdentity{Kind: "VarmorPolicy", Name: "test", Namespace: "testns"}, true, nil, false)

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

	// Sidecar mounts the ALS socket directory read-only on runc (Envoy only
	// connects to the node agent's socket as a gRPC client). a micro-VM omits it.
	assert.Assert(t, strings.Contains(patch, `"name": "`+varmorconfig.AuditNetworkProxyVolumeName+`", "mountPath": "`+varmorconfig.AuditNetworkProxySocketDir+`", "readOnly": true`),
		"patch should mount the ALS socket directory into the sidecar")

	// Sidecar carries the micro-VM audit sink env vars.
	assert.Assert(t, strings.Contains(patch, `{"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}`),
		"patch should inject NODE_NAME via Downward API")
	assert.Assert(t, strings.Contains(patch, `{"name": "PROFILE_NAME", "value": "varmor-testns-test"}`),
		"patch should inject PROFILE_NAME")
	assert.Assert(t, strings.Contains(patch, `{"name": "POLICY_KIND", "value": "VarmorPolicy"}`),
		"patch should inject POLICY_KIND")
	assert.Assert(t, strings.Contains(patch, `{"name": "POLICY_NAME", "value": "test"}`),
		"patch should inject POLICY_NAME")
	assert.Assert(t, strings.Contains(patch, `{"name": "POLICY_NAMESPACE", "value": "testns"}`),
		"patch should inject POLICY_NAMESPACE")
	// VARMOR_NAMESPACE must carry the vArmor component namespace (varmorconfig.
	// Namespace), NOT the workload namespace. Inside the sidecar POD_NAMESPACE
	// is the business Pod's namespace, so the sink relies on this explicit env
	// to populate varmorNamespace correctly.
	assert.Assert(t, strings.Contains(patch, `{"name": "VARMOR_NAMESPACE", "value": "`+varmorconfig.Namespace+`"}`),
		"patch should inject VARMOR_NAMESPACE with the vArmor component namespace")
	assert.Assert(t, strings.Contains(patch, `{"name": "VARMOR_ENVOY_UID", "value": "1337"}`),
		"patch should inject VARMOR_ENVOY_UID")

	// Sidecar starts as root so the entrypoint can bind the micro-VM sink before
	// dropping to the Envoy uid.
	assert.Assert(t, strings.Contains(patch, `"securityContext": {"runAsUser": 0}`),
		"patch should start the sidecar as root (runAsUser 0)")

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
	patch := buildNetworkProxyPatch("varmor-testns-test", varmorpolicy.AuditPolicyIdentity{Kind: "VarmorPolicy", Name: "test", Namespace: "testns"}, true, proxyConfig, false)

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

// Test_buildNetworkProxyPatch_MicroVM asserts that on a micro-VM the ALS
// hostPath volume and the sidecar ALS volumeMount are both omitted (the hostPath
// cannot cross the VM boundary; the in-sidecar audit sink binds the socket in the
// container's own rootfs), while the Downward API / sink env vars and the
// root-start securityContext are still injected.
func Test_buildNetworkProxyPatch_MicroVM(t *testing.T) {
	patch := buildNetworkProxyPatch("varmor-testns-test", varmorpolicy.AuditPolicyIdentity{Kind: "VarmorPolicy", Name: "test", Namespace: "testns"}, true, nil, true)

	// No ALS socket hostPath volume on a micro-VM.
	assert.Assert(t, !strings.Contains(patch, `"hostPath": {"path": "`+varmorconfig.AuditNetworkProxySocketDir+`"`),
		"micro-VM patch must not add the ALS socket hostPath volume")
	// No ALS socket volumeMount on a micro-VM.
	assert.Assert(t, !strings.Contains(patch, `"mountPath": "`+varmorconfig.AuditNetworkProxySocketDir+`"`),
		"micro-VM patch must not mount the ALS socket directory into the sidecar")

	// Env vars and root-start securityContext are still injected.
	assert.Assert(t, strings.Contains(patch, `{"name": "PROFILE_NAME", "value": "varmor-testns-test"}`),
		"micro-VM patch should still inject PROFILE_NAME")
	assert.Assert(t, strings.Contains(patch, `{"name": "VARMOR_NAMESPACE", "value": "`+varmorconfig.Namespace+`"}`),
		"micro-VM patch should still inject VARMOR_NAMESPACE with the vArmor component namespace")
	assert.Assert(t, strings.Contains(patch, `{"name": "VARMOR_ENVOY_UID", "value": "1337"}`),
		"micro-VM patch should still inject VARMOR_ENVOY_UID")
	assert.Assert(t, strings.Contains(patch, `"securityContext": {"runAsUser": 0}`),
		"micro-VM patch should still start the sidecar as root")
}

// Test_buildNetworkProxyPatch_GlobalDefaultResources asserts that cluster-global
// sidecar resource defaults from the varmor-config ConfigMap flow through the
// injection chain into the sidecar container's "resources" field, and that the
// merge is field-level: a global value overrides its field while unset fields
// keep the built-in defaults.
func Test_buildNetworkProxyPatch_GlobalDefaultResources(t *testing.T) {
	restore := varmorconfig.SetDynamicConfigForTest(varmorconfig.DynamicConfig{
		NetworkProxy: varmorconfig.NetworkProxyDynamicConfig{
			DefaultResources: varmorconfig.ProxyDefaultResources{
				NonMITM: varmorconfig.ProxyResourceTier{
					Requests: map[string]string{"cpu": "70m"},      // memory falls back to built-in 64Mi
					Limits:   map[string]string{"memory": "300Mi"}, // cpu falls back to built-in 500m
				},
			},
		},
	})
	defer restore()

	patch := buildNetworkProxyPatch("varmor-testns-test", varmorpolicy.AuditPolicyIdentity{Kind: "VarmorPolicy", Name: "test", Namespace: "testns"}, true, nil, false)

	// Global-configured fields land in the sidecar resources.
	assert.Assert(t, strings.Contains(patch, `"cpu":"70m"`),
		"sidecar resources should carry the global requests.cpu override")
	assert.Assert(t, strings.Contains(patch, `"memory":"300Mi"`),
		"sidecar resources should carry the global limits.memory override")
	// Unset fields keep the built-in non-MITM defaults.
	assert.Assert(t, strings.Contains(patch, `"memory":"64Mi"`),
		"sidecar resources should keep the built-in requests.memory default")
	assert.Assert(t, strings.Contains(patch, `"cpu":"500m"`),
		"sidecar resources should keep the built-in limits.cpu default")
}

// Test_buildNetworkProxyPatch_GlobalMITMTier asserts that the MITM tier of the
// global config is selected for MITM policies.
func Test_buildNetworkProxyPatch_GlobalMITMTier(t *testing.T) {
	restore := varmorconfig.SetDynamicConfigForTest(varmorconfig.DynamicConfig{
		NetworkProxy: varmorconfig.NetworkProxyDynamicConfig{
			DefaultResources: varmorconfig.ProxyDefaultResources{
				MITM: varmorconfig.ProxyResourceTier{
					Limits: map[string]string{"cpu": "1500m"},
				},
			},
		},
	})
	defer restore()

	proxyConfig := &varmor.NetworkProxyConfig{
		MITM: &varmor.MITMConfig{Domains: []string{"example.com"}},
	}
	patch := buildNetworkProxyPatch("varmor-testns-test", varmorpolicy.AuditPolicyIdentity{Kind: "VarmorPolicy", Name: "test", Namespace: "testns"}, true, proxyConfig, false)

	// The MITM-tier global override lands; other fields keep MITM built-in defaults.
	assert.Assert(t, strings.Contains(patch, `"cpu":"1500m"`),
		"MITM sidecar resources should carry the global mitm.limits.cpu override")
	assert.Assert(t, strings.Contains(patch, `"memory":"512Mi"`),
		"MITM sidecar resources should keep the built-in mitm limits.memory default")
}
