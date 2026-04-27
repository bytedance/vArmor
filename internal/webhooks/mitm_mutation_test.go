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
	corev1 "k8s.io/api/core/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

func Test_buildNetworkProxyPatch_MITMEnabled(t *testing.T) {
	profileName := "varmor-testns-test"
	mitmConfig := &varmor.NetworkProxyConfig{
		MITM: &varmor.MITMConfig{
			Domains: []string{"example.com", "*.api.internal"},
		},
	}

	patch := buildNetworkProxyPatch(profileName, true, mitmConfig)

	// Should contain the sidecar MITM TLS volumeMount
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-tls"`),
		"patch should contain MITM TLS volume mount for sidecar")

	// Should contain both MITM volumes
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-tls", "configMap"`),
		"patch should contain MITM TLS volume definition")
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-ca-bundle", "configMap"`),
		"patch should contain MITM CA bundle volume definition")

	// Should reference ConfigMap key mappings
	assert.Assert(t, strings.Contains(patch, `"key": "mitm-leaf.crt", "path": "leaf.crt"`),
		"patch should project mitm-leaf.crt as leaf.crt")
	assert.Assert(t, strings.Contains(patch, `"key": "mitm-leaf.key", "path": "leaf.key"`),
		"patch should project mitm-leaf.key as leaf.key")
	assert.Assert(t, strings.Contains(patch, `"key": "mitm-ca-bundle.crt", "path": "ca-bundle.crt"`),
		"patch should project mitm-ca-bundle.crt as ca-bundle.crt")
	assert.Assert(t, strings.Contains(patch, `"key": "mitm-ca-bundle.crt", "path": "ca-certificates.crt"`),
		"patch should project mitm-ca-bundle.crt as ca-certificates.crt for targets")

	// Should reference the profileName in ConfigMap
	assert.Assert(t, strings.Contains(patch, `"name": "`+profileName+`"`),
		"patch should reference profileName in ConfigMap volumes")
}

func Test_buildNetworkProxyPatch_MITMDisabled(t *testing.T) {
	profileName := "varmor-testns-test"

	testCases := []struct {
		name        string
		proxyConfig *varmor.NetworkProxyConfig
	}{
		{
			name:        "nilConfig",
			proxyConfig: nil,
		},
		{
			name:        "nilMITM",
			proxyConfig: &varmor.NetworkProxyConfig{},
		},
		{
			name: "emptyDomains",
			proxyConfig: &varmor.NetworkProxyConfig{
				MITM: &varmor.MITMConfig{
					Domains: []string{},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			patch := buildNetworkProxyPatch(profileName, true, tc.proxyConfig)

			// Should NOT contain MITM volumes
			assert.Assert(t, !strings.Contains(patch, "varmor-network-proxy-mitm-tls"),
				"patch should NOT contain MITM TLS volume when MITM is disabled")
			assert.Assert(t, !strings.Contains(patch, "varmor-network-proxy-mitm-ca-bundle"),
				"patch should NOT contain MITM CA bundle volume when MITM is disabled")

			// Should still contain the base proxy volume
			assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-config"`),
				"patch should still contain the base proxy config volume")
		})
	}
}

func Test_buildNetworkProxyMITMTargetPatch_Workloads(t *testing.T) {
	container := corev1.Container{
		Name:  "app",
		Image: "nginx:latest",
	}

	patch := buildNetworkProxyMITMTargetPatch(true, container, 0)

	// Should create empty volumeMounts array first (container has none)
	assert.Assert(t, strings.Contains(patch, `"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts", "value": []`),
		"should create empty volumeMounts array for container with no mounts")

	// Should append CA bundle volumeMount
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-ca-bundle"`),
		"should append CA bundle volumeMount")
	assert.Assert(t, strings.Contains(patch, `"mountPath": "`+varmorconfig.MITMCABundleMountDir+`"`),
		"should mount at MITMCABundleMountDir")

	// Should create empty env array first
	assert.Assert(t, strings.Contains(patch, `"op": "add", "path": "/spec/template/spec/containers/0/env", "value": []`),
		"should create empty env array for container with no env")

	// Should inject all 4 TLS env vars
	for _, envName := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		assert.Assert(t, strings.Contains(patch, `"name": "`+envName+`"`),
			"should inject env var "+envName)
		assert.Assert(t, strings.Contains(patch, `"value": "`+varmorconfig.MITMCABundlePath+`"`),
			"env var "+envName+" should point to MITMCABundlePath")
	}
}

func Test_buildNetworkProxyMITMTargetPatch_ExistingMountsAndEnv(t *testing.T) {
	container := corev1.Container{
		Name:  "app",
		Image: "nginx:latest",
		VolumeMounts: []corev1.VolumeMount{
			{Name: "existing-vol", MountPath: "/data"},
		},
		Env: []corev1.EnvVar{
			{Name: "MY_VAR", Value: "hello"},
		},
	}

	patch := buildNetworkProxyMITMTargetPatch(true, container, 1)

	// Should NOT create empty arrays (already exist)
	assert.Assert(t, !strings.Contains(patch, `"path": "/spec/template/spec/containers/1/volumeMounts", "value": []`),
		"should NOT create empty volumeMounts array when mounts exist")
	assert.Assert(t, !strings.Contains(patch, `"path": "/spec/template/spec/containers/1/env", "value": []`),
		"should NOT create empty env array when env exists")

	// Should still append mount and envs
	assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy-mitm-ca-bundle"`),
		"should still append CA bundle volumeMount")
	assert.Assert(t, strings.Contains(patch, `"name": "SSL_CERT_FILE"`),
		"should still inject SSL_CERT_FILE")
}

func Test_buildNetworkProxyMITMTargetPatch_Pod(t *testing.T) {
	container := corev1.Container{
		Name:  "app",
		Image: "nginx:latest",
	}

	patch := buildNetworkProxyMITMTargetPatch(false, container, 0)

	// Pod path should NOT have /spec/template prefix
	assert.Assert(t, strings.Contains(patch, `"/spec/containers/0/volumeMounts"`),
		"Pod path should use /spec/containers, not /spec/template/spec/containers")
	assert.Assert(t, !strings.Contains(patch, `/spec/template/`),
		"Pod path should not contain /spec/template/")
}
