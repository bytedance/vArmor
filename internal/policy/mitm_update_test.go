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

package policy

import (
	"testing"

	"gotest.tools/assert"
	coreV1 "k8s.io/api/core/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

// ---- isMITMEnabled tests ----

func Test_isMITMEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		config   *varmor.NetworkProxyConfig
		expected bool
	}{
		{"nil config", nil, false},
		{"nil MITM", &varmor.NetworkProxyConfig{}, false},
		{"empty domains", &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: []string{}}}, false},
		{"with domains", &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: []string{"example.com"}}}, true},
		{"multiple domains", &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{Domains: []string{"a.com", "*.b.com"}}}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, isMITMEnabled(tc.config), tc.expected)
		})
	}
}

// ---- cleanupMITMVolumes tests ----

func Test_cleanupMITMVolumes(t *testing.T) {
	volumes := []coreV1.Volume{
		{Name: "app-data"},
		{Name: "varmor-network-proxy-config"},
		{Name: "varmor-network-proxy-mitm-tls"},
		{Name: "varmor-network-proxy-mitm-ca-bundle"},
		{Name: "other-vol"},
	}

	cleanupMITMVolumes(&volumes)

	assert.Equal(t, len(volumes), 3)
	assert.Equal(t, volumes[0].Name, "app-data")
	assert.Equal(t, volumes[1].Name, "varmor-network-proxy-config")
	assert.Equal(t, volumes[2].Name, "other-vol")
}

func Test_cleanupMITMVolumes_NoMITMVolumes(t *testing.T) {
	volumes := []coreV1.Volume{
		{Name: "app-data"},
		{Name: "varmor-network-proxy-config"},
	}

	cleanupMITMVolumes(&volumes)

	assert.Equal(t, len(volumes), 2)
}

func Test_cleanupMITMVolumes_Empty(t *testing.T) {
	volumes := []coreV1.Volume{}
	cleanupMITMVolumes(&volumes)
	assert.Equal(t, len(volumes), 0)
}

// ---- cleanupMITMFromSidecar tests ----

func Test_cleanupMITMFromSidecar(t *testing.T) {
	containers := []coreV1.Container{
		{
			Name: "app",
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "app-data"},
			},
		},
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
				{Name: "varmor-network-proxy-mitm-tls"},
			},
		},
	}

	cleanupMITMFromSidecar(containers)

	// Sidecar should only have config mount left
	assert.Equal(t, len(containers[1].VolumeMounts), 1)
	assert.Equal(t, containers[1].VolumeMounts[0].Name, "varmor-network-proxy-config")

	// App container should be untouched
	assert.Equal(t, len(containers[0].VolumeMounts), 1)
}

func Test_cleanupMITMFromSidecar_NoMITMMount(t *testing.T) {
	containers := []coreV1.Container{
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
			},
		},
	}

	cleanupMITMFromSidecar(containers)
	assert.Equal(t, len(containers[0].VolumeMounts), 1)
}

// ---- cleanupMITMFromTargetContainers tests ----

func Test_cleanupMITMFromTargetContainers(t *testing.T) {
	target := varmor.Target{Kind: "Deployment"}

	containers := []coreV1.Container{
		{
			Name: "app",
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "app-data"},
				{Name: "varmor-network-proxy-mitm-ca-bundle"},
			},
			Env: []coreV1.EnvVar{
				{Name: "MY_VAR", Value: "hello"},
				{Name: "SSL_CERT_FILE", Value: varmorconfig.MITMCABundlePath},
				{Name: "REQUESTS_CA_BUNDLE", Value: varmorconfig.MITMCABundlePath},
				{Name: "NODE_EXTRA_CA_CERTS", Value: varmorconfig.MITMCABundlePath},
				{Name: "CURL_CA_BUNDLE", Value: varmorconfig.MITMCABundlePath},
			},
		},
		{
			Name: proxyContainer.Name, // sidecar, should be skipped
			Env:  []coreV1.EnvVar{{Name: "SOME_VAR", Value: "x"}},
		},
	}

	cleanupMITMFromTargetContainers(containers, target)

	// App container: MITM mount and env vars removed
	assert.Equal(t, len(containers[0].VolumeMounts), 1)
	assert.Equal(t, containers[0].VolumeMounts[0].Name, "app-data")
	assert.Equal(t, len(containers[0].Env), 1)
	assert.Equal(t, containers[0].Env[0].Name, "MY_VAR")

	// Sidecar: untouched
	assert.Equal(t, len(containers[1].Env), 1)
}

func Test_cleanupMITMFromTargetContainers_SpecificTargets(t *testing.T) {
	target := varmor.Target{
		Kind:       "Deployment",
		Containers: []string{"app1"},
	}

	containers := []coreV1.Container{
		{
			Name: "app1",
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-mitm-ca-bundle"},
			},
			Env: []coreV1.EnvVar{
				{Name: "SSL_CERT_FILE", Value: varmorconfig.MITMCABundlePath},
			},
		},
		{
			Name: "app2", // not targeted
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-mitm-ca-bundle"},
			},
			Env: []coreV1.EnvVar{
				{Name: "SSL_CERT_FILE", Value: varmorconfig.MITMCABundlePath},
			},
		},
	}

	cleanupMITMFromTargetContainers(containers, target)

	// app1: cleaned
	assert.Equal(t, len(containers[0].VolumeMounts), 0)
	assert.Equal(t, len(containers[0].Env), 0)

	// app2: not targeted, should be untouched
	assert.Equal(t, len(containers[1].VolumeMounts), 1)
	assert.Equal(t, len(containers[1].Env), 1)
}

// ---- applyMITMToSidecar tests ----

func Test_applyMITMToSidecar(t *testing.T) {
	containers := []coreV1.Container{
		{Name: "app"},
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
			},
		},
	}

	applyMITMToSidecar(containers)

	assert.Equal(t, len(containers[1].VolumeMounts), 2)
	assert.Equal(t, containers[1].VolumeMounts[1].Name, "varmor-network-proxy-mitm-tls")
	assert.Equal(t, containers[1].VolumeMounts[1].MountPath, "/etc/envoy/tls")
	assert.Assert(t, containers[1].VolumeMounts[1].ReadOnly)

	// App should be untouched
	assert.Equal(t, len(containers[0].VolumeMounts), 0)
}

// ---- applyMITMVolumes tests ----

func Test_applyMITMVolumes(t *testing.T) {
	profileName := "varmor-testns-test"
	volumes := []coreV1.Volume{
		{Name: "existing-vol"},
	}

	applyMITMVolumes(&volumes, profileName)

	assert.Equal(t, len(volumes), 3)
	assert.Equal(t, volumes[1].Name, "varmor-network-proxy-mitm-tls")
	assert.Equal(t, volumes[1].Secret.SecretName, profileName)
	assert.Equal(t, len(volumes[1].Secret.Items), 3)
	assert.Equal(t, volumes[2].Name, "varmor-network-proxy-mitm-ca-bundle")
	assert.Equal(t, volumes[2].Secret.SecretName, profileName)
	assert.Equal(t, len(volumes[2].Secret.Items), 1)
}

func Test_applyMITMVolumes_DeepCopyIndependence(t *testing.T) {
	volumes1 := []coreV1.Volume{}
	volumes2 := []coreV1.Volume{}

	applyMITMVolumes(&volumes1, "profile-a")
	applyMITMVolumes(&volumes2, "profile-b")

	// Each call should produce independent Secret names
	assert.Equal(t, volumes1[0].Secret.SecretName, "profile-a")
	assert.Equal(t, volumes2[0].Secret.SecretName, "profile-b")
}

// ---- applyMITMToTargetContainers tests ----

func Test_applyMITMToTargetContainers_AllContainers(t *testing.T) {
	target := varmor.Target{Kind: "Deployment"}

	containers := []coreV1.Container{
		{Name: "app1", Image: "nginx"},
		{Name: "app2", Image: "redis"},
		{Name: proxyContainer.Name, Image: "envoy"}, // sidecar, should be skipped
	}

	result := applyMITMToTargetContainers(containers, target)

	// app1 and app2 should have CA bundle mount + 4 env vars
	for _, i := range []int{0, 1} {
		assert.Equal(t, len(result[i].VolumeMounts), 1)
		assert.Equal(t, result[i].VolumeMounts[0].Name, "varmor-network-proxy-mitm-ca-bundle")
		assert.Equal(t, result[i].VolumeMounts[0].MountPath, varmorconfig.MITMCABundleMountDir)
		assert.Equal(t, len(result[i].Env), 4)
		assert.Equal(t, result[i].Env[0].Name, "SSL_CERT_FILE")
		assert.Equal(t, result[i].Env[1].Name, "REQUESTS_CA_BUNDLE")
		assert.Equal(t, result[i].Env[2].Name, "NODE_EXTRA_CA_CERTS")
		assert.Equal(t, result[i].Env[3].Name, "CURL_CA_BUNDLE")
		for _, ev := range result[i].Env {
			assert.Equal(t, ev.Value, varmorconfig.MITMCABundlePath)
		}
	}

	// sidecar should be untouched
	assert.Equal(t, len(result[2].VolumeMounts), 0)
	assert.Equal(t, len(result[2].Env), 0)
}

func Test_applyMITMToTargetContainers_SpecificContainers(t *testing.T) {
	target := varmor.Target{
		Kind:       "Deployment",
		Containers: []string{"app1"},
	}

	containers := []coreV1.Container{
		{Name: "app1", Image: "nginx"},
		{Name: "app2", Image: "redis"},
	}

	result := applyMITMToTargetContainers(containers, target)

	// app1 should have MITM injected
	assert.Equal(t, len(result[0].VolumeMounts), 1)
	assert.Equal(t, len(result[0].Env), 4)

	// app2 should be untouched
	assert.Equal(t, len(result[1].VolumeMounts), 0)
	assert.Equal(t, len(result[1].Env), 0)
}

// ---- Round-trip cleanup + apply test ----

func Test_MITM_RoundTrip_CleanupThenApply(t *testing.T) {
	profileName := "varmor-testns-test"
	target := varmor.Target{Kind: "Deployment"}

	// Simulate a pod that already has MITM injected
	volumes := []coreV1.Volume{
		{Name: "app-data"},
		{Name: "varmor-network-proxy-config"},
		{Name: "varmor-network-proxy-mitm-tls", VolumeSource: coreV1.VolumeSource{
			Secret: &coreV1.SecretVolumeSource{
				SecretName: "old-profile",
			},
		}},
		{Name: "varmor-network-proxy-mitm-ca-bundle", VolumeSource: coreV1.VolumeSource{
			Secret: &coreV1.SecretVolumeSource{
				SecretName: "old-profile",
			},
		}},
	}

	containers := []coreV1.Container{
		{
			Name: "app",
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "app-data"},
				{Name: "varmor-network-proxy-mitm-ca-bundle"},
			},
			Env: []coreV1.EnvVar{
				{Name: "MY_VAR", Value: "keep-me"},
				{Name: "SSL_CERT_FILE", Value: "old-path"},
				{Name: "REQUESTS_CA_BUNDLE", Value: "old-path"},
				{Name: "NODE_EXTRA_CA_CERTS", Value: "old-path"},
				{Name: "CURL_CA_BUNDLE", Value: "old-path"},
			},
		},
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
				{Name: "varmor-network-proxy-mitm-tls"},
			},
		},
	}

	// Step 1: Cleanup
	cleanupMITMVolumes(&volumes)
	cleanupMITMFromSidecar(containers)
	cleanupMITMFromTargetContainers(containers, target)

	// Verify cleanup
	assert.Equal(t, len(volumes), 2)                    // app-data + proxy-config
	assert.Equal(t, len(containers[0].VolumeMounts), 1) // app-data only
	assert.Equal(t, len(containers[0].Env), 1)          // MY_VAR only
	assert.Equal(t, len(containers[1].VolumeMounts), 1) // proxy-config only

	// Step 2: Re-apply with new profile
	applyMITMToSidecar(containers)
	applyMITMVolumes(&volumes, profileName)
	containers = applyMITMToTargetContainers(containers, target)

	// Verify apply
	assert.Equal(t, len(volumes), 4) // app-data + proxy-config + 2 MITM
	assert.Equal(t, volumes[2].Secret.SecretName, profileName)
	assert.Equal(t, volumes[3].Secret.SecretName, profileName)

	// Sidecar should have TLS mount
	assert.Equal(t, len(containers[1].VolumeMounts), 2)
	assert.Equal(t, containers[1].VolumeMounts[1].Name, "varmor-network-proxy-mitm-tls")

	// App should have CA bundle mount + 4 env vars (plus original MY_VAR)
	assert.Equal(t, len(containers[0].VolumeMounts), 2)
	assert.Equal(t, containers[0].VolumeMounts[1].Name, "varmor-network-proxy-mitm-ca-bundle")
	assert.Equal(t, len(containers[0].Env), 5) // MY_VAR + 4 TLS env
	assert.Equal(t, containers[0].Env[0].Name, "MY_VAR")
	assert.Equal(t, containers[0].Env[0].Value, "keep-me")
	assert.Equal(t, containers[0].Env[1].Value, varmorconfig.MITMCABundlePath)
}
