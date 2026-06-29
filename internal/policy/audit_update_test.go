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

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// ---- isAuditALSEnabled tests ----

func Test_isAuditALSEnabled(t *testing.T) {
	original := varmorconfig.AuditNetworkProxySink
	defer func() { varmorconfig.AuditNetworkProxySink = original }()

	testCases := []struct {
		name     string
		sink     string
		expected bool
	}{
		{"stdout default", profile.AuditSinkStdout, false},
		{"grpc_als", profile.AuditSinkGRPCALS, true},
		{"unknown value", "something-else", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			varmorconfig.AuditNetworkProxySink = tc.sink
			assert.Equal(t, isAuditALSEnabled(), tc.expected)
		})
	}
}

// ---- applyAuditToSidecar tests ----

func Test_applyAuditToSidecar(t *testing.T) {
	containers := []coreV1.Container{
		{Name: "app"},
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
			},
		},
	}

	applyAuditToSidecar(containers)

	// Sidecar gains the ALS socket volumeMount.
	assert.Equal(t, len(containers[1].VolumeMounts), 2)
	assert.Equal(t, containers[1].VolumeMounts[1].Name, varmorconfig.AuditNetworkProxyVolumeName)
	assert.Equal(t, containers[1].VolumeMounts[1].MountPath, varmorconfig.AuditNetworkProxySocketDir)
	assert.Assert(t, containers[1].VolumeMounts[1].ReadOnly)

	// Sidecar gains the two Downward API env vars.
	assert.Equal(t, len(containers[1].Env), 2)
	assert.Equal(t, containers[1].Env[0].Name, "POD_NAME")
	assert.Assert(t, containers[1].Env[0].ValueFrom != nil)
	assert.Assert(t, containers[1].Env[0].ValueFrom.FieldRef != nil)
	assert.Equal(t, containers[1].Env[0].ValueFrom.FieldRef.FieldPath, "metadata.name")
	assert.Equal(t, containers[1].Env[1].Name, "POD_NAMESPACE")
	assert.Assert(t, containers[1].Env[1].ValueFrom != nil)
	assert.Assert(t, containers[1].Env[1].ValueFrom.FieldRef != nil)
	assert.Equal(t, containers[1].Env[1].ValueFrom.FieldRef.FieldPath, "metadata.namespace")

	// App container must be untouched.
	assert.Equal(t, len(containers[0].VolumeMounts), 0)
	assert.Equal(t, len(containers[0].Env), 0)
}

// ---- applyAuditVolumes tests ----

func Test_applyAuditVolumes(t *testing.T) {
	volumes := []coreV1.Volume{
		{Name: "existing-vol"},
	}

	applyAuditVolumes(&volumes)

	assert.Equal(t, len(volumes), 2)
	assert.Equal(t, volumes[1].Name, varmorconfig.AuditNetworkProxyVolumeName)
	assert.Assert(t, volumes[1].HostPath != nil)
	assert.Equal(t, volumes[1].HostPath.Path, varmorconfig.AuditNetworkProxySocketDir)
	assert.Assert(t, volumes[1].HostPath.Type != nil)
	assert.Equal(t, *volumes[1].HostPath.Type, coreV1.HostPathDirectoryOrCreate)
}

func Test_applyAuditVolumes_DeepCopyIndependence(t *testing.T) {
	volumes1 := []coreV1.Volume{}
	volumes2 := []coreV1.Volume{}

	applyAuditVolumes(&volumes1)
	applyAuditVolumes(&volumes2)

	// Each call must append an independent volume value (no shared pointer
	// aliasing through the package-level template variable).
	assert.Assert(t, volumes1[0].HostPath != volumes2[0].HostPath)
	assert.Assert(t, volumes1[0].HostPath.Type != volumes2[0].HostPath.Type)
}

// ---- cleanupAuditFromSidecar tests ----

func Test_cleanupAuditFromSidecar(t *testing.T) {
	containers := []coreV1.Container{
		{Name: "app"},
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
				{Name: varmorconfig.AuditNetworkProxyVolumeName},
			},
			Env: []coreV1.EnvVar{
				{Name: "SOME_ENV", Value: "keep"},
				{Name: "POD_NAME"},
				{Name: "POD_NAMESPACE"},
			},
		},
	}

	cleanupAuditFromSidecar(containers)

	// Only the config mount survives.
	assert.Equal(t, len(containers[1].VolumeMounts), 1)
	assert.Equal(t, containers[1].VolumeMounts[0].Name, "varmor-network-proxy-config")

	// Only the non-audit env survives.
	assert.Equal(t, len(containers[1].Env), 1)
	assert.Equal(t, containers[1].Env[0].Name, "SOME_ENV")
}

func Test_cleanupAuditFromSidecar_Idempotent(t *testing.T) {
	containers := []coreV1.Container{
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
			},
		},
	}

	// Cleaning a sidecar without audit objects must be a no-op.
	cleanupAuditFromSidecar(containers)
	assert.Equal(t, len(containers[0].VolumeMounts), 1)
	assert.Equal(t, len(containers[0].Env), 0)
}

// ---- cleanupAuditVolumes tests ----

func Test_cleanupAuditVolumes(t *testing.T) {
	volumes := []coreV1.Volume{
		{Name: "app-data"},
		{Name: "varmor-network-proxy-config"},
		{Name: varmorconfig.AuditNetworkProxyVolumeName},
		{Name: "other-vol"},
	}

	cleanupAuditVolumes(&volumes)

	assert.Equal(t, len(volumes), 3)
	for _, v := range volumes {
		assert.Assert(t, v.Name != varmorconfig.AuditNetworkProxyVolumeName)
	}
}

// ---- apply then cleanup round-trip ----

func Test_applyThenCleanupAudit_RoundTrip(t *testing.T) {
	containers := []coreV1.Container{
		{
			Name: proxyContainer.Name,
			VolumeMounts: []coreV1.VolumeMount{
				{Name: "varmor-network-proxy-config"},
			},
		},
	}
	volumes := []coreV1.Volume{
		{Name: "varmor-network-proxy-config"},
	}

	applyAuditToSidecar(containers)
	applyAuditVolumes(&volumes)
	cleanupAuditFromSidecar(containers)
	cleanupAuditVolumes(&volumes)

	// Back to the pre-audit shape.
	assert.Equal(t, len(containers[0].VolumeMounts), 1)
	assert.Equal(t, len(containers[0].Env), 0)
	assert.Equal(t, len(volumes), 1)
	assert.Equal(t, volumes[0].Name, "varmor-network-proxy-config")
}
