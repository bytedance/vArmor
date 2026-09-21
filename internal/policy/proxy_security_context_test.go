// Copyright 2021-2023 vArmor Authors
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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

func proxySecurityCases() []struct {
	name string
	pod  *corev1.PodSecurityContext
	app  *corev1.SecurityContext
} {
	return []struct {
		name string
		pod  *corev1.PodSecurityContext
		app  *corev1.SecurityContext
	}{
		{"container_uid", nil, &corev1.SecurityContext{RunAsUser: ptr.To(int64(1000))}},
		{"pod_uid", &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(1000)), RunAsGroup: ptr.To(int64(1000)), FSGroup: ptr.To(int64(1000))}, nil},
		{"pod_nonroot", &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true)}, &corev1.SecurityContext{RunAsUser: ptr.To(int64(1000))}},
		{"pod_uid_nonroot", &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(1000)), RunAsNonRoot: ptr.To(true)}, nil},
		{"container_uid_nonroot", nil, &corev1.SecurityContext{RunAsUser: ptr.To(int64(1000)), RunAsNonRoot: ptr.To(true), ReadOnlyRootFilesystem: ptr.To(true)}},
	}
}

func assertProxySecurity(t *testing.T, before, after *corev1.PodSpec, uid int64, mitm bool) {
	t.Helper()
	require.Equal(t, before.SecurityContext, after.SecurityContext, "business Pod security context changed")
	require.Len(t, after.Containers, 2)
	require.Len(t, after.InitContainers, 2)
	require.Equal(t, before.Containers[0].SecurityContext, after.Containers[0].SecurityContext)
	require.Equal(t, before.InitContainers[0], after.InitContainers[0], "business init container changed")
	init := after.InitContainers[1]
	proxy := after.Containers[1]
	require.Equal(t, "varmor-network-proxy-init", init.Name)
	require.Equal(t, "varmor-network-proxy", proxy.Name)
	for _, c := range []corev1.Container{init, proxy} {
		require.NotNil(t, c.SecurityContext, c.Name)
		require.Equal(t, ptr.To(int64(0)), c.SecurityContext.RunAsUser, c.Name)
		require.Equal(t, ptr.To(false), c.SecurityContext.RunAsNonRoot, c.Name)
		require.Nil(t, c.SecurityContext.Privileged)
		require.Nil(t, c.SecurityContext.RunAsGroup)
		require.Nil(t, c.SecurityContext.SeccompProfile)
	}
	require.Equal(t, &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}, init.SecurityContext.Capabilities)
	require.Nil(t, proxy.SecurityContext.Capabilities)
	require.Len(t, init.Command, 3)
	require.Contains(t, init.Command[2], fmt.Sprintf("ENVOY_UID=%d\n", uid))
	require.Contains(t, init.Command[2], "--uid-owner ${ENVOY_UID} -j RETURN")
	env := make(map[string]corev1.EnvVar)
	for _, e := range proxy.Env {
		env[e.Name] = e
	}
	require.Equal(t, fmt.Sprint(uid), env["VARMOR_ENVOY_UID"].Value)
	require.NotNil(t, env["POD_UID"].ValueFrom)
	require.True(t, init.Resources.Requests.Cpu().Equal(resource.MustParse("10m")))
	require.True(t, proxy.Resources.Requests.Cpu().Equal(resource.MustParse("75m")))
	require.False(t, proxy.Resources.Limits.Memory().IsZero())
	mounts := make(map[string]corev1.VolumeMount)
	for _, m := range proxy.VolumeMounts {
		mounts[m.Name] = m
	}
	require.Contains(t, mounts, "varmor-network-proxy-config")
	require.Contains(t, mounts, varmorconfig.AuditNetworkProxyVolumeName)
	require.True(t, mounts[varmorconfig.AuditNetworkProxyVolumeName].ReadOnly)
	_, tls := mounts["varmor-network-proxy-mitm-tls"]
	require.Equal(t, mitm, tls)
	volumes := make(map[string]corev1.Volume)
	for _, v := range after.Volumes {
		require.NotContains(t, volumes, v.Name)
		volumes[v.Name] = v
	}
	require.Contains(t, volumes, varmorconfig.AuditNetworkProxyVolumeName)
	if mitm {
		require.Contains(t, volumes, "varmor-network-proxy-mitm-tls")
		require.Contains(t, volumes, "varmor-network-proxy-mitm-ca-bundle")
	}
}

func TestNetworkProxyPodSecurityContext(t *testing.T) {
	for _, tc := range proxySecurityCases() {
		for _, uid := range []int64{1337, 2337} {
			for _, mitm := range []bool{false, true} {
				for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
					t.Run(fmt.Sprintf("%s/%s/uid_%d/mitm_%t", kind, tc.name, uid, mitm), func(t *testing.T) {
						spec := corev1.PodSpec{
							SecurityContext: tc.pod.DeepCopy(),
							Containers:      []corev1.Container{{Name: "app", Image: "app:test", SecurityContext: tc.app.DeepCopy()}},
							InitContainers:  []corev1.Container{{Name: "app-init", Image: "app:test", SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(int64(1000)), RunAsNonRoot: ptr.To(true)}}},
						}
						config := &varmor.NetworkProxyConfig{Resources: &varmor.ProxyResourceOverride{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("75m")}}}
						if uid != 1337 {
							config.ProxyUID = ptr.To(uid)
						}
						if mitm {
							config.MITM = &varmor.MITMConfig{Domains: []string{"example.test"}}
						}
						original := spec.DeepCopy()
						target := varmor.Target{Kind: kind}
						template := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"example.test/business": "keep"}}, Spec: spec}
						var obj interface{}
						switch kind {
						case "Pod":
							obj = &corev1.Pod{ObjectMeta: template.ObjectMeta, Spec: spec}
						case "Deployment":
							obj = &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: template}}
						case "StatefulSet":
							obj = &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{Template: template}}
						case "DaemonSet":
							obj = &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: template}}
						}

						id := AuditPolicyIdentity{Kind: "VarmorPolicy", Name: "test", Namespace: "default"}
						for pass := 0; pass < 3; pass++ {
							switch o := obj.(type) {
							case *appsv1.Deployment:
								modifyDeploymentAnnotationsAndEnv("NetworkProxy", varmor.EnhanceProtectMode, target, config, o, "varmor-default-test", id, false)
							case *appsv1.StatefulSet:
								modifyStatefulSetAnnotationsAndEnv("NetworkProxy", varmor.EnhanceProtectMode, target, config, o, "varmor-default-test", id, false)
							case *appsv1.DaemonSet:
								modifyDaemonSetAnnotationsAndEnv("NetworkProxy", varmor.EnhanceProtectMode, target, config, o, "varmor-default-test", id, false)
							}
							// Serialization verifies explicit zero/false fields and isolates the
							// API object from the controller's container templates.
							raw, err := json.Marshal(obj)
							require.NoError(t, err)
							switch kind {
							case "Deployment":
								obj = &appsv1.Deployment{}
							case "StatefulSet":
								obj = &appsv1.StatefulSet{}
							case "DaemonSet":
								obj = &appsv1.DaemonSet{}
							}
							require.NoError(t, json.Unmarshal(raw, obj))
							result := securityPodSpec(obj)
							assertProxySecurity(t, original, result, uid, mitm)
							if pass == 0 {
								// Simulate a stored template produced by the old injector. The next
								// controller reconciliation must replace it, without duplicates.
								result.InitContainers[1].SecurityContext.RunAsUser = nil
								result.InitContainers[1].SecurityContext.RunAsNonRoot = nil
								result.Containers[1].SecurityContext.RunAsNonRoot = nil
							}
						}

					})
				}
			}
		}
	}
}

func securityPodSpec(obj interface{}) *corev1.PodSpec {
	switch o := obj.(type) {
	case *corev1.Pod:
		return &o.Spec
	case *appsv1.Deployment:
		return &o.Spec.Template.Spec
	case *appsv1.StatefulSet:
		return &o.Spec.Template.Spec
	case *appsv1.DaemonSet:
		return &o.Spec.Template.Spec
	default:
		panic("unexpected workload")
	}
}
