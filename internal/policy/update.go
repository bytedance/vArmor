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
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"

	appsV1 "k8s.io/api/apps/v1"
	coreV1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

var (
	scriptTemplate = `set -ex
ENVOY_UID=%d
ENVOY_PORT=%d
ENVOY_ADMIN_PORT=%d
iptables -t nat -N VARMOR_OUTPUT
iptables -t nat -N VARMOR_REDIRECT
iptables -t nat -A OUTPUT -p tcp -j VARMOR_OUTPUT
iptables -t nat -A VARMOR_OUTPUT -m owner --uid-owner ${ENVOY_UID} -j RETURN
iptables -t nat -A VARMOR_OUTPUT -d 127.0.0.0/8 -j RETURN
iptables -t nat -A VARMOR_OUTPUT -p tcp -j VARMOR_REDIRECT
iptables -t nat -A VARMOR_REDIRECT -p tcp -j REDIRECT --to-ports ${ENVOY_PORT}
iptables -t filter -A OUTPUT -p tcp --dport ${ENVOY_ADMIN_PORT} -m owner ! --uid-owner ${ENVOY_UID} -j DROP`

	proxyInitContainer = coreV1.Container{
		Name:  "varmor-network-proxy-init",
		Image: varmorconfig.ProxyInitImage,
		SecurityContext: &coreV1.SecurityContext{
			Capabilities: &coreV1.Capabilities{
				Add: []coreV1.Capability{"NET_ADMIN"},
			},
		},
		Resources: coreV1.ResourceRequirements{
			Requests: coreV1.ResourceList{
				coreV1.ResourceCPU:    resource.MustParse("10m"),
				coreV1.ResourceMemory: resource.MustParse("16Mi"),
			},
		},
		Command: []string{}, // Set Command with script
	}

	proxyContainer = coreV1.Container{
		Name:            "varmor-network-proxy",
		Image:           varmorconfig.ProxyImage,
		SecurityContext: &coreV1.SecurityContext{}, // Set RunAsUser with proxyUID
		Args:            []string{"-c", "/etc/envoy/bootstrap.yaml", "-l", "info"},
		ReadinessProbe: &coreV1.Probe{
			ProbeHandler: coreV1.ProbeHandler{
				HTTPGet: &coreV1.HTTPGetAction{
					Path: "/ready",
					Port: intstr.IntOrString{Type: intstr.Int, IntVal: 0}, // Set IntVal with ProxyAdminPort
				},
			},
			InitialDelaySeconds: 2,
			PeriodSeconds:       5,
		},
		Resources: coreV1.ResourceRequirements{
			Requests: coreV1.ResourceList{
				coreV1.ResourceCPU:    resource.MustParse("50m"),
				coreV1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: coreV1.ResourceList{
				coreV1.ResourceCPU:    resource.MustParse("200m"),
				coreV1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
		VolumeMounts: []coreV1.VolumeMount{
			{
				Name:      "varmor-network-proxy-config",
				MountPath: "/etc/envoy",
				ReadOnly:  true,
			},
		},
	}

	proxyVolume = coreV1.Volume{
		Name: "varmor-network-proxy-config",
		VolumeSource: coreV1.VolumeSource{
			ConfigMap: &coreV1.ConfigMapVolumeSource{}, // Set name with profileName
		},
	}
)

func modifyDeploymentAnnotationsAndEnv(
	enforcer string,
	mode varmor.VarmorPolicyMode,
	target varmor.Target,
	proxyConfig *varmor.NetworkProxyConfig,
	deploy *appsV1.Deployment,
	profileName string,
	bpfExclusiveMode bool) {

	e := varmortypes.GetEnforcerType(enforcer)

	// Clean up first
	for key, value := range deploy.Spec.Template.Annotations {
		// NetworkProxy
		if key == "pod.networkproxy.security.beta.varmor.org" && value != "unconfined" {
			delete(deploy.Spec.Template.Annotations, key)
			// Clean up the proxy init container
			for index, container := range deploy.Spec.Template.Spec.InitContainers {
				if container.Name == proxyInitContainer.Name {
					deploy.Spec.Template.Spec.InitContainers = append(deploy.Spec.Template.Spec.InitContainers[:index], deploy.Spec.Template.Spec.InitContainers[index+1:]...)
					break
				}
			}
			// Clean up the proxy container
			for index, container := range deploy.Spec.Template.Spec.Containers {
				if container.Name == proxyContainer.Name {
					deploy.Spec.Template.Spec.Containers = append(deploy.Spec.Template.Spec.Containers[:index], deploy.Spec.Template.Spec.Containers[index+1:]...)
					break
				}
			}
			// Clean up the proxy volume
			for index, volume := range deploy.Spec.Template.Spec.Volumes {
				if volume.Name == proxyVolume.Name {
					deploy.Spec.Template.Spec.Volumes = append(deploy.Spec.Template.Spec.Volumes[:index], deploy.Spec.Template.Spec.Volumes[index+1:]...)
					break
				}
			}
		}
		// BPF
		if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
			delete(deploy.Spec.Template.Annotations, key)
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if !varmorconfig.AppArmorGA {
				// Below Kubernetes v1.30
				if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
					delete(deploy.Spec.Template.Annotations, key)
				}
			} else {
				// Kubernetes v1.30 and above
				if strings.HasPrefix(key, "container.apparmor.security.beta.varmor.org/") && value != "unconfined" {
					delete(deploy.Spec.Template.Annotations, key)
					parts := strings.Split(key, "/")
					if len(parts) != 2 {
						continue
					}
					// Clean up the apparmor settings from the SecurityContext
					for index, container := range deploy.Spec.Template.Spec.Containers {
						if container.Name == parts[1] && deploy.Spec.Template.Spec.Containers[index].SecurityContext != nil {
							deploy.Spec.Template.Spec.Containers[index].SecurityContext.AppArmorProfile = nil
						}
					}
				}
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
				parts := strings.Split(key, "/")
				if len(parts) != 2 {
					continue
				}
				// Clean up the seccomp settings from the SecurityContext
				for index, container := range deploy.Spec.Template.Spec.Containers {
					if container.Name == parts[1] && deploy.Spec.Template.Spec.Containers[index].SecurityContext != nil {
						deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
					}
				}
			}
		}
	}

	// Add the modification time to annotation
	if deploy.Spec.Template.Annotations == nil {
		deploy.Spec.Template.Annotations = make(map[string]string)
	}

	if profileName == "" {
		return
	}

	// NetworkProxy
	if (e & varmortypes.NetworkProxy) != 0 {
		if value, ok := deploy.Spec.Template.Annotations["pod.networkproxy.security.beta.varmor.org"]; !ok || value != "unconfined" {
			proxyUID := varmorconfig.DefaultProxyUID
			proxyPort := varmorconfig.DefaultProxyPort
			proxyAdminPort := varmorconfig.DefaultProxyAdminPort

			if proxyConfig != nil {
				if proxyConfig.ProxyUID != nil {
					proxyUID = *proxyConfig.ProxyUID
				}
				if proxyConfig.ProxyPort != nil {
					proxyPort = *proxyConfig.ProxyPort
				}
				if proxyConfig.ProxyAdminPort != nil {
					proxyAdminPort = *proxyConfig.ProxyAdminPort
				}
			}

			deploy.Spec.Template.Annotations["pod.networkproxy.security.beta.varmor.org"] = fmt.Sprintf("localhost/%s", profileName)
			// Add a init container
			script := fmt.Sprintf(scriptTemplate, proxyUID, proxyPort, proxyAdminPort)
			proxyInitContainer.Command = []string{"sh", "-c", script}
			deploy.Spec.Template.Spec.InitContainers = append(deploy.Spec.Template.Spec.InitContainers, proxyInitContainer)
			// Add a proxy sidecar container
			proxyContainer.SecurityContext.RunAsUser = &proxyUID
			proxyContainer.ReadinessProbe.HTTPGet.Port.IntVal = int32(proxyAdminPort)
			deploy.Spec.Template.Spec.Containers = append(deploy.Spec.Template.Spec.Containers, proxyContainer)
			// Add a volume
			proxyVolume.ConfigMap.Name = profileName
			deploy.Spec.Template.Spec.Volumes = append(deploy.Spec.Template.Spec.Volumes, proxyVolume)
		}
	}

	// Setting new annotations and seccomp context for AppArmor, BPF and Seccomp
	for index, container := range deploy.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
				if bpfExclusiveMode {
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					deploy.Spec.Template.Annotations[key] = "unconfined"
				}
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				if !varmorconfig.AppArmorGA {
					// Below Kubernetes v1.30
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
						deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
					}
				} else {
					// Kubernetes v1.30 and above
					if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
						(deploy.Spec.Template.Spec.SecurityContext != nil && deploy.Spec.Template.Spec.SecurityContext.AppArmorProfile != nil && deploy.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
						// Do nothing
					} else {
						deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
						if deploy.Spec.Template.Spec.Containers[index].SecurityContext == nil {
							deploy.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
						}
						deploy.Spec.Template.Spec.Containers[index].SecurityContext.AppArmorProfile = &coreV1.AppArmorProfile{
							Type:             "Localhost",
							LocalhostProfile: &profileName,
						}
					}
				}
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
				(deploy.Spec.Template.Spec.SecurityContext != nil && deploy.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && deploy.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
				continue
			}

			deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if deploy.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			if mode == varmor.RuntimeDefaultMode {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type: "RuntimeDefault",
				}
			} else {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: &profileName,
				}
			}
		}
	}
}

func modifyStatefulSetAnnotationsAndEnv(
	enforcer string,
	mode varmor.VarmorPolicyMode,
	target varmor.Target,
	proxyConfig *varmor.NetworkProxyConfig,
	stateful *appsV1.StatefulSet,
	profileName string,
	bpfExclusiveMode bool) {
	e := varmortypes.GetEnforcerType(enforcer)

	// Clean up first
	for key, value := range stateful.Spec.Template.Annotations {
		// NetworkProxy
		if key == "pod.networkproxy.security.beta.varmor.org" && value != "unconfined" {
			delete(stateful.Spec.Template.Annotations, key)
			// Clean up the proxy init container
			for index, container := range stateful.Spec.Template.Spec.InitContainers {
				if container.Name == proxyInitContainer.Name {
					stateful.Spec.Template.Spec.InitContainers = append(stateful.Spec.Template.Spec.InitContainers[:index], stateful.Spec.Template.Spec.InitContainers[index+1:]...)
					break
				}
			}
			// Clean up the proxy container
			for index, container := range stateful.Spec.Template.Spec.Containers {
				if container.Name == proxyContainer.Name {
					stateful.Spec.Template.Spec.Containers = append(stateful.Spec.Template.Spec.Containers[:index], stateful.Spec.Template.Spec.Containers[index+1:]...)
					break
				}
			}
			// Clean up the proxy volume
			for index, volume := range stateful.Spec.Template.Spec.Volumes {
				if volume.Name == proxyVolume.Name {
					stateful.Spec.Template.Spec.Volumes = append(stateful.Spec.Template.Spec.Volumes[:index], stateful.Spec.Template.Spec.Volumes[index+1:]...)
					break
				}
			}
		}
		// BPF
		if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
			delete(stateful.Spec.Template.Annotations, key)
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if !varmorconfig.AppArmorGA {
				// Below Kubernetes v1.30
				if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
					delete(stateful.Spec.Template.Annotations, key)
				}
			} else {
				// Kubernetes v1.30 and above
				if strings.HasPrefix(key, "container.apparmor.security.beta.varmor.org/") && value != "unconfined" {
					delete(stateful.Spec.Template.Annotations, key)
					parts := strings.Split(key, "/")
					if len(parts) != 2 {
						continue
					}
					// Clean up the apparmor settings from the SecurityContext
					for index, container := range stateful.Spec.Template.Spec.Containers {
						if container.Name == parts[1] && stateful.Spec.Template.Spec.Containers[index].SecurityContext != nil {
							stateful.Spec.Template.Spec.Containers[index].SecurityContext.AppArmorProfile = nil
						}
					}
				}
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
				parts := strings.Split(key, "/")
				if len(parts) != 2 {
					continue
				}
				// Clean up the seccomp settings from the SecurityContext
				for index, container := range stateful.Spec.Template.Spec.Containers {
					if container.Name == parts[1] && stateful.Spec.Template.Spec.Containers[index].SecurityContext != nil {
						stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
					}
				}
			}
		}
	}

	// Add the modification time to annotation
	if stateful.Spec.Template.Annotations == nil {
		stateful.Spec.Template.Annotations = make(map[string]string)
	}

	if profileName == "" {
		return
	}

	// NetworkProxy
	if (e & varmortypes.NetworkProxy) != 0 {
		if value, ok := stateful.Spec.Template.Annotations["pod.networkproxy.security.beta.varmor.org"]; !ok || value != "unconfined" {
			proxyUID := varmorconfig.DefaultProxyUID
			proxyPort := varmorconfig.DefaultProxyPort
			proxyAdminPort := varmorconfig.DefaultProxyAdminPort

			if proxyConfig != nil {
				if proxyConfig.ProxyUID != nil {
					proxyUID = *proxyConfig.ProxyUID
				}
				if proxyConfig.ProxyPort != nil {
					proxyPort = *proxyConfig.ProxyPort
				}
				if proxyConfig.ProxyAdminPort != nil {
					proxyAdminPort = *proxyConfig.ProxyAdminPort
				}
			}

			stateful.Spec.Template.Annotations["pod.networkproxy.security.beta.varmor.org"] = fmt.Sprintf("localhost/%s", profileName)
			// Add a init container
			script := fmt.Sprintf(scriptTemplate, proxyUID, proxyPort, proxyAdminPort)
			proxyInitContainer.Command = []string{"sh", "-c", script}
			stateful.Spec.Template.Spec.InitContainers = append(stateful.Spec.Template.Spec.InitContainers, proxyInitContainer)
			// Add a proxy sidecar container
			proxyContainer.SecurityContext.RunAsUser = &proxyUID
			proxyContainer.ReadinessProbe.HTTPGet.Port.IntVal = int32(proxyAdminPort)
			stateful.Spec.Template.Spec.Containers = append(stateful.Spec.Template.Spec.Containers, proxyContainer)
			// Add a volume
			proxyVolume.ConfigMap.Name = profileName
			stateful.Spec.Template.Spec.Volumes = append(stateful.Spec.Template.Spec.Volumes, proxyVolume)
		}
	}

	// Setting new annotations and seccomp context for AppArmor, BPF and Seccomp
	for index, container := range stateful.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
				if bpfExclusiveMode {
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					stateful.Spec.Template.Annotations[key] = "unconfined"
				}
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				if !varmorconfig.AppArmorGA {
					// Below Kubernetes v1.30
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					if value, ok := stateful.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
						stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
					}
				} else {
					// Kubernetes v1.30 and above
					if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
						(stateful.Spec.Template.Spec.SecurityContext != nil && stateful.Spec.Template.Spec.SecurityContext.AppArmorProfile != nil && stateful.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
						// Do nothing
					} else {
						stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
						if stateful.Spec.Template.Spec.Containers[index].SecurityContext == nil {
							stateful.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
						}
						stateful.Spec.Template.Spec.Containers[index].SecurityContext.AppArmorProfile = &coreV1.AppArmorProfile{
							Type:             "Localhost",
							LocalhostProfile: &profileName,
						}
					}
				}
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
				(stateful.Spec.Template.Spec.SecurityContext != nil && stateful.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && stateful.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
				continue
			}

			stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if stateful.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			if mode == varmor.RuntimeDefaultMode {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type: "RuntimeDefault",
				}
			} else {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: &profileName,
				}
			}
		}
	}
}

func modifyDaemonSetAnnotationsAndEnv(
	enforcer string,
	mode varmor.VarmorPolicyMode,
	target varmor.Target,
	proxyConfig *varmor.NetworkProxyConfig,
	daemon *appsV1.DaemonSet,
	profileName string,
	bpfExclusiveMode bool) {
	e := varmortypes.GetEnforcerType(enforcer)

	// Clean up first
	for key, value := range daemon.Spec.Template.Annotations {
		// NetworkProxy
		if key == "pod.networkproxy.security.beta.varmor.org" && value != "unconfined" {
			delete(daemon.Spec.Template.Annotations, key)
			// Clean up the proxy init container
			for index, container := range daemon.Spec.Template.Spec.InitContainers {
				if container.Name == proxyInitContainer.Name {
					daemon.Spec.Template.Spec.InitContainers = append(daemon.Spec.Template.Spec.InitContainers[:index], daemon.Spec.Template.Spec.InitContainers[index+1:]...)
					break
				}
			}
			// Clean up the proxy container
			for index, container := range daemon.Spec.Template.Spec.Containers {
				if container.Name == proxyContainer.Name {
					daemon.Spec.Template.Spec.Containers = append(daemon.Spec.Template.Spec.Containers[:index], daemon.Spec.Template.Spec.Containers[index+1:]...)
					break
				}
			}
			// Clean up the proxy volume
			for index, volume := range daemon.Spec.Template.Spec.Volumes {
				if volume.Name == proxyVolume.Name {
					daemon.Spec.Template.Spec.Volumes = append(daemon.Spec.Template.Spec.Volumes[:index], daemon.Spec.Template.Spec.Volumes[index+1:]...)
					break
				}
			}
		}
		// BPF
		if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
			delete(daemon.Spec.Template.Annotations, key)
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if !varmorconfig.AppArmorGA {
				// Below Kubernetes v1.30
				if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
					delete(daemon.Spec.Template.Annotations, key)
				}
			} else {
				// Kubernetes v1.30 and above
				if strings.HasPrefix(key, "container.apparmor.security.beta.varmor.org/") && value != "unconfined" {
					delete(daemon.Spec.Template.Annotations, key)
					parts := strings.Split(key, "/")
					if len(parts) != 2 {
						continue
					}
					// Clean up the apparmor settings from the SecurityContext
					for index, container := range daemon.Spec.Template.Spec.Containers {
						if container.Name == parts[1] && daemon.Spec.Template.Spec.Containers[index].SecurityContext != nil {
							daemon.Spec.Template.Spec.Containers[index].SecurityContext.AppArmorProfile = nil
						}
					}
				}
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
				parts := strings.Split(key, "/")
				if len(parts) != 2 {
					continue
				}
				// Clean up the seccomp settings from the SecurityContext
				for index, container := range daemon.Spec.Template.Spec.Containers {
					if container.Name == parts[1] && daemon.Spec.Template.Spec.Containers[index].SecurityContext != nil {
						daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
					}
				}
			}
		}
	}

	// Add the modification time to annotation
	if daemon.Spec.Template.Annotations == nil {
		daemon.Spec.Template.Annotations = make(map[string]string)
	}

	if profileName == "" {
		return
	}

	// NetworkProxy
	if (e & varmortypes.NetworkProxy) != 0 {
		if value, ok := daemon.Spec.Template.Annotations["pod.networkproxy.security.beta.varmor.org"]; !ok || value != "unconfined" {
			proxyUID := varmorconfig.DefaultProxyUID
			proxyPort := varmorconfig.DefaultProxyPort
			proxyAdminPort := varmorconfig.DefaultProxyAdminPort

			if proxyConfig != nil {
				if proxyConfig.ProxyUID != nil {
					proxyUID = *proxyConfig.ProxyUID
				}
				if proxyConfig.ProxyPort != nil {
					proxyPort = *proxyConfig.ProxyPort
				}
				if proxyConfig.ProxyAdminPort != nil {
					proxyAdminPort = *proxyConfig.ProxyAdminPort
				}
			}

			daemon.Spec.Template.Annotations["pod.networkproxy.security.beta.varmor.org"] = fmt.Sprintf("localhost/%s", profileName)
			// Add a init container
			script := fmt.Sprintf(scriptTemplate, proxyUID, proxyPort, proxyAdminPort)
			proxyInitContainer.Command = []string{"sh", "-c", script}
			daemon.Spec.Template.Spec.InitContainers = append(daemon.Spec.Template.Spec.InitContainers, proxyInitContainer)
			// Add a proxy sidecar container
			proxyContainer.SecurityContext.RunAsUser = &proxyUID
			proxyContainer.ReadinessProbe.HTTPGet.Port.IntVal = int32(proxyAdminPort)
			daemon.Spec.Template.Spec.Containers = append(daemon.Spec.Template.Spec.Containers, proxyContainer)
			// Add a volume
			proxyVolume.ConfigMap.Name = profileName
			daemon.Spec.Template.Spec.Volumes = append(daemon.Spec.Template.Spec.Volumes, proxyVolume)
		}
	}

	// Setting new annotations and seccomp context for AppArmor, BPF and Seccomp
	for index, container := range daemon.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
				if bpfExclusiveMode {
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					daemon.Spec.Template.Annotations[key] = "unconfined"
				}
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				if !varmorconfig.AppArmorGA {
					// Below Kubernetes v1.30
					key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					if value, ok := daemon.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
						daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
					}
				} else {
					// Kubernetes v1.30 and above
					if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
						(daemon.Spec.Template.Spec.SecurityContext != nil && daemon.Spec.Template.Spec.SecurityContext.AppArmorProfile != nil && daemon.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
						// Do nothing
					} else {
						daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
						if daemon.Spec.Template.Spec.Containers[index].SecurityContext == nil {
							daemon.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
						}
						daemon.Spec.Template.Spec.Containers[index].SecurityContext.AppArmorProfile = &coreV1.AppArmorProfile{
							Type:             "Localhost",
							LocalhostProfile: &profileName,
						}
					}
				}
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
				(daemon.Spec.Template.Spec.SecurityContext != nil && daemon.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && daemon.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
				continue
			}

			daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if daemon.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			if mode == varmor.RuntimeDefaultMode {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type: "RuntimeDefault",
				}
			} else {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: &profileName,
				}
			}
		}
	}
}

func updateWorkloadAnnotationsAndEnv(
	appsInterface appsv1.AppsV1Interface,
	namespace string,
	enforcer string,
	mode varmor.VarmorPolicyMode,
	target varmor.Target,
	proxyConfig *varmor.NetworkProxyConfig,
	profileName string,
	bpfExclusiveMode bool,
	logger logr.Logger) {

	matchFields := make(map[string]string)
	if target.Name != "" {
		matchFields["metadata.name"] = target.Name
	}

	// The target must have the webhook selector label.
	for key, value := range varmorconfig.WebhookSelectorLabel {
		if target.Selector == nil {
			target.Selector = &metav1.LabelSelector{}
		}
		if target.Selector.MatchLabels == nil {
			target.Selector.MatchLabels = make(map[string]string)
		}
		target.Selector.MatchLabels[key] = value
	}

	selector, err := metav1.LabelSelectorAsSelector(target.Selector)
	if err != nil {
		logger.Error(err, "LabelSelectorAsSelector()")
		return
	}

	listOpt := metav1.ListOptions{
		LabelSelector:   selector.String(),
		FieldSelector:   fields.Set(matchFields).String(),
		ResourceVersion: "0",
	}

	switch target.Kind {
	case "Deployment":
		deploys, err := appsInterface.Deployments(namespace).List(context.Background(), listOpt)
		if err != nil {
			logger.Error(err, "Deployments().List()")
			return
		}

		for _, item := range deploys.Items {
			deploy := &item
			regain := false
			updateDeployment := func() error {
				if regain {
					deploy, err = appsInterface.Deployments(deploy.Namespace).Get(context.Background(), deploy.Name, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					regain = false
				}

				deployOld := deploy.DeepCopy()
				modifyDeploymentAnnotationsAndEnv(enforcer, mode, target, proxyConfig, deploy, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(deployOld, deploy) {
					return nil
				}
				deploy.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)
				_, err = appsInterface.Deployments(deploy.Namespace).Update(context.Background(), deploy, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "Deployments", "namespace", deploy.Namespace, "name", deploy.Name)
				} else {
					regain = true
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateDeployment)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		}

	case "StatefulSet":
		statefuls, err := appsInterface.StatefulSets(namespace).List(context.Background(), listOpt)
		if err != nil {
			logger.Error(err, "StatefulSets().List()")
			return
		}

		for _, item := range statefuls.Items {
			stateful := &item
			regain := false
			updateStateful := func() error {
				if regain {
					stateful, err = appsInterface.StatefulSets(stateful.Namespace).Get(context.Background(), stateful.Name, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					regain = false
				}

				statefulOld := stateful.DeepCopy()
				modifyStatefulSetAnnotationsAndEnv(enforcer, mode, target, proxyConfig, stateful, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(statefulOld, stateful) {
					return nil
				}
				stateful.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)
				_, err = appsInterface.StatefulSets(stateful.Namespace).Update(context.Background(), stateful, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "StatefulSets", "namespace", stateful.Namespace, "name", stateful.Name)
				} else {
					regain = true
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateStateful)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		}

	case "DaemonSet":
		daemons, err := appsInterface.DaemonSets(namespace).List(context.Background(), listOpt)
		if err != nil {
			logger.Error(err, "DaemonSets().List()")
			return
		}

		if len(daemons.Items) == 0 {
			return
		}

		for _, item := range daemons.Items {
			daemon := &item
			regain := false
			updateDaemon := func() error {
				if regain {
					daemon, err = appsInterface.DaemonSets(daemon.Namespace).Get(context.Background(), daemon.Name, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					regain = false
				}

				daemonOld := daemon.DeepCopy()
				modifyDaemonSetAnnotationsAndEnv(enforcer, mode, target, proxyConfig, daemon, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(daemonOld, &daemon) {
					return nil
				}
				daemon.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)
				_, err = appsInterface.DaemonSets(daemon.Namespace).Update(context.Background(), daemon, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "DaemonSets", "namespace", daemon.Namespace, "name", daemon.Name)
				} else {
					regain = true
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateDaemon)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		}
	}
}

func forceSetOwnerReference(ap *varmor.ArmorProfile, obj interface{}, clusterScope bool) {
	controller := true
	if clusterScope {
		vcp := obj.(*varmor.VarmorClusterPolicy)
		ap.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "crd.varmor.org/v1beta1",
				Kind:       "VarmorClusterPolicy",
				Name:       vcp.Name,
				UID:        vcp.UID,
				Controller: &controller,
			},
		}
	} else {
		vp := obj.(*varmor.VarmorPolicy)
		ap.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "crd.varmor.org/v1beta1",
				Kind:       "VarmorPolicy",
				Name:       vp.Name,
				UID:        vp.UID,
				Controller: &controller,
			},
		}
	}
}

func resetArmorProfileModelStatus(varmorInterface varmorinterface.CrdV1beta1Interface, namespace, name string) error {
	return retry.RetryOnConflict(retry.DefaultRetry,
		func() error {
			apm, err := varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				if k8errors.IsNotFound(err) {
					return nil
				}
				return err
			}
			apm.Status.CompletedNumber = 0
			apm.Status.Conditions = nil
			apm.Status.Ready = false
			_, err = varmorInterface.ArmorProfileModels(namespace).UpdateStatus(context.Background(), apm, metav1.UpdateOptions{})
			return err
		})
}

func policyOwnArmorProfile(obj interface{}, ap *varmor.ArmorProfile, clusterScope bool) bool {
	if clusterScope {
		vcp := obj.(*varmor.VarmorClusterPolicy)
		if len(ap.OwnerReferences) == 1 {
			return vcp.UID == ap.OwnerReferences[0].UID
		}
	} else {
		vp := obj.(*varmor.VarmorPolicy)
		if len(ap.OwnerReferences) == 1 {
			return vp.UID == ap.OwnerReferences[0].UID
		}
	}
	return false
}
