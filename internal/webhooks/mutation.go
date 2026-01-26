// Copyright 2022-2023 vArmor Authors
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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

func (ws *WebhookServer) matchAndPatch(request *admissionv1.AdmissionRequest, key string, target varmor.Target, logger logr.Logger) *admissionv1.AdmissionResponse {
	policyNamespace, policyName, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}
	logger.V(2).Info("policy matching", "policy namespace", policyNamespace, "policy name", policyName)

	clusterScope := policyNamespace == ""
	if !clusterScope && policyNamespace != request.Namespace {
		return nil
	}

	if request.Kind.Kind != target.Kind {
		return nil
	}

	enforcer := ""
	var mode varmor.VarmorPolicyMode
	if clusterScope {
		enforcer = ws.policyCacher.ClusterPolicyEnforcer[key]
		mode = ws.policyCacher.ClusterPolicyMode[key]
		policyNamespace = varmorconfig.Namespace
	} else {
		enforcer = ws.policyCacher.PolicyEnforcer[key]
		mode = ws.policyCacher.PolicyMode[key]
	}

	obj, err := ws.deserializeWorkload(request)
	if err != nil {
		logger.Error(err, "ws.deserializeWorkload()")
		return nil
	}

	m, err := meta.Accessor(obj)
	if err != nil {
		logger.Error(err, "meta.Accessor()")
		return nil
	}

	apName := varmorprofile.GenerateArmorProfileName(policyNamespace, policyName, clusterScope)
	if target.Name != "" && target.Name == m.GetName() {
		logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
		patch, err := buildPatch(obj, enforcer, mode, target, apName, ws.bpfExclusiveMode, varmorconfig.AppArmorGA)
		if err != nil {
			logger.Error(err, "ws.buildPatch()")
			return nil
		}
		logger.V(2).Info("mutating resource", "json patch", patch)
		return successResponse(request.UID, []byte(patch))
	} else if target.Selector != nil {
		selector, err := metav1.LabelSelectorAsSelector(target.Selector)
		if err != nil {
			return nil
		}
		if selector.Matches(labels.Set(m.GetLabels())) {
			logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
			patch, err := buildPatch(obj, enforcer, mode, target, apName, ws.bpfExclusiveMode, varmorconfig.AppArmorGA)
			if err != nil {
				logger.Error(err, "ws.buildPatch()")
				return nil
			}
			logger.V(2).Info("mutating resource", "json patch", patch)
			return successResponse(request.UID, []byte(patch))
		}
	}

	return nil
}

func (ws *WebhookServer) deserializeWorkload(request *admissionv1.AdmissionRequest) (interface{}, error) {
	switch request.Kind.Kind {
	case "Deployment":
		deploy := appsv1.Deployment{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &deploy)
		return &deploy, err
	case "StatefulSet":
		statusful := appsv1.StatefulSet{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &statusful)
		return &statusful, err
	case "DaemonSet":
		daemon := appsv1.DaemonSet{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &daemon)
		return &daemon, err
	case "Pod":
		pod := corev1.Pod{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &pod)
		return &pod, err
	}
	return nil, fmt.Errorf("unsupported kind")
}

func buildPatch(obj interface{}, enforcer string,
	mode varmor.VarmorPolicyMode, target varmor.Target,
	profileName string, bpfExclusiveMode bool, appArmorGA bool) (patch string, err error) {
	var jsonPatch string

	switch target.Kind {
	case "Deployment":
		deploy := obj.(*appsv1.Deployment)

		if deploy.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}

		if deploy.Spec.Template.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/spec/template/metadata/annotations", "value": {}},`
		}

		for index, container := range deploy.Spec.Template.Spec.Containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
				continue
			}

			e := varmortypes.GetEnforcerType(enforcer)

			// BPF
			if (e & varmortypes.BPF) != 0 {
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
				if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
					jsonPatch += buildBpfPatch(appArmorGA, true, bpfExclusiveMode, profileName, container, index)
				}
			}
			// AppArmor
			if (e & varmortypes.AppArmor) != 0 {
				key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
				if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
					if !appArmorGA {
						// Below Kubernetes v1.30
						key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
						if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
							jsonPatch += buildAppArmorPatch(appArmorGA, true, profileName, container, index)
						}
					} else {
						// Kubernetes v1.30 and above
						if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
							(deploy.Spec.Template.Spec.SecurityContext != nil && deploy.Spec.Template.Spec.SecurityContext.AppArmorProfile != nil && deploy.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
							// Do nothing
						} else {
							jsonPatch += buildAppArmorPatch(appArmorGA, true, profileName, container, index)
							if container.SecurityContext == nil {
								container.SecurityContext = &corev1.SecurityContext{}
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
				jsonPatch += buildSeccompPatch(true, profileName, container, index, mode)
			}
		}
	case "StatefulSet":
		statefulSet := obj.(*appsv1.StatefulSet)

		if statefulSet.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}

		if statefulSet.Spec.Template.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/spec/template/metadata/annotations", "value": {}},`
		}

		for index, container := range statefulSet.Spec.Template.Spec.Containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
				continue
			}

			e := varmortypes.GetEnforcerType(enforcer)

			// BPF
			if (e & varmortypes.BPF) != 0 {
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
				if value, ok := statefulSet.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
					jsonPatch += buildBpfPatch(appArmorGA, true, bpfExclusiveMode, profileName, container, index)
				}
			}
			// AppArmor
			if (e & varmortypes.AppArmor) != 0 {
				key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
				if value, ok := statefulSet.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
					if !appArmorGA {
						// Below Kubernetes v1.30
						key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
						if value, ok := statefulSet.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
							jsonPatch += buildAppArmorPatch(appArmorGA, true, profileName, container, index)
						}
					} else {
						// Kubernetes v1.30 and above
						if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
							(statefulSet.Spec.Template.Spec.SecurityContext != nil && statefulSet.Spec.Template.Spec.SecurityContext.AppArmorProfile != nil && statefulSet.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
							// Do nothing
						} else {
							jsonPatch += buildAppArmorPatch(appArmorGA, true, profileName, container, index)
							if container.SecurityContext == nil {
								container.SecurityContext = &corev1.SecurityContext{}
							}
						}
					}
				}
			}
			// Seccomp
			if (e & varmortypes.Seccomp) != 0 {
				key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
				if value, ok := statefulSet.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
					(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
					(statefulSet.Spec.Template.Spec.SecurityContext != nil && statefulSet.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && statefulSet.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
					continue
				}
				jsonPatch += buildSeccompPatch(true, profileName, container, index, mode)
			}
		}
	case "DaemonSet":
		daemonSet := obj.(*appsv1.DaemonSet)

		if daemonSet.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}

		if daemonSet.Spec.Template.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/spec/template/metadata/annotations", "value": {}},`
		}

		for index, container := range daemonSet.Spec.Template.Spec.Containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
				continue
			}

			e := varmortypes.GetEnforcerType(enforcer)

			// BPF
			if (e & varmortypes.BPF) != 0 {
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
				if value, ok := daemonSet.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
					jsonPatch += buildBpfPatch(appArmorGA, true, bpfExclusiveMode, profileName, container, index)
				}
			}
			// AppArmor
			if (e & varmortypes.AppArmor) != 0 {
				key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
				if value, ok := daemonSet.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
					if !appArmorGA {
						// Below Kubernetes v1.30
						key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
						if value, ok := daemonSet.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
							jsonPatch += buildAppArmorPatch(appArmorGA, true, profileName, container, index)
						}
					} else {
						// Kubernetes v1.30 and above
						if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
							(daemonSet.Spec.Template.Spec.SecurityContext != nil && daemonSet.Spec.Template.Spec.SecurityContext.AppArmorProfile != nil && daemonSet.Spec.Template.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
							// Do nothing
						} else {
							jsonPatch += buildAppArmorPatch(appArmorGA, true, profileName, container, index)
							if container.SecurityContext == nil {
								container.SecurityContext = &corev1.SecurityContext{}
							}
						}
					}
				}
			}
			// Seccomp
			if (e & varmortypes.Seccomp) != 0 {
				key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
				if value, ok := daemonSet.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
					(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
					(daemonSet.Spec.Template.Spec.SecurityContext != nil && daemonSet.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && daemonSet.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
					continue
				}
				jsonPatch += buildSeccompPatch(true, profileName, container, index, mode)
			}
		}
	case "Pod":
		pod := obj.(*corev1.Pod)

		if pod.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}

		for index, container := range pod.Spec.Containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
				continue
			}

			e := varmortypes.GetEnforcerType(enforcer)

			// BPF
			if (e & varmortypes.BPF) != 0 {
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
				if value, ok := pod.Annotations[key]; !ok || value != "unconfined" {
					jsonPatch += buildBpfPatch(appArmorGA, false, bpfExclusiveMode, profileName, container, index)
				}
			}
			// AppArmor
			if (e & varmortypes.AppArmor) != 0 {
				key := fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", container.Name)
				if value, ok := pod.Annotations[key]; !ok || value != "unconfined" {
					if !appArmorGA {
						// Below Kubernetes v1.30
						key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
						if value, ok := pod.Annotations[key]; !ok || value != "unconfined" {
							jsonPatch += buildAppArmorPatch(appArmorGA, false, profileName, container, index)
						}
					} else {
						// Kubernetes v1.30 and above
						if (container.SecurityContext != nil && container.SecurityContext.AppArmorProfile != nil && container.SecurityContext.AppArmorProfile.Type == "Unconfined") ||
							(pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.AppArmorProfile != nil && pod.Spec.SecurityContext.AppArmorProfile.Type == "Unconfined") {
							// Do nothing
						} else {
							jsonPatch += buildAppArmorPatch(appArmorGA, false, profileName, container, index)
							if container.SecurityContext == nil {
								container.SecurityContext = &corev1.SecurityContext{}
							}
						}
					}
				}
			}
			// Seccomp
			if (e & varmortypes.Seccomp) != 0 {
				key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
				if value, ok := pod.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
					(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
					(pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil && pod.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
					continue
				}
				jsonPatch += buildSeccompPatch(false, profileName, container, index, mode)
			}
		}
	}

	if len(jsonPatch) > 0 {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "%s"},`, time.Now().Format(time.RFC3339))
		jsonPatch = jsonPatch[:len(jsonPatch)-1]
		patch = fmt.Sprintf("[%s]", jsonPatch)
	}

	return patch, nil
}

func buildBpfPatch(
	appArmorGA bool,
	workloads bool,
	bpfExclusiveMode bool,
	profileName string,
	container corev1.Container,
	index int) string {

	var jsonPatch string

	if workloads {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container.Name, profileName)
	} else {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container.Name, profileName)
	}

	if bpfExclusiveMode {
		if workloads {
			if !appArmorGA {
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, container.Name)
			} else {
				if container.SecurityContext == nil {
					jsonPatch += fmt.Sprintf(`{"op": "add", "path": "/spec/template/spec/containers/%d/securityContext", "value": {}},`, index)
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/spec/containers/%d/securityContext/appArmorProfile", "value": {"type": "Unconfined"}},`, index)
			}
		} else {
			if !appArmorGA {
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, container.Name)
			} else {
				if container.SecurityContext == nil {
					jsonPatch += fmt.Sprintf(`{"op": "add", "path": "/spec/containers/%d/securityContext", "value": {}},`, index)
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/containers/%d/securityContext/appArmorProfile", "value": {"type": "Unconfined"}},`, index)
			}
		}
	}

	return jsonPatch
}

func buildAppArmorPatch(
	appArmorGA bool,
	workloads bool,
	profileName string,
	container corev1.Container,
	index int) string {

	var jsonPatch string

	if workloads {
		if !appArmorGA {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, container.Name, profileName)
		} else {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container.Name, profileName)
			if container.SecurityContext == nil {
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": "/spec/template/spec/containers/%d/securityContext", "value": {}},`, index)
			}
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/spec/containers/%d/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "%s"}},`, index, profileName)
		}
	} else {
		if !appArmorGA {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, container.Name, profileName)
		} else {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container.Name, profileName)
			if container.SecurityContext == nil {
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": "/spec/containers/%d/securityContext", "value": {}},`, index)
			}
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/containers/%d/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "%s"}},`, index, profileName)
		}
	}

	return jsonPatch
}

func buildSeccompPatch(
	workloads bool,
	profileName string,
	container corev1.Container,
	index int, mode varmor.VarmorPolicyMode) string {

	var jsonPatch string

	if workloads {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.seccomp.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container.Name, profileName)
		if container.SecurityContext == nil {
			jsonPatch += fmt.Sprintf(`{"op": "add", "path": "/spec/template/spec/containers/%d/securityContext", "value": {}},`, index)
		}
		if mode == varmor.RuntimeDefaultMode {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/spec/containers/%d/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},`, index)
		} else {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/spec/containers/%d/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "%s"}},`, index, profileName)
		}
	} else {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.seccomp.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container.Name, profileName)
		if container.SecurityContext == nil {
			jsonPatch += fmt.Sprintf(`{"op": "add", "path": "/spec/containers/%d/securityContext", "value": {}},`, index)
		}
		if mode == varmor.RuntimeDefaultMode {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/containers/%d/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},`, index)
		} else {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/containers/%d/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "%s"}},`, index, profileName)
		}
	}

	return jsonPatch
}
