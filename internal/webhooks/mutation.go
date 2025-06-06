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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

// bodyToAdmissionReview creates AdmissionReview object from request body.
// Answers to the http.ResponseWriter if request is not valid.
func bodyToAdmissionReview(request *http.Request, writer http.ResponseWriter, logger logr.Logger) *admissionv1.AdmissionReview {
	if request.Body == nil {
		logger.Info("empty body", "req", request.URL.String())
		http.Error(writer, "empty body", http.StatusBadRequest)
		return nil
	}

	defer request.Body.Close()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		logger.Info("failed to read HTTP body", "req", request.URL.String())
		http.Error(writer, "failed to read HTTP body", http.StatusBadRequest)
	}

	contentType := request.Header.Get("Content-Type")
	if contentType != "application/json" {
		logger.Info("invalid Content-Type", "contextType", contentType)
		http.Error(writer, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return nil
	}

	admissionReview := &admissionv1.AdmissionReview{}
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		logger.Error(err, "failed to decode request body to type 'AdmissionReview")
		http.Error(writer, "Can't decode body as AdmissionReview", http.StatusExpectationFailed)
		return nil
	}

	return admissionReview
}

func writeResponse(rw http.ResponseWriter, admissionReview *admissionv1.AdmissionReview) {
	responseJSON, err := json.Marshal(admissionReview)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Could not encode response: %v", err), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	if _, err := rw.Write(responseJSON); err != nil {
		http.Error(rw, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func successResponse(uid types.UID, patch []byte) *admissionv1.AdmissionResponse {
	r := &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: true,
		Result: &metav1.Status{
			Status: "Success",
		},
	}

	if len(patch) > 0 {
		patchType := admissionv1.PatchTypeJSONPatch
		r.PatchType = &patchType
		r.Patch = patch
	}

	return r
}

func errorResponse(uid types.UID, err error, message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: message + ": " + err.Error(),
		},
	}
}

func failureResponse(uid types.UID, message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: message,
		},
	}
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
