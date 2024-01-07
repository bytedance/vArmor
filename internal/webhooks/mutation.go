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

func buildPatch(obj interface{}, enforcer string, target varmor.Target, profileName string, bpfExclusiveMode bool) (patch string, err error) {
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

		var containers []string
		for _, c := range deploy.Spec.Template.Spec.Containers {
			containers = append(containers, c.Name)
		}

		for _, container := range containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container, target.Containers) {
				continue
			}

			switch enforcer {
			case "BPF":
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container)
				if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container, profileName)
				if bpfExclusiveMode {
					jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, container)
				}
			case "AppArmor":
				key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container)
				if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, container, profileName)
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

		var containers []string
		for _, c := range statefulSet.Spec.Template.Spec.Containers {
			containers = append(containers, c.Name)
		}

		for _, container := range containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container, target.Containers) {
				continue
			}

			switch enforcer {
			case "BPF":
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container)
				if value, ok := statefulSet.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container, profileName)
				if bpfExclusiveMode {
					jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, container)
				}
			case "AppArmor":
				key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container)
				if value, ok := statefulSet.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, container, profileName)
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

		var containers []string
		for _, c := range daemonSet.Spec.Template.Spec.Containers {
			containers = append(containers, c.Name)
		}

		for _, container := range containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container, target.Containers) {
				continue
			}

			switch enforcer {
			case "BPF":
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container)
				if value, ok := daemonSet.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container, profileName)
				if bpfExclusiveMode {
					jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, container)
				}
			case "AppArmor":
				key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container)
				if value, ok := daemonSet.Spec.Template.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, container, profileName)
			}
		}
	case "Pod":
		pod := obj.(*corev1.Pod)

		if pod.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}

		var containers []string
		for _, c := range pod.Spec.Containers {
			containers = append(containers, c.Name)
		}

		for _, container := range containers {
			if len(target.Containers) != 0 && !varmorutils.InStringArray(container, target.Containers) {
				continue
			}

			switch enforcer {
			case "BPF":
				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container)
				if value, ok := pod.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, container, profileName)
				if bpfExclusiveMode {
					jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, container)
				}
			case "AppArmor":
				key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container)
				if value, ok := pod.Annotations[key]; ok && value == "unconfined" {
					continue
				}
				jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, container, profileName)
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
