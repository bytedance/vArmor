// Copyright 2026 vArmor Authors
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

package workload

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	// BuiltinRollupName is the configuration key for the three apps/v1 adapters.
	BuiltinRollupName = "builtin"
	// PodAdapterName is the adapter name and configuration key for core/v1 Pods.
	PodAdapterName = "pod"
	// RootPath is the template path for a root-level Pod.
	RootPath = ""
	// WorkloadTemplatePath is the template path for the three apps/v1 adapters.
	WorkloadTemplatePath = "/spec/template"
)

// BuiltinPodTemplates extracts template views from an already decoded built-in
// workload. The built-in adapters call it after converting their unstructured
// input to the typed workload, so all four built-in kinds share the same
// template paths and metadata handling.
func BuiltinPodTemplates(obj interface{}) ([]PodTemplateRef, error) {
	var template *corev1.PodTemplateSpec
	switch o := obj.(type) {
	case *appsv1.Deployment:
		template = &o.Spec.Template
	case *appsv1.StatefulSet:
		template = &o.Spec.Template
	case *appsv1.DaemonSet:
		template = &o.Spec.Template
	case *corev1.Pod:
		template = &corev1.PodTemplateSpec{ObjectMeta: o.ObjectMeta, Spec: o.Spec}
		return []PodTemplateRef{{Path: RootPath, Template: template}}, nil
	default:
		return nil, fmt.Errorf("unsupported workload object type %T", obj)
	}
	return []PodTemplateRef{{Path: WorkloadTemplatePath, Template: template}}, nil
}
