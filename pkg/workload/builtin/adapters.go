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

// Package builtin provides the workload adapters for the four resource types
// vArmor has always supported: Deployment, StatefulSet, DaemonSet and Pod.
// Importing the package self-registers the adapters into the workload
// package's global catalog via init; the manager binary blank-imports it for
// that side effect. Adapters() remains available for tests that build
// throwaway registries explicitly through workload.NewRegistry.
package builtin

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/bytedance/vArmor/pkg/workload"
)

const (
	// Adapter names. These double as the workloadAdapters config keys.
	DeploymentName  = "deployment"
	StatefulSetName = "statefulset"
	DaemonSetName   = "daemonset"
	PodName         = workload.PodAdapterName
)

// adapter is the shared implementation for the built-in kinds. It carries the
// type identity and a constructor for decoding unstructured objects.
type adapter struct {
	name       string
	gvk        schema.GroupVersionKind
	gvr        schema.GroupVersionResource
	operations []admissionregistrationv1.OperationType
	newObject  func() runtime.Object
}

func (a *adapter) Name() string                     { return a.name }
func (a *adapter) GVK() schema.GroupVersionKind     { return a.gvk }
func (a *adapter) GVR() schema.GroupVersionResource { return a.gvr }
func (a *adapter) PodTemplates(obj *unstructured.Unstructured) ([]workload.PodTemplateRef, error) {
	if obj == nil {
		return nil, fmt.Errorf("workload/builtin: nil unstructured object")
	}
	typed := a.newObject()
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, typed); err != nil {
		return nil, err
	}
	return workload.BuiltinPodTemplates(typed)
}
func (a *adapter) DefaultWebhookOptions() workload.WebhookOptions {
	return workload.WebhookOptions{
		FailurePolicy:  admissionregistrationv1.Ignore,
		Operations:     append([]admissionregistrationv1.OperationType(nil), a.operations...),
		TimeoutSeconds: 0, // 0 => use the manager global default
	}
}

// createUpdate is the default operation set for the apps/v1 workload kinds.
var createUpdate = []admissionregistrationv1.OperationType{
	admissionregistrationv1.Create, admissionregistrationv1.Update,
}

// adapterSpec captures the static identity of one built-in adapter.
type adapterSpec struct {
	name       string
	kind       string
	plural     string
	group      string
	version    string
	operations []admissionregistrationv1.OperationType
	newObject  func() runtime.Object
}

// init self-registers the built-in adapters into the process-wide workload
// catalog. Linking this package (the manager binary blank-imports it) is
// therefore sufficient to make the built-ins discoverable; whether each one
// actually serves admissions is still decided by the workloadAdapters
// `enabled` filter at the composition root. Validation stays deferred to
// workload.NewRegistry, so init cannot panic on a misconfigured adapter.
func init() {
	for _, a := range Adapters() {
		workload.Register(a)
	}
}

// Adapters returns the four built-in workload adapters in deterministic
// order. init registers the same set into the global catalog; tests also use
// it to build isolated registries via workload.NewRegistry.
func Adapters() []workload.Adapter {
	specs := []adapterSpec{
		{DeploymentName, "Deployment", "deployments", "apps", "v1", createUpdate, func() runtime.Object { return &appsv1.Deployment{} }},
		{StatefulSetName, "StatefulSet", "statefulsets", "apps", "v1", createUpdate, func() runtime.Object { return &appsv1.StatefulSet{} }},
		{DaemonSetName, "DaemonSet", "daemonsets", "apps", "v1", createUpdate, func() runtime.Object { return &appsv1.DaemonSet{} }},
		{PodName, "Pod", "pods", "", "v1", []admissionregistrationv1.OperationType{admissionregistrationv1.Create}, func() runtime.Object { return &corev1.Pod{} }},
	}
	adapters := make([]workload.Adapter, 0, len(specs))
	for _, s := range specs {
		adapters = append(adapters, &adapter{
			name:       s.name,
			gvk:        schema.GroupVersionKind{Group: s.group, Version: s.version, Kind: s.kind},
			gvr:        schema.GroupVersionResource{Group: s.group, Version: s.version, Resource: s.plural},
			operations: s.operations,
			newObject:  s.newObject,
		})
	}
	return adapters
}
