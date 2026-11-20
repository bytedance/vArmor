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
// that side effect. Adapters() is also used by tests that build throwaway
// registries explicitly through workload.NewRegistry.
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
	// Adapter names: stable identifiers for the built-in kinds and the
	// planned workloadAdapters config keys.
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

// builtinGroupKinds is derived once from Adapters() so the adapter roster
// stays the single source of truth for which kinds ship with vArmor: adding
// or removing a built-in adapter updates this set automatically, with no
// parallel identity list to keep in sync.
var builtinGroupKinds = func() map[schema.GroupKind]struct{} {
	groupKinds := make(map[schema.GroupKind]struct{}, 4)
	for _, a := range Adapters() {
		groupKinds[a.GVK().GroupKind()] = struct{}{}
	}
	return groupKinds
}()

// IsBuiltinAdapter reports whether a is one of the adapters shipped in this
// package. The webhook uses it to preserve the historical fail-open
// behavior for built-in kinds while failing closed on custom adapters.
func IsBuiltinAdapter(a workload.Adapter) bool {
	if a == nil {
		return false
	}
	_, ok := builtinGroupKinds[a.GVK().GroupKind()]
	return ok
}

// init self-registers the built-in adapters into the process-wide workload
// catalog. Linking this package (the manager binary blank-imports it) is
// therefore sufficient to make the built-ins part of the runtime Registry;
// every registered adapter is currently active, and a future
// workloadAdapters `enabled` filter at the composition root will control
// which ones serve admissions. Validation stays deferred to
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
	return []workload.Adapter{
		&adapter{
			name:       DeploymentName,
			gvk:        schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			gvr:        schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			operations: createUpdate,
			newObject:  func() runtime.Object { return &appsv1.Deployment{} },
		},
		&adapter{
			name:       StatefulSetName,
			gvk:        schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"},
			gvr:        schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"},
			operations: createUpdate,
			newObject:  func() runtime.Object { return &appsv1.StatefulSet{} },
		},
		&adapter{
			name:       DaemonSetName,
			gvk:        schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"},
			gvr:        schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			operations: createUpdate,
			newObject:  func() runtime.Object { return &appsv1.DaemonSet{} },
		},
		&adapter{
			name:       PodName,
			gvk:        schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			gvr:        schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
			newObject:  func() runtime.Object { return &corev1.Pod{} },
		},
	}
}
