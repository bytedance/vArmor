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

package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/bytedance/vArmor/pkg/workload"
)

func toUnstructured(t *testing.T, obj interface{}) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatalf("ToUnstructured: %v", err)
	}
	return &unstructured.Unstructured{Object: m}
}

// testRegistry builds an isolated registry containing exactly the built-in
// adapters; tests never depend on process-global state.
func testRegistry(t *testing.T) *workload.Registry {
	t.Helper()
	r, err := workload.NewRegistry(Adapters()...)
	assert.NoError(t, err)
	return r
}

func TestInit_SelfRegistersBuiltinAdapters(t *testing.T) {
	// The builtin test binary links this package and therefore runs its
	// init exactly once; the global catalog must hold the same four
	// adapters Adapters() returns.
	registered := workload.RegisteredAdapters()
	assert.Len(t, registered, len(Adapters()))

	wantNames := make(map[string]struct{}, len(Adapters()))
	for _, a := range Adapters() {
		wantNames[a.Name()] = struct{}{}
	}
	for _, a := range registered {
		assert.Contains(t, wantNames, a.Name(), "unexpected adapter %q in the global catalog", a.Name())
	}
}

func TestBuiltinAdapters_IdentityAndOptions(t *testing.T) {
	expected := map[string]struct {
		gvkGroup, gvkKind, gvrResource string
		firstOp                        admissionregistrationv1.OperationType
	}{
		DeploymentName:  {"apps", "Deployment", "deployments", admissionregistrationv1.Create},
		StatefulSetName: {"apps", "StatefulSet", "statefulsets", admissionregistrationv1.Create},
		DaemonSetName:   {"apps", "DaemonSet", "daemonsets", admissionregistrationv1.Create},
		PodName:         {"", "Pod", "pods", admissionregistrationv1.Create},
	}

	for _, a := range testRegistry(t).List() {
		want, ok := expected[a.Name()]
		if !ok {
			t.Fatalf("unexpected registered adapter %q", a.Name())
		}
		if a.GVK().Group != want.gvkGroup || a.GVK().Kind != want.gvkKind {
			t.Errorf("%s: GVK = %v, want group %q kind %q", a.Name(), a.GVK(), want.gvkGroup, want.gvkKind)
		}
		if a.GVR().Resource != want.gvrResource {
			t.Errorf("%s: GVR resource = %q, want %q", a.Name(), a.GVR().Resource, want.gvrResource)
		}
		opts := a.DefaultWebhookOptions()
		if opts.FailurePolicy != admissionregistrationv1.Ignore {
			t.Errorf("%s: failure policy = %v, want Ignore", a.Name(), opts.FailurePolicy)
		}
		if len(opts.Operations) == 0 || opts.Operations[0] != want.firstOp {
			t.Errorf("%s: operations = %v, want leading %v", a.Name(), opts.Operations, want.firstOp)
		}
	}
}

func TestBuiltinAdapters_TypedAndUnstructuredTemplates(t *testing.T) {
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "demo",
			Labels:      map[string]string{"app": "demo"},
			Annotations: map[string]string{"example.com/opt-in": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "main",
				SecurityContext: &corev1.SecurityContext{
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
			}},
		},
	}
	testCases := []struct {
		kind string
		obj  runtime.Object
		path string
	}{
		{"Deployment", &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: template}}, workload.WorkloadTemplatePath},
		{"StatefulSet", &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{Template: template}}, workload.WorkloadTemplatePath},
		{"DaemonSet", &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: template}}, workload.WorkloadTemplatePath},
		{"Pod", &corev1.Pod{ObjectMeta: template.ObjectMeta, Spec: template.Spec}, workload.RootPath},
	}
	for _, tc := range testCases {
		t.Run(tc.kind, func(t *testing.T) {
			typed, err := workload.BuiltinPodTemplates(tc.obj)
			if !assert.NoError(t, err) {
				return
			}
			a, ok := testRegistry(t).LookupByKind(tc.kind)
			if !assert.True(t, ok) {
				return
			}
			converted, err := a.PodTemplates(toUnstructured(t, tc.obj))
			if !assert.NoError(t, err) {
				return
			}
			want := []workload.PodTemplateRef{{Path: tc.path, Template: &template}}
			assert.Equal(t, want, typed)
			assert.Equal(t, typed, converted)
			_, err = a.PodTemplates(nil)
			assert.Error(t, err)
			_, err = a.PodTemplates(&unstructured.Unstructured{Object: map[string]interface{}{"spec": "invalid"}})
			assert.Error(t, err)
		})
	}
}
