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

package webhooks

import (
	"encoding/json"
	"strings"
	"testing"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	"gotest.tools/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorpolicy "github.com/bytedance/vArmor/internal/policy"
)

// containerlessWorkload builds one of the four built-in workload kinds whose
// only pod template carries an empty PodSpec (no application containers).
func containerlessWorkload(t *testing.T, kind string) (interface{}, varmor.Target) {
	t.Helper()
	meta := metav1.ObjectMeta{Name: "containerless", Namespace: "test"}
	target := varmor.Target{Kind: kind, Name: meta.Name}
	switch kind {
	case "Deployment":
		return &appsv1.Deployment{ObjectMeta: meta, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{}}}, target
	case "StatefulSet":
		return &appsv1.StatefulSet{ObjectMeta: meta, Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{}}}, target
	case "DaemonSet":
		return &appsv1.DaemonSet{ObjectMeta: meta, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{}}}, target
	case "Pod":
		return &corev1.Pod{ObjectMeta: meta}, target
	default:
		t.Fatalf("unsupported kind %q", kind)
		return nil, target
	}
}

// assertPatchApplies applies a patch like the API server would, failing on
// any unapplyable op (the regression under test).
func assertPatchApplies(t *testing.T, obj interface{}, patch string) {
	t.Helper()
	if patch == "" {
		return
	}
	raw, err := json.Marshal(obj)
	assert.NilError(t, err)
	decoded, err := jsonpatch.DecodePatch([]byte(patch))
	assert.NilError(t, err)
	_, err = decoded.Apply(raw)
	assert.NilError(t, err)
}

// TestBuildNativePatch_ContainerlessTemplates covers built-in kinds whose
// template has no app containers. Without the guard NetworkProxy appends to
// spec/containers, which serializes to null for a zero-slice PodSpec (no
// omitempty): the op cannot apply and the API server rejects the request even
// under failurePolicy: Ignore. The patch must stay applyable with no
// spec-level ops; MAC enforcers keep their historical metadata-only behavior.
func TestBuildNativePatch_ContainerlessTemplates(t *testing.T) {
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "Pod"} {
		for _, enforcer := range []string{"NetworkProxy", "AppArmor", "BPF", "Seccomp", "AppArmorSeccomp"} {
			t.Run(kind+"/"+enforcer, func(t *testing.T) {
				obj, target := containerlessWorkload(t, kind)
				patch, err := buildNativePatch(obj, enforcer, varmor.EnhanceProtectMode, target, nil,
					"varmor-testns-test", varmorpolicy.AuditPolicyIdentity{}, false, true)
				assert.NilError(t, err)
				assertPatchApplies(t, obj, patch)
				// No injection target: no sidecar, init container, volume or
				// per-container securityContext ops. Metadata-only prelude
				// ops (e.g. /spec/template/metadata/annotations) remain.
				for _, forbidden := range []string{"spec/containers", "spec/initContainers", "spec/volumes"} {
					assert.Assert(t, !strings.Contains(patch, forbidden), "containerless template must not patch %s: %s", forbidden, patch)
				}
			})
		}
	}
}

// TestBuildNativePatch_NetworkProxyPatchApplies is the positive control: a
// one-container template still renders the full applyable NetworkProxy patch
// for every built-in kind.
func TestBuildNativePatch_NetworkProxyPatchApplies(t *testing.T) {
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "Pod"} {
		t.Run(kind, func(t *testing.T) {
			obj, target := containerlessWorkload(t, kind)
			app := corev1.Container{Name: "app", Image: "demo:latest"}
			switch w := obj.(type) {
			case *appsv1.Deployment:
				w.Spec.Template.Spec.Containers = []corev1.Container{app}
			case *appsv1.StatefulSet:
				w.Spec.Template.Spec.Containers = []corev1.Container{app}
			case *appsv1.DaemonSet:
				w.Spec.Template.Spec.Containers = []corev1.Container{app}
			case *corev1.Pod:
				w.Spec.Containers = []corev1.Container{app}
			}

			patch, err := buildNativePatch(obj, "NetworkProxy", varmor.EnhanceProtectMode, target, nil,
				"varmor-testns-test", varmorpolicy.AuditPolicyIdentity{}, false, true)
			assert.NilError(t, err)
			assert.Assert(t, patch != "", "a valid template must still be mutated")
			assert.Assert(t, strings.Contains(patch, `"name": "varmor-network-proxy"`), "sidecar must be injected: %s", patch)

			raw, err := json.Marshal(obj)
			assert.NilError(t, err)
			decoded, err := jsonpatch.DecodePatch([]byte(patch))
			assert.NilError(t, err)
			applied, err := decoded.Apply(raw)
			assert.NilError(t, err)

			var containers int
			switch obj.(type) {
			case *appsv1.Deployment:
				got := &appsv1.Deployment{}
				assert.NilError(t, json.Unmarshal(applied, got))
				containers = len(got.Spec.Template.Spec.Containers)
			case *appsv1.StatefulSet:
				got := &appsv1.StatefulSet{}
				assert.NilError(t, json.Unmarshal(applied, got))
				containers = len(got.Spec.Template.Spec.Containers)
			case *appsv1.DaemonSet:
				got := &appsv1.DaemonSet{}
				assert.NilError(t, json.Unmarshal(applied, got))
				containers = len(got.Spec.Template.Spec.Containers)
			case *corev1.Pod:
				got := &corev1.Pod{}
				assert.NilError(t, json.Unmarshal(applied, got))
				containers = len(got.Spec.Containers)
			}
			assert.Equal(t, containers, 2, "original container plus the injected Envoy sidecar")
		})
	}
}

// decodeRawWorkload decodes an admission-style raw JSON payload into the
// typed workload struct, mirroring deserializeWorkload. The API server
// itself decodes every built-in-kind request into its typed object before
// invoking admission and applies the returned patch against that same
// serialized form, so plain json.Unmarshal reproduces the structural
// behavior under test without standing up a scheme.
func decodeRawWorkload(t *testing.T, kind, raw string) (interface{}, varmor.Target) {
	t.Helper()
	target := varmor.Target{Kind: kind, Name: "containerless"}
	switch kind {
	case "Deployment":
		obj := &appsv1.Deployment{}
		assert.NilError(t, json.Unmarshal([]byte(raw), obj))
		return obj, target
	case "StatefulSet":
		obj := &appsv1.StatefulSet{}
		assert.NilError(t, json.Unmarshal([]byte(raw), obj))
		return obj, target
	case "DaemonSet":
		obj := &appsv1.DaemonSet{}
		assert.NilError(t, json.Unmarshal([]byte(raw), obj))
		return obj, target
	case "Pod":
		obj := &corev1.Pod{}
		assert.NilError(t, json.Unmarshal([]byte(raw), obj))
		return obj, target
	default:
		t.Fatalf("unsupported kind %q", kind)
		return nil, target
	}
}

// TestBuildNativePatch_RawJSONMissingSpec locks in the typed-decode
// guarantee for admission payloads whose wire JSON omits spec, carries a
// null/empty spec, or an explicit containers: null. Such shapes cannot reach
// the patch builder as absent JSON nodes: decoding into the non-pointer
// PodSpec struct (whose Containers field has no omitempty) materializes the
// whole spec/template/spec chain on re-marshal, so the zero-container guard
// in buildPodTemplatePatch keeps the NetworkProxy injection ops away while
// the remaining metadata-only patch still applies. Switching the native
// path to unstructured decoding (as the custom adapter path must use) would
// break this assumption and re-introduce the missing-node rejection.
func TestBuildNativePatch_RawJSONMissingSpec(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
		raw  string
	}{
		{
			name: "Deployment without spec",
			kind: "Deployment",
			raw:  `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"containerless","namespace":"test"}}`,
		},
		{
			name: "Deployment with null spec",
			kind: "Deployment",
			raw:  `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"containerless","namespace":"test"},"spec":null}`,
		},
		{
			name: "Deployment with empty template spec",
			kind: "Deployment",
			raw:  `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"containerless","namespace":"test"},"spec":{"template":{"spec":{}}}}`,
		},
		{
			name: "Deployment with null containers",
			kind: "Deployment",
			raw:  `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"containerless","namespace":"test"},"spec":{"template":{"spec":{"containers":null}}}}`,
		},
		{
			name: "StatefulSet without spec",
			kind: "StatefulSet",
			raw:  `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"containerless","namespace":"test"}}`,
		},
		{
			name: "DaemonSet without spec",
			kind: "DaemonSet",
			raw:  `{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"containerless","namespace":"test"}}`,
		},
		{
			name: "Pod without spec",
			kind: "Pod",
			raw:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"containerless","namespace":"test"}}`,
		},
		{
			name: "Pod with empty spec",
			kind: "Pod",
			raw:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"containerless","namespace":"test"},"spec":{}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj, target := decodeRawWorkload(t, tc.kind, tc.raw)

			// The guard condition itself: every malformed shape decodes to
			// zero application containers.
			switch w := obj.(type) {
			case *appsv1.Deployment:
				assert.Equal(t, len(w.Spec.Template.Spec.Containers), 0)
			case *appsv1.StatefulSet:
				assert.Equal(t, len(w.Spec.Template.Spec.Containers), 0)
			case *appsv1.DaemonSet:
				assert.Equal(t, len(w.Spec.Template.Spec.Containers), 0)
			case *corev1.Pod:
				assert.Equal(t, len(w.Spec.Containers), 0)
			}

			// Typed re-marshal materializes the absent nodes, including the
			// explicit containers: null on which an unguarded /- append
			// cannot apply.
			remarshaled, err := json.Marshal(obj)
			assert.NilError(t, err)
			assert.Assert(t, strings.Contains(string(remarshaled), `"containers":null`),
				"typed decode must materialize spec.containers: %s", string(remarshaled))

			patch, err := buildNativePatch(obj, "NetworkProxy", varmor.EnhanceProtectMode, target, nil,
				"varmor-testns-test", varmorpolicy.AuditPolicyIdentity{}, false, true)
			assert.NilError(t, err)
			assertPatchApplies(t, obj, patch)
			for _, forbidden := range []string{"spec/containers", "spec/initContainers", "spec/volumes"} {
				assert.Assert(t, !strings.Contains(patch, forbidden), "containerless template must not patch %s: %s", forbidden, patch)
			}
		})
	}
}
