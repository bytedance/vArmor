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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	"gotest.tools/assert"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorpolicy "github.com/bytedance/vArmor/internal/policy"
	"github.com/bytedance/vArmor/internal/policycacher"
	"github.com/bytedance/vArmor/pkg/workload"
	"github.com/bytedance/vArmor/pkg/workload/workloadtest"
)

// testRegistry builds an isolated custom-only registry holding just the
// package's multiTemplateFake. Registry construction is shared via
// workloadtest; tests never rely on process-global adapter registration.
func testRegistry(t *testing.T) *workload.Registry {
	t.Helper()
	return workloadtest.NewRegistry(t, newMultiTemplateFake())
}

func toUnstructuredObject(t *testing.T, obj runtime.Object) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	assert.NilError(t, err)
	return &unstructured.Unstructured{Object: m}
}

// multiTemplateGVK/multiTemplateGVR are the fixed identity of the
// multiTemplateFake adapter, declared once so the adapter constructor and all
// request/fixture builders share a single source of truth.
var (
	multiTemplateGVK = schema.GroupVersionKind{Group: "webhooks.test.varmor.org", Version: "v1", Kind: "MultiTemplateCR"}
	multiTemplateGVR = schema.GroupVersionResource{Group: "webhooks.test.varmor.org", Version: "v1", Resource: "multitemplatecrs"}
)

// multiTemplateFake is a custom adapter that exposes two pod templates. It
// embeds workload.FakeAdapter for identity (Name/GVK/GVR and default
// options) and overrides only PodTemplates with the multi-template extraction
// behavior under test. Its bare Kind is unique within the package so it can
// never collide with a built-in adapter. Tests construct it into isolated
// registries rather than relying on any process-global state.
type multiTemplateFake struct {
	workload.FakeAdapter
}

// newMultiTemplateFake builds a multiTemplateFake with its fixed identity.
func newMultiTemplateFake() multiTemplateFake {
	return multiTemplateFake{FakeAdapter: workload.FakeAdapter{
		AdapterName: "multitemplate",
		AdapterGVK:  multiTemplateGVK,
		AdapterGVR:  multiTemplateGVR,
	}}
}

// PodTemplates walks the CRD-specific spec.groups map. The field is
// intentionally named "groups": the tests prove that arbitrary
// adapter-supplied template paths are spliced into patch paths verbatim.
func (multiTemplateFake) PodTemplates(obj *unstructured.Unstructured) ([]workload.PodTemplateRef, error) {
	var refs []workload.PodTemplateRef
	for _, name := range []string{"a", "b"} {
		m, found, err := unstructured.NestedMap(obj.Object, "spec", "groups", name)
		if err != nil || !found {
			return nil, fmt.Errorf("missing template %s", name)
		}
		template := &corev1.PodTemplateSpec{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, template); err != nil {
			return nil, err
		}
		refs = append(refs, workload.PodTemplateRef{Path: "/spec/groups/" + name, Template: template})
	}
	return refs, nil
}

func multiTemplateObject(t *testing.T, metadata bool) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	// Unstructured.UnmarshalJSON goes through UnstructuredJSONScheme.Decode,
	// which rejects raw JSON missing apiVersion/kind just like a real
	// AdmissionRequest payload; calling SetGroupVersionKind afterwards cannot
	// repair an object whose UnmarshalJSON already failed.
	assert.NilError(t, json.Unmarshal([]byte(fmt.Sprintf(`{
		"apiVersion":%q,
		"kind":%q,
		"metadata":{"name":"cr"},
		"spec":{"unknown":"keep","groups":{
			"a":{"spec":{"containers":[{"name":"c","image":"demo","unknownContainer":"keep"}],"unknownField":"preserve-me"}},
			"b":{"spec":{"containers":[{"name":"c","image":"demo","unknownContainer":"keep"}],"unknownField":"preserve-me"}}
		}}}`, multiTemplateGVK.GroupVersion().String(), multiTemplateGVK.Kind)), u))
	u.SetGroupVersionKind(multiTemplateGVK)
	if metadata {
		for _, name := range []string{"a", "b"} {
			assert.NilError(t, unstructured.SetNestedMap(u.Object, map[string]interface{}{"labels": map[string]interface{}{"existing": "keep"}}, "spec", "groups", name, "metadata"))
		}
	}
	return u
}

func applyAdapterPatch(t *testing.T, u *unstructured.Unstructured, patch string) *unstructured.Unstructured {
	t.Helper()
	raw, err := json.Marshal(u)
	assert.NilError(t, err)
	decoded, err := jsonpatch.DecodePatch([]byte(patch))
	assert.NilError(t, err)
	result, err := decoded.Apply(raw)
	assert.NilError(t, err)
	after := &unstructured.Unstructured{}
	assert.NilError(t, json.Unmarshal(result, after))
	return after
}

func TestBuildPatch_CustomTemplatesApplyAllEnforcers(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		for _, enforcer := range []string{"AppArmor", "BPF", "Seccomp", "AppArmorSeccomp", "NetworkProxy"} {
			t.Run(fmt.Sprintf("%s/metadata=%t", enforcer, metadata), func(t *testing.T) {
				u := multiTemplateObject(t, metadata)
				patch, err := buildCustomPatch(u, newMultiTemplateFake(), enforcer, varmor.RuntimeDefaultMode,
					varmor.Target{Kind: "MultiTemplateCR", Name: "cr"}, nil,
					"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, false)
				assert.NilError(t, err)
				after := applyAdapterPatch(t, u, patch)
				for _, name := range []string{"a", "b"} {
					unknown, _, err := unstructured.NestedString(after.Object, "spec", "groups", name, "spec", "unknownField")
					assert.NilError(t, err)
					assert.Equal(t, unknown, "preserve-me")
					containers, _, err := unstructured.NestedSlice(after.Object, "spec", "groups", name, "spec", "containers")
					assert.NilError(t, err)
					assert.Equal(t, containers[0].(map[string]interface{})["unknownContainer"], interface{}("keep"))
					if metadata {
						label, _, err := unstructured.NestedString(after.Object, "spec", "groups", name, "metadata", "labels", "existing")
						assert.NilError(t, err)
						assert.Equal(t, label, "keep")
					}
					// AppArmor uniquely proves per-ref path splicing: one
					// annotation-ensure op and one profile op per template.
					if enforcer == "AppArmor" {
						assert.Assert(t, strings.Contains(patch, fmt.Sprintf(`"/spec/groups/%s/metadata/annotations"`, name)), "missing ref-%s ops: %s", name, patch)
						assert.Assert(t, strings.Contains(patch, fmt.Sprintf("/spec/groups/%s/metadata/annotations/container.apparmor", name)))
						value, found, err := unstructured.NestedString(after.Object, "spec", "groups", name, "metadata", "annotations", "container.apparmor.security.beta.kubernetes.io/c")
						assert.NilError(t, err)
						assert.Assert(t, found)
						assert.Equal(t, value, "localhost/varmor-test-cr")
					}
				}
			})
		}
	}
}

// TestBuildPatch_SkipsTemplatesWithoutContainers covers templates whose raw
// JSON has no usable spec.containers array: without the guard the NetworkProxy
// add-ops target non-existent nodes, so the API server rejects the request
// even under failurePolicy: Ignore. Skipped templates receive no ops,
// siblings are still injected, and an all-skipped object returns an empty
// patch so it is counted as patch_skipped_unconfined.
func TestBuildPatch_SkipsTemplatesWithoutContainers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		allSkipped bool
		mutate     func(*unstructured.Unstructured)
	}{
		{
			name: "template node without spec",
			mutate: func(u *unstructured.Unstructured) {
				unstructured.RemoveNestedField(u.Object, "spec", "groups", "a", "spec")
			},
		},
		{
			name: "spec without containers",
			mutate: func(u *unstructured.Unstructured) {
				assert.NilError(t, unstructured.SetNestedField(u.Object, map[string]interface{}{}, "spec", "groups", "a", "spec"))
			},
		},
		{
			name: "empty containers array",
			mutate: func(u *unstructured.Unstructured) {
				assert.NilError(t, unstructured.SetNestedField(u.Object, []interface{}{}, "spec", "groups", "a", "spec", "containers"))
			},
		},
		{
			name:       "all templates without spec",
			allSkipped: true,
			mutate: func(u *unstructured.Unstructured) {
				unstructured.RemoveNestedField(u.Object, "spec", "groups", "a", "spec")
				unstructured.RemoveNestedField(u.Object, "spec", "groups", "b", "spec")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := multiTemplateObject(t, false)
			tc.mutate(u)
			patch, err := buildCustomPatch(u, newMultiTemplateFake(), "NetworkProxy", varmor.RuntimeDefaultMode,
				varmor.Target{Kind: "MultiTemplateCR", Name: "cr"}, nil,
				"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, false)
			assert.NilError(t, err)
			if tc.allSkipped {
				assert.Equal(t, patch, "", "objects whose templates all lack containers must stay unmutated")
				return
			}
			// Fails if the patch cannot apply — the missing-node 500 this
			// guard exists to prevent.
			after := applyAdapterPatch(t, u, patch)
			assert.Assert(t, !strings.Contains(patch, "/spec/groups/a/"), "empty template must receive no ops: %s", patch)
			assert.Assert(t, strings.Contains(patch, "/spec/groups/b/spec/initContainers"), "sibling template must still be injected: %s", patch)
			containers, _, err := unstructured.NestedSlice(after.Object, "spec", "groups", "b", "spec", "containers")
			assert.NilError(t, err)
			assert.Equal(t, len(containers), 2, "original container plus the injected Envoy sidecar")
		})
	}
}

// TestResourceMutation_SelectedCustomErrorsFailOpen verifies that a custom
// adapter decode or template-extraction failure never denies admission. The
// error is logged and counted, matchAndPatchCustom returns nil, and
// resourceMutation keeps walking the remaining matching policies before
// admitting the object unmutated — the same fail-open/fallback convention the
// built-in kinds have always used. Only a fully selected, valid object is
// mutated.
func TestResourceMutation_SelectedCustomErrorsFailOpen(t *testing.T) {
	target := varmor.Target{Kind: "MultiTemplateCR", Name: "cr"}
	ws := &WebhookServer{log: logr.Discard(), registry: testRegistry(t), policyCacher: &policycacher.PolicyCacher{
		ClusterPolicyTargets:  map[string]varmor.Target{"cluster": target},
		ClusterPolicyEnforcer: map[string]string{"cluster": "AppArmor"},
		PolicyTargets:         map[string]varmor.Target{"default/lower": target},
		PolicyEnforcer:        map[string]string{"default/lower": "Seccomp"},
	}}
	for _, tc := range []struct {
		name      string
		mutate    func(*unstructured.Unstructured, *admissionv1.AdmissionRequest)
		wantPatch bool
	}{
		{"valid", func(*unstructured.Unstructured, *admissionv1.AdmissionRequest) {}, true},
		{"missing template", func(u *unstructured.Unstructured, _ *admissionv1.AdmissionRequest) {
			unstructured.RemoveNestedField(u.Object, "spec", "groups", "a")
		}, false},
		{"malformed template", func(u *unstructured.Unstructured, _ *admissionv1.AdmissionRequest) {
			assert.NilError(t, unstructured.SetNestedField(u.Object, "invalid", "spec", "groups", "a", "spec", "containers"))
		}, false},
		{"object group mismatch", func(u *unstructured.Unstructured, _ *admissionv1.AdmissionRequest) { u.SetAPIVersion("other.test/v1") }, false},
		{"unregistered request group", func(_ *unstructured.Unstructured, r *admissionv1.AdmissionRequest) { r.Kind.Group = "other.test" }, false},
		{"name nonmatch", func(u *unstructured.Unstructured, r *admissionv1.AdmissionRequest) {
			u.SetName("other")
			r.Name = "other"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := multiTemplateObject(t, false)
			r := &admissionv1.AdmissionRequest{UID: "test", Name: "cr", Namespace: "default", Kind: metav1.GroupVersionKind{Group: multiTemplateGVK.Group, Version: multiTemplateGVK.Version, Kind: multiTemplateGVK.Kind}}
			tc.mutate(u, r)
			raw, err := json.Marshal(u)
			assert.NilError(t, err)
			r.Object = runtime.RawExtension{Raw: raw}
			response := ws.resourceMutation(r)
			// Every terminal outcome is an in-protocol Allowed response: a
			// processing failure fails open rather than returning a denial.
			assert.Assert(t, response.Allowed, "custom processing errors must fail open")
			assert.Equal(t, response.UID, r.UID)
			assert.Equal(t, len(response.Patch) > 0, tc.wantPatch)
			if tc.wantPatch {
				assert.Assert(t, strings.Contains(string(response.Patch), "apparmor"))
				assert.Assert(t, !strings.Contains(string(response.Patch), "seccomp"))
			}

			// The same request through the HTTP wrapper must answer 200 with
			// an Allowed review even when processing fails open.
			body, err := json.Marshal(admissionv1.AdmissionReview{Request: r})
			assert.NilError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			ws.handlerFunc(ws.resourceMutation)(recorder, req)
			assert.Equal(t, recorder.Code, http.StatusOK)
			var review admissionv1.AdmissionReview
			assert.NilError(t, json.Unmarshal(recorder.Body.Bytes(), &review))
			assert.Assert(t, review.Response.Allowed)
			assert.Equal(t, len(review.Response.Patch) > 0, tc.wantPatch)
		})
	}
}

// TestMatchAndPatchCustom_MalformedSelectorFailsOpen covers the selector
// parse branch: policies are admitted without parsing their label selector,
// so an invalid selector operator can reach dispatch. The custom path must
// keep its fail-open contract (nil response, object admitted unmutated) while
// recording the selector_error dispatch result; with metrics disabled the
// recorder is a nil-safe no-op.
func TestMatchAndPatchCustom_MalformedSelectorFailsOpen(t *testing.T) {
	ws := &WebhookServer{log: logr.Discard(), registry: testRegistry(t), policyCacher: &policycacher.PolicyCacher{
		PolicyEnforcer: map[string]string{"default/lower": "AppArmor"},
	}}
	target := varmor.Target{
		Kind: "MultiTemplateCR",
		Selector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: "Bogus"},
			},
		},
	}

	raw, err := json.Marshal(multiTemplateObject(t, false))
	assert.NilError(t, err)
	request := &admissionv1.AdmissionRequest{
		UID:       "test",
		Name:      "cr",
		Namespace: "default",
		Kind:      metav1.GroupVersionKind{Group: multiTemplateGVK.Group, Version: multiTemplateGVK.Version, Kind: multiTemplateGVK.Kind},
		Object:    runtime.RawExtension{Raw: raw},
	}

	response := ws.matchAndPatchCustom(request, "default/lower", target, logr.Discard(),
		"default", "lower", false, varmorpolicy.AuditPolicyIdentity{})
	assert.Assert(t, response == nil, "a malformed selector must fail open with no patch")
}

// TestDeserializeWorkload_NativeKindsDecodeTyped iterates the shared
// workload.BuiltInKinds set — making this a drift detector for a fifth
// native Kind — and asserts each one decodes typed with no adapter lookup.
func TestDeserializeWorkload_NativeKindsDecodeTyped(t *testing.T) {
	ws := &WebhookServer{deserializer: scheme.Codecs.UniversalDeserializer()}
	nativeGroups := map[string]struct {
		group      string
		apiVersion string
	}{
		"Pod":         {"", "v1"},
		"Deployment":  {"apps", "apps/v1"},
		"StatefulSet": {"apps", "apps/v1"},
		"DaemonSet":   {"apps", "apps/v1"},
	}
	for _, kind := range workload.BuiltInKinds() {
		meta, ok := nativeGroups[kind]
		assert.Assert(t, ok, "Kind %q in workload.BuiltInKinds needs native decode/patch metadata in this test", kind)
		t.Run(kind, func(t *testing.T) {
			request := &admissionv1.AdmissionRequest{
				Kind:   metav1.GroupVersionKind{Group: meta.group, Version: "v1", Kind: kind},
				Object: runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":"demo"}}`, meta.apiVersion, kind))},
			}
			obj, err := ws.deserializeWorkload(request)
			assert.NilError(t, err)
			decoded, ok := obj.(runtime.Object)
			assert.Assert(t, ok)
			expected := schema.GroupVersionKind{Group: meta.group, Version: "v1", Kind: kind}
			assert.Equal(t, decoded.GetObjectKind().GroupVersionKind(), expected)
		})
	}

	// A non-built-in Kind must fail both native switches.
	unknown := &admissionv1.AdmissionRequest{
		Kind:   metav1.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"},
		Object: runtime.RawExtension{Raw: []byte(`{"apiVersion":"batch/v1","kind":"Job"}`)},
	}
	obj, err := ws.deserializeWorkload(unknown)
	assert.Assert(t, obj == nil)
	assert.ErrorContains(t, err, "unsupported kind")
	_, err = buildNativePatch(nil, "AppArmor", varmor.EnhanceProtectMode, varmor.Target{Kind: "Job"},
		nil, "demo", varmorpolicy.AuditPolicyIdentity{}, false, false)
	assert.ErrorContains(t, err, `unsupported workload kind "Job"`)
}

// TestDeserializeCustomWorkload_ValidatesDecodedIdentity covers the custom
// path's unstructured decode: the in-payload GVK must match both the
// admission request and the adapter selected for that GVK, and a request
// drift is returned as an error which the caller logs, counts as
// decode_error and fails open (the object is admitted unmutated).
func TestDeserializeCustomWorkload_ValidatesDecodedIdentity(t *testing.T) {
	adapter, ok := testRegistry(t).LookupGVK(multiTemplateGVK)
	assert.Assert(t, ok)
	request := &admissionv1.AdmissionRequest{
		Kind:   metav1.GroupVersionKind{Group: multiTemplateGVK.Group, Version: multiTemplateGVK.Version, Kind: multiTemplateGVK.Kind},
		Object: runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":"demo"}}`, multiTemplateGVK.GroupVersion().String(), multiTemplateGVK.Kind))},
	}
	obj, err := deserializeCustomWorkload(request, adapter)
	assert.NilError(t, err)
	assert.Equal(t, obj.GetObjectKind().GroupVersionKind(), adapter.GVK())

	request.Kind.Group = "other.test"
	_, err = deserializeCustomWorkload(request, adapter)
	assert.Assert(t, err != nil, "request/object mismatch must be rejected")
}

// TestBuildNativePatch_TypedKindsProduceIdenticalTemplatePatch proves the
// shared buildPodTemplatePatch injection gives the four typed native kinds
// their historical output: the three apps/v1 kinds share one /spec/template
// shape and emit byte-identical normalized patches, while a root Pod splices
// the empty template path. Every generated patch must also apply cleanly to
// the object's unstructured form.
func TestBuildNativePatch_TypedKindsProduceIdenticalTemplatePatch(t *testing.T) {
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "demo"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "demo"}}},
	}
	for _, enforcer := range []string{"AppArmor", "BPF", "Seccomp", "AppArmorSeccomp", "NetworkProxy"} {
		for _, ga := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/GA=%t", enforcer, ga), func(t *testing.T) {
				meta := metav1.ObjectMeta{Name: "demo"}
				deploy := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta, Spec: appsv1.DeploymentSpec{Template: template}}
				stateful := &appsv1.StatefulSet{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "StatefulSet"}, ObjectMeta: meta, Spec: appsv1.StatefulSetSpec{Template: template}}
				daemon := &appsv1.DaemonSet{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"}, ObjectMeta: meta, Spec: appsv1.DaemonSetSpec{Template: template}}
				pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta, Spec: template.Spec}
				var appsBaseline, podBaseline string
				// Native kinds stay typed end-to-end: buildNativePatch takes
				// the decoded object and dispatches on target.Kind.
				for _, obj := range []runtime.Object{deploy, stateful, daemon, pod} {
					target := varmor.Target{Kind: obj.GetObjectKind().GroupVersionKind().Kind, Name: "demo"}
					patch, err := buildNativePatch(obj, enforcer, varmor.RuntimeDefaultMode, target, nil, "varmor-test-demo", varmorpolicy.AuditPolicyIdentity{}, false, ga)
					assert.NilError(t, err)
					assert.Assert(t, patch != "", "expected a non-empty patch for %s/%s", enforcer, target.Kind)
					if strings.Contains(patch, "1mutatedAt") {
						index := strings.Index(patch, `1mutatedAt", "value": `)
						patch = patch[:index+len(`1mutatedAt", "value": `)] + `"TIME_STRING"}]`
					}
					if target.Kind == "Pod" {
						// A root Pod splices the empty template path: every
						// operation addresses the object root, so the
						// workload template path must never appear.
						assert.Assert(t, !strings.Contains(patch, "/spec/template"),
							"root Pod patch must not contain the /spec/template path: %s", patch)
						if podBaseline == "" {
							podBaseline = patch
						}
						assert.Equal(t, patch, podBaseline)
					} else {
						// The three apps/v1 kinds share the identical
						// /spec/template shape, so their normalized patches
						// must be byte-identical and address the same template path.
						assert.Assert(t, strings.Contains(patch, "/spec/template"),
							"%s patch must use the /spec/template template path: %s", target.Kind, patch)
						if appsBaseline == "" {
							appsBaseline = patch
						}
						assert.Equal(t, patch, appsBaseline)
					}
					after := applyAdapterPatch(t, toUnstructuredObject(t, obj), patch)
					// AppArmor on the pre-GA (beta annotation) path addition-
					// ally proves the applied annotation carries the resolved
					// profile name under the right template path; GA delivers
					// it through securityContext instead, which the
					// byte-identical patch comparison above already covers.
					if enforcer == "AppArmor" && !ga {
						fields := []string{"metadata", "annotations", "container.apparmor.security.beta.kubernetes.io/main"}
						if target.Kind != "Pod" {
							fields = append([]string{"spec", "template"}, fields...)
						}
						value, found, err := unstructured.NestedString(after.Object, fields...)
						assert.NilError(t, err)
						assert.Assert(t, found)
						assert.Equal(t, value, "localhost/varmor-test-demo")
					}
				}
				// Both template path families must have produced a patch set;
				// this guards against a silent empty-patch regression for either.
				assert.Assert(t, appsBaseline != "" && podBaseline != "")
			})
		}
	}
}

// TestBuildPatch_NoTemplates covers the len(refs)==0 early return: an
// adapter supplying no templates means no injection, so the object (including
// a pre-populated annotations map) must be left untouched. The return happens
// before metadata is inspected, so separate metadata variants would be
// behaviorally identical.
func TestBuildPatch_NoTemplates(t *testing.T) {
	adapter := workload.FakeAdapter{
		AdapterName: "no-templates",
		AdapterGVK:  multiTemplateGVK,
		AdapterGVR:  multiTemplateGVR,
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": "cr", "annotations": map[string]interface{}{"existing": "keep"}},
	}}
	obj.SetGroupVersionKind(adapter.GVK())
	before := obj.DeepCopy()

	patch, err := buildCustomPatch(obj, adapter, "AppArmor", varmor.RuntimeDefaultMode,
		varmor.Target{Kind: adapter.GVK().Kind, Name: "cr"}, nil,
		"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, false)

	assert.NilError(t, err)
	assert.Equal(t, patch, "", "objects without templates must not receive metadata patches")
	assert.DeepEqual(t, obj, before)
}

// overlappingGVK/overlappingGVR identify the adapter that deliberately returns
// overlapping template paths to exercise the custom-adapter guard in buildCustomPatch.
var (
	overlappingGVK = schema.GroupVersionKind{Group: "webhooks.test.varmor.org", Version: "v1", Kind: "OverlapCR"}
	overlappingGVR = schema.GroupVersionResource{Group: "webhooks.test.varmor.org", Version: "v1", Resource: "overlapcrs"}
)

// adapterWithOverlap returns two refs at the same path. The custom-adapter
// loop in buildCustomPatch must reject this before reaching the templateAtPointer
// call on the second ref.
type adapterWithOverlap struct {
	workload.FakeAdapter
}

func (adapterWithOverlap) PodTemplates(obj *unstructured.Unstructured) ([]workload.PodTemplateRef, error) {
	m, found, err := unstructured.NestedMap(obj.Object, "spec", "template")
	if err != nil || !found {
		return nil, fmt.Errorf("missing spec.template")
	}
	tmpl := &corev1.PodTemplateSpec{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, tmpl); err != nil {
		return nil, err
	}
	return []workload.PodTemplateRef{
		{Path: "/spec/template", Template: tmpl},
		{Path: "/spec/template", Template: tmpl}, // duplicate path — must be rejected
	}, nil
}

// adapterWithNestedOverlap returns parent/child paths. The HasPrefix guards
// in buildCustomPatch must reject this.
type adapterWithNestedOverlap struct {
	workload.FakeAdapter
}

func (adapterWithNestedOverlap) PodTemplates(obj *unstructured.Unstructured) ([]workload.PodTemplateRef, error) {
	parent, found, err := unstructured.NestedMap(obj.Object, "spec", "parent")
	if err != nil || !found {
		return nil, fmt.Errorf("missing spec.parent")
	}
	child, found, err := unstructured.NestedMap(obj.Object, "spec", "parent", "child")
	if err != nil || !found {
		return nil, fmt.Errorf("missing spec.parent.child")
	}
	parentTmpl := &corev1.PodTemplateSpec{}
	childTmpl := &corev1.PodTemplateSpec{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(parent, parentTmpl); err != nil {
		return nil, err
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(child, childTmpl); err != nil {
		return nil, err
	}
	return []workload.PodTemplateRef{
		{Path: "/spec/parent", Template: parentTmpl},
		{Path: "/spec/parent/child", Template: childTmpl}, // child of previous — must be rejected
	}, nil
}

// Multi-version routing fixtures. The two adapters serve different versions
// of one CRD (same API group, bare Kind and REST resource) and keep their pod
// template under a version-specific field. A wrong-version dispatch therefore
// fails inside PodTemplates instead of silently producing a plausible patch.
var (
	widgetV1GVK = schema.GroupVersionKind{Group: "webhooks.test.varmor.org", Version: "v1", Kind: "Widget"}
	widgetV2GVK = schema.GroupVersionKind{Group: "webhooks.test.varmor.org", Version: "v2", Kind: "Widget"}
	widgetV1GVR = schema.GroupVersionResource{Group: "webhooks.test.varmor.org", Version: "v1", Resource: "widgets"}
	widgetV2GVR = schema.GroupVersionResource{Group: "webhooks.test.varmor.org", Version: "v2", Resource: "widgets"}
)

type versionedWidgetFake struct {
	workload.FakeAdapter
	version string
}

func (f versionedWidgetFake) templateField() string {
	return "template" + strings.ToUpper(f.version)
}

func (f versionedWidgetFake) PodTemplates(obj *unstructured.Unstructured) ([]workload.PodTemplateRef, error) {
	field := f.templateField()
	m, found, err := unstructured.NestedMap(obj.Object, "spec", field)
	if err != nil || !found {
		return nil, fmt.Errorf("version %s adapter requires spec.%s", f.version, field)
	}
	tmpl := &corev1.PodTemplateSpec{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, tmpl); err != nil {
		return nil, err
	}
	return []workload.PodTemplateRef{{Path: "/spec/" + field, Template: tmpl}}, nil
}

func newVersionedWidgetRegistry(t *testing.T) *workload.Registry {
	t.Helper()
	v1 := versionedWidgetFake{
		FakeAdapter: workload.FakeAdapter{AdapterName: "widget-v1", AdapterGVK: widgetV1GVK, AdapterGVR: widgetV1GVR},
		version:     "v1",
	}
	v2 := versionedWidgetFake{
		FakeAdapter: workload.FakeAdapter{AdapterName: "widget-v2", AdapterGVK: widgetV2GVK, AdapterGVR: widgetV2GVR},
		version:     "v2",
	}
	registry, err := workload.NewRegistry(v1, v2)
	assert.NilError(t, err)
	return registry
}

func TestResourceMutation_MultiVersionRoutesVersionExact(t *testing.T) {
	registry := newVersionedWidgetRegistry(t)
	target := varmor.Target{Kind: "Widget", Name: "w"}
	ws := &WebhookServer{
		log:      logr.Discard(),
		registry: registry,
		policyCacher: &policycacher.PolicyCacher{
			PolicyTargets:  map[string]varmor.Target{"default/widget-policy": target},
			PolicyEnforcer: map[string]string{"default/widget-policy": "AppArmor"},
		},
	}

	for _, tc := range []struct {
		name       string
		gvk        schema.GroupVersionKind
		ownField   string
		otherField string
	}{
		{"v1 admission", widgetV1GVK, "templateV1", "templateV2"},
		{"v2 admission", widgetV2GVK, "templateV2", "templateV1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"apiVersion": %q,
				"kind": "Widget",
				"metadata": {"name": "w"},
				"spec": {%q: {"spec": {"containers": [{"name": "c", "image": "demo"}]}}}
			}`, tc.gvk.GroupVersion().String(), tc.ownField))
			request := &admissionv1.AdmissionRequest{
				UID:       "test",
				Name:      "w",
				Namespace: "default",
				Kind:      metav1.GroupVersionKind{Group: tc.gvk.Group, Version: tc.gvk.Version, Kind: tc.gvk.Kind},
				Object:    runtime.RawExtension{Raw: raw},
			}

			// A wrong-version route would hit the other adapter's missing-field
			// error and fail open without a patch, so an Allowed response
			// carrying the version-specific patch path proves version-exact
			// dispatch.
			response := ws.resourceMutation(request)
			assert.Assert(t, response.Allowed, "the matching versioned adapter must handle the request")
			assert.Assert(t, len(response.Patch) > 0, "expected a patch for the selected object")
			patch := string(response.Patch)
			assert.Assert(t, strings.Contains(patch, "/spec/"+tc.ownField), "patch must address the version's own template: %s", patch)
			assert.Assert(t, !strings.Contains(patch, "/spec/"+tc.otherField), "patch must never touch the other version's template: %s", patch)
			// The AppArmor op keyed on container "c" proves the adapter
			// decoded its version-specific template into a PodTemplateSpec
			// rather than splicing an empty shell.
			assert.Assert(t, strings.Contains(patch, "container.apparmor.security.beta.kubernetes.io~1c"), patch)
		})
	}

	// A registered Kind at an unserved version passes through unmutated: the
	// registry has no v3 adapter, and lookup must not fall through to v1.
	unserved := &admissionv1.AdmissionRequest{
		UID:       "unserved",
		Name:      "w",
		Namespace: "default",
		Kind:      metav1.GroupVersionKind{Group: widgetV1GVK.Group, Version: "v3", Kind: "Widget"},
		Object: runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{
			"apiVersion": %q,
			"kind": "Widget",
			"metadata": {"name": "w"},
			"spec": {"templateV1": {"spec": {"containers": [{"name": "c"}]}}}
		}`, widgetV1GVK.Group+"/v3"))},
	}
	response := ws.resourceMutation(unserved)
	assert.Assert(t, response.Allowed)
	assert.Equal(t, len(response.Patch), 0)
}

func TestBuildPatch_CustomAdaptersRejectOverlappingPaths(t *testing.T) {
	for _, tc := range []struct {
		name    string
		adapter workload.Adapter
		paths   string
		json    string // raw JSON for the admission object; both adapter and content share this GVK
	}{
		{
			name:    "duplicate path",
			adapter: adapterWithOverlap{FakeAdapter: workload.FakeAdapter{AdapterName: "overlap-dup", AdapterGVK: overlappingGVK, AdapterGVR: overlappingGVR}},
			paths:   "/spec/template twice",
			json:    `{"apiVersion":"webhooks.test.varmor.org/v1","kind":"OverlapCR","metadata":{"name":"o"},"spec":{"template":{"spec":{"containers":[{"name":"c"}]}}}}`,
		},
		{
			name:    "parent/child paths",
			adapter: adapterWithNestedOverlap{FakeAdapter: workload.FakeAdapter{AdapterName: "overlap-nest", AdapterGVK: overlappingGVK, AdapterGVR: overlappingGVR}},
			paths:   "/spec/parent and /spec/parent/child",
			json:    `{"apiVersion":"webhooks.test.varmor.org/v1","kind":"OverlapCR","metadata":{"name":"o"},"spec":{"parent":{"spec":{"containers":[{"name":"p"}]},"child":{"spec":{"containers":[{"name":"c"}]}}}}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &unstructured.Unstructured{}
			assert.NilError(t, json.Unmarshal([]byte(tc.json), u))
			patch, err := buildCustomPatch(u, tc.adapter, "AppArmor", varmor.RuntimeDefaultMode, varmor.Target{Kind: overlappingGVK.Kind, Name: "o"}, nil,
				"varmor-test-o", varmorpolicy.AuditPolicyIdentity{}, false, false)
			assert.Assert(t, err != nil, "expected overlap rejection for %s, got patch=%q", tc.paths, patch)
			assert.Assert(t, strings.Contains(err.Error(), "overlapping"), "error must mention overlap: %v", err)
		})
	}
}

// TestBuildPatch_NullTemplateAnnotationsStillPrimed covers an explicit
// "annotations": null node: a key-presence check treats null as present and
// skips priming, so annotation child ops fail to traverse it and the request
// is rejected even under failurePolicy: Ignore. The guard must type-assert
// the node and prime an empty map, producing a patch that applies end to end.
func TestBuildPatch_NullTemplateAnnotationsStillPrimed(t *testing.T) {
	u := multiTemplateObject(t, true)
	// Set an explicit JSON null while keeping the surrounding metadata node.
	assert.NilError(t, unstructured.SetNestedField(u.Object, nil, "spec", "groups", "a", "metadata", "annotations"))

	patch, err := buildCustomPatch(u, newMultiTemplateFake(), "AppArmor", varmor.RuntimeDefaultMode,
		varmor.Target{Kind: "MultiTemplateCR", Name: "cr"}, nil,
		"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, true)
	assert.NilError(t, err)
	assert.Assert(t, strings.Contains(patch, `"/spec/groups/a/metadata/annotations"`),
		"the null annotations node must be primed: %s", patch)

	// Fails if any op cannot apply — the exact rejection this guard prevents.
	after := applyAdapterPatch(t, u, patch)
	value, found, err := unstructured.NestedString(after.Object, "spec", "groups", "a", "metadata", "annotations", "container.apparmor.security.beta.varmor.org/c")
	assert.NilError(t, err)
	assert.Assert(t, found, "apparmor annotation must land under the primed map")
	assert.Equal(t, value, "localhost/varmor-test-cr")
}

// capturingLogSink records Info-level messages so tests can assert on
// operator-facing warnings without pulling in a full logging stack.
type capturingLogSink struct {
	infoMessages []string
}

func (s *capturingLogSink) Init(logr.RuntimeInfo) {}

// Enabled captures operator-visible Info-level (V0) messages only; V(2)
// debug logging such as "policy matching" must not pollute the assertions.
func (s *capturingLogSink) Enabled(level int) bool { return level == 0 }
func (s *capturingLogSink) Info(_ int, msg string, _ ...interface{}) {
	s.infoMessages = append(s.infoMessages, msg)
}
func (s *capturingLogSink) Error(error, string, ...interface{})    {}
func (s *capturingLogSink) WithValues(...interface{}) logr.LogSink { return s }
func (s *capturingLogSink) WithName(string) logr.LogSink           { return s }

// TestMatchAndPatch_ClusterScopedResourceGate covers the impossible cell:
// a namespaced VarmorPolicy against a cluster-scoped object (Namespace="")
// fails open with an actionable warning, while Kind mismatches, ordinary
// cross-namespace skips and cluster policies stay silent.
func TestMatchAndPatch_ClusterScopedResourceGate(t *testing.T) {
	const kind = "ClusterWidget"
	target := varmor.Target{Kind: kind, Name: "global"}
	buildRequest := func(namespace string) *admissionv1.AdmissionRequest {
		return &admissionv1.AdmissionRequest{
			UID:       "test",
			Name:      "global",
			Namespace: namespace,
			Kind:      metav1.GroupVersionKind{Group: "example.com", Version: "v1", Kind: kind},
		}
	}

	t.Run("namespaced policy vs cluster-scoped object warns and skips", func(t *testing.T) {
		sink := &capturingLogSink{}
		ws := &WebhookServer{log: logr.Discard()}
		response := ws.matchAndPatch(buildRequest(""), "default/p", target, logr.New(sink))
		assert.Assert(t, response == nil, "the impossible cell must fail open with no patch")
		assert.Equal(t, len(sink.infoMessages), 1)
		assert.Assert(t, strings.Contains(sink.infoMessages[0], "VarmorClusterPolicy"))
	})

	t.Run("Kind mismatch stays silent", func(t *testing.T) {
		sink := &capturingLogSink{}
		ws := &WebhookServer{log: logr.Discard()}
		other := varmor.Target{Kind: "SomethingElse", Name: "global"}
		response := ws.matchAndPatch(buildRequest(""), "default/p", other, logr.New(sink))
		assert.Assert(t, response == nil)
		assert.Equal(t, len(sink.infoMessages), 0)
	})

	t.Run("ordinary cross-namespace skip stays silent", func(t *testing.T) {
		sink := &capturingLogSink{}
		ws := &WebhookServer{log: logr.Discard()}
		response := ws.matchAndPatch(buildRequest("other-ns"), "default/p", target, logr.New(sink))
		assert.Assert(t, response == nil)
		assert.Equal(t, len(sink.infoMessages), 0)
	})

	t.Run("cluster policy passes the gate without warning", func(t *testing.T) {
		sink := &capturingLogSink{}
		// An empty registry makes the later custom dispatch miss cleanly;
		// the assertion is that the gate neither warns nor blocks the call.
		ws := &WebhookServer{log: logr.Discard(), registry: workloadtest.NewRegistry(t)}
		response := ws.matchAndPatch(buildRequest(""), "cluster-p", target, logr.New(sink))
		assert.Assert(t, response == nil)
		assert.Equal(t, len(sink.infoMessages), 0)
	})
}
