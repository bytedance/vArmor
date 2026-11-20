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

// testRegistry builds an isolated registry containing the built-in adapters
// plus the package's multiTemplateFake. Registry construction is shared via
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

func TestBuildPatch_UnstructuredDeploymentProducesValidPatch(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}}},
			},
		},
	}
	u := toUnstructuredObject(t, deploy)
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
	// A field vArmor does not model must survive untouched because the renderer
	// only reads the object and never writes back to it.
	u.Object["spec"].(map[string]interface{})["xCustomField"] = "preserve-me"

	target := varmor.Target{Kind: "Deployment", Name: "demo"}
	patch, err := buildPatch(u, "AppArmor", varmor.RuntimeDefaultMode, target, nil,
		"varmor-test-demo", varmorpolicy.AuditPolicyIdentity{}, false, false, testRegistry(t))
	assert.NilError(t, err)
	assert.Assert(t, patch != "", "expected a non-empty patch")

	// It must be a syntactically valid JSON Patch array.
	var ops []map[string]interface{}
	assert.NilError(t, json.Unmarshal([]byte(patch), &ops))
	assert.Assert(t, len(ops) >= 2)

	// The unstructured path routes through the built-in adapter and emits the
	// same /spec/template-prefixed AppArmor op as the typed path.
	assert.Assert(t, strings.Contains(patch, "/metadata/annotations"), "root annotations must be ensured: %s", patch)
	assert.Assert(t, strings.Contains(patch,
		"/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1main"),
		"expected template-prefixed AppArmor op: %s", patch)

	assert.Equal(t, u.Object["spec"].(map[string]interface{})["xCustomField"], "preserve-me")
	after := applyAdapterPatch(t, u, patch)
	value, _, err := unstructured.NestedString(after.Object, "spec", "xCustomField")
	assert.NilError(t, err)
	assert.Equal(t, value, "preserve-me")
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
// adapter-supplied prefixes are spliced into patch paths verbatim.
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

func TestBuildPatch_MultiTemplateEmitsOnePatchSetPerRef(t *testing.T) {
	u := multiTemplateObject(t, false)

	target := varmor.Target{Kind: "MultiTemplateCR", Name: "cr"}
	patch, err := buildPatch(u, "AppArmor", varmor.RuntimeDefaultMode, target, nil,
		"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, false, testRegistry(t))
	assert.NilError(t, err)

	// One annotation-ensure op per distinct template path.
	assert.Assert(t, strings.Contains(patch, `"/spec/groups/a/metadata/annotations"`), "missing ref-a ops: %s", patch)
	assert.Assert(t, strings.Contains(patch, `"/spec/groups/b/metadata/annotations"`), "missing ref-b ops: %s", patch)
	// And the AppArmor op is prefixed with each ref path.
	assert.Assert(t, strings.Contains(patch, "/spec/groups/a/metadata/annotations/container.apparmor"))
	assert.Assert(t, strings.Contains(patch, "/spec/groups/b/metadata/annotations/container.apparmor"))
	after := applyAdapterPatch(t, u, patch)
	for _, name := range []string{"a", "b"} {
		value, found, err := unstructured.NestedString(after.Object, "spec", "groups", name, "metadata", "annotations", "container.apparmor.security.beta.kubernetes.io/c")
		assert.NilError(t, err)
		assert.Assert(t, found)
		assert.Equal(t, value, "localhost/varmor-test-cr")
		unknown, _, err := unstructured.NestedString(after.Object, "spec", "groups", name, "spec", "unknownField")
		assert.NilError(t, err)
		assert.Equal(t, unknown, "preserve-me")
	}
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
				patch, err := buildPatch(u, enforcer, varmor.RuntimeDefaultMode, varmor.Target{Kind: "MultiTemplateCR", Name: "cr"}, nil,
					"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, false, testRegistry(t))
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
				}
			})
		}
	}
}

func TestResourceMutation_SelectedCustomErrorsStopPolicyFallback(t *testing.T) {
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
		wantError bool
		wantPatch bool
	}{
		{"valid", func(*unstructured.Unstructured, *admissionv1.AdmissionRequest) {}, false, true},
		{"missing template", func(u *unstructured.Unstructured, _ *admissionv1.AdmissionRequest) {
			unstructured.RemoveNestedField(u.Object, "spec", "groups", "a")
		}, true, false},
		{"malformed template", func(u *unstructured.Unstructured, _ *admissionv1.AdmissionRequest) {
			assert.NilError(t, unstructured.SetNestedField(u.Object, "invalid", "spec", "groups", "a", "spec", "containers"))
		}, true, false},
		{"object group mismatch", func(u *unstructured.Unstructured, _ *admissionv1.AdmissionRequest) { u.SetAPIVersion("other.test/v1") }, true, false},
		{"unregistered request group", func(_ *unstructured.Unstructured, r *admissionv1.AdmissionRequest) { r.Kind.Group = "other.test" }, false, false},
		{"name nonmatch", func(u *unstructured.Unstructured, r *admissionv1.AdmissionRequest) {
			u.SetName("other")
			r.Name = "other"
		}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := multiTemplateObject(t, false)
			r := &admissionv1.AdmissionRequest{UID: "test", Name: "cr", Namespace: "default", Kind: metav1.GroupVersionKind{Group: multiTemplateGVK.Group, Version: multiTemplateGVK.Version, Kind: multiTemplateGVK.Kind}}
			tc.mutate(u, r)
			raw, err := json.Marshal(u)
			assert.NilError(t, err)
			r.Object = runtime.RawExtension{Raw: raw}
			response := ws.resourceMutation(r)
			assert.Equal(t, !response.Allowed, tc.wantError)
			assert.Equal(t, len(response.Patch) > 0, tc.wantPatch)
			if tc.wantError {
				assert.Equal(t, response.Result.Code, int32(http.StatusInternalServerError))
				assert.Equal(t, response.UID, r.UID)
			}
			if tc.wantPatch {
				assert.Assert(t, strings.Contains(string(response.Patch), "apparmor"))
				assert.Assert(t, !strings.Contains(string(response.Patch), "seccomp"))
			}
		})
	}
	// The object carries the adapter's GVK but omits spec.groups, so
	// PodTemplates extraction must fail and surface as a 500.
	badObject := &unstructured.Unstructured{}
	badObject.SetGroupVersionKind(multiTemplateGVK)
	badObject.SetName("cr")
	badRaw, err := json.Marshal(badObject)
	assert.NilError(t, err)
	bad := &admissionv1.AdmissionRequest{UID: "bad", Name: "cr", Namespace: "default", Kind: metav1.GroupVersionKind{Group: multiTemplateGVK.Group, Version: multiTemplateGVK.Version, Kind: multiTemplateGVK.Kind}, Object: runtime.RawExtension{Raw: badRaw}}
	body, err := json.Marshal(admissionv1.AdmissionReview{Request: bad})
	assert.NilError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ws.handlerFunc(ws.resourceMutation)(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusInternalServerError)
}

func TestDeserializeWorkload_ValidatesDecodedIdentity(t *testing.T) {
	ws := &WebhookServer{deserializer: scheme.Codecs.UniversalDeserializer()}
	for _, tc := range []struct {
		kind       string
		group      string
		apiVersion string
	}{
		{"Deployment", "apps", "apps/v1"},
		{"StatefulSet", "apps", "apps/v1"},
		{"DaemonSet", "apps", "apps/v1"},
		{"Pod", "", "v1"},
		{multiTemplateGVK.Kind, multiTemplateGVK.Group, multiTemplateGVK.Group + "/" + multiTemplateGVK.Version},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			a, ok := testRegistry(t).LookupByKind(tc.kind)
			assert.Assert(t, ok)
			request := &admissionv1.AdmissionRequest{
				Kind:   metav1.GroupVersionKind{Group: tc.group, Version: "v1", Kind: tc.kind},
				Object: runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":"demo"}}`, tc.apiVersion, tc.kind))},
			}
			obj, err := ws.deserializeWorkload(request, a)
			assert.NilError(t, err)
			assert.Equal(t, obj.GetObjectKind().GroupVersionKind(), a.GVK())
			request.Kind.Group = "other.test"
			_, err = ws.deserializeWorkload(request, a)
			assert.Assert(t, err != nil, "request/object mismatch must be rejected")
		})
	}
}

func TestBuildPatch_BuiltinTypedAndUnstructuredCompatibility(t *testing.T) {
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
				normalize := func(patch string) string {
					var ops []map[string]interface{}
					assert.NilError(t, json.Unmarshal([]byte(patch), &ops))
					for _, op := range ops {
						if op["path"] == "/metadata/annotations/webhook.varmor.org~1mutatedAt" {
							op["value"] = "TIME"
						}
					}
					normalized, err := json.Marshal(ops)
					assert.NilError(t, err)
					return string(normalized)
				}
				var appsBaseline, podBaseline string
				// Admission decodes every workload as unstructured, so each
				// built-in kind reaches buildPatch through its adapter only.
				for _, obj := range []runtime.Object{deploy, stateful, daemon, pod} {
					target := varmor.Target{Kind: obj.GetObjectKind().GroupVersionKind().Kind, Name: "demo"}
					u := toUnstructuredObject(t, obj)
					patch, err := buildPatch(u, enforcer, varmor.RuntimeDefaultMode, target, nil, "varmor-test-demo", varmorpolicy.AuditPolicyIdentity{}, false, ga, testRegistry(t))
					assert.NilError(t, err)
					assert.Assert(t, patch != "", "expected a non-empty patch for %s/%s", enforcer, target.Kind)
					normalized := normalize(patch)
					if target.Kind == "Pod" {
						// A root Pod splices the empty prefix: every
						// operation addresses the object root, so the
						// workload template prefix must never appear.
						assert.Assert(t, !strings.Contains(normalized, "/spec/template"),
							"root Pod patch must not use the /spec/template prefix: %s", normalized)
						if podBaseline == "" {
							podBaseline = normalized
						}
						assert.Equal(t, normalized, podBaseline)
					} else {
						// The three apps/v1 kinds share the identical
						// /spec/template shape, so their normalized patches
						// must be byte-identical and carry the prefix.
						assert.Assert(t, strings.Contains(normalized, "/spec/template"),
							"%s patch must use the /spec/template prefix: %s", target.Kind, normalized)
						if appsBaseline == "" {
							appsBaseline = normalized
						}
						assert.Equal(t, normalized, appsBaseline)
					}
					applyAdapterPatch(t, u, patch)
				}
				// Both prefix families must have produced a patch set; this
				// guards against a silent empty-patch regression for either.
				assert.Assert(t, appsBaseline != "" && podBaseline != "")
			})
		}
	}
}

func TestBuildPatch_NoTemplates(t *testing.T) {
	adapter := workload.FakeAdapter{
		AdapterName: "no-templates",
		AdapterGVK:  multiTemplateGVK,
		AdapterGVR:  multiTemplateGVR,
	}
	registry := workloadtest.NewRegistry(t, adapter)

	for _, tc := range []struct {
		name     string
		metadata map[string]interface{}
	}{
		{name: "missing metadata"},
		{name: "missing annotations", metadata: map[string]interface{}{"name": "cr"}},
		{name: "empty annotations", metadata: map[string]interface{}{
			"name": "cr", "annotations": map[string]interface{}{},
		}},
		{name: "existing annotations", metadata: map[string]interface{}{
			"name": "cr", "annotations": map[string]interface{}{"existing": "keep"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
			obj.SetGroupVersionKind(adapter.GVK())
			if tc.metadata != nil {
				obj.Object["metadata"] = tc.metadata
			}
			before := obj.DeepCopy()

			patch, err := buildPatch(obj, "AppArmor", varmor.RuntimeDefaultMode,
				varmor.Target{Kind: adapter.GVK().Kind, Name: "cr"}, nil,
				"varmor-test-cr", varmorpolicy.AuditPolicyIdentity{}, false, false, registry)

			assert.NilError(t, err)
			assert.Equal(t, patch, "", "objects without templates must not receive metadata patches")
			assert.Equal(t, classifyPatchResult(patch), dispatchResultPatchSkippedUnconfined)
			assert.DeepEqual(t, obj, before)
		})
	}
}

func TestClassifyPatchResult(t *testing.T) {
	assert.Equal(t, classifyPatchResult(""), dispatchResultPatchSkippedUnconfined)
	assert.Equal(t, classifyPatchResult(`[{"op":"add"}]`), dispatchResultPatched)
}

// overlappingGVK/overlappingGVR identify the adapter that deliberately returns
// overlapping template paths to exercise the custom-adapter guard in buildPatch.
var (
	overlappingGVK = schema.GroupVersionKind{Group: "webhooks.test.varmor.org", Version: "v1", Kind: "OverlapCR"}
	overlappingGVR = schema.GroupVersionResource{Group: "webhooks.test.varmor.org", Version: "v1", Resource: "overlapcrs"}
)

// adapterWithOverlap returns two refs at the same path. The custom-adapter
// loop in buildPatch must reject this before reaching the templateAtPointer
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
// in buildPatch must reject this.
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

func TestExtractTemplateRefs_UnstructuredBuiltins(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}}},
			},
		},
	}
	u := toUnstructuredObject(t, deploy)
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})

	_, refs, err := extractTemplateRefs(u, testRegistry(t))
	assert.NilError(t, err)
	assert.Equal(t, len(refs), 1)
	assert.Equal(t, refs[0].Path, workload.WorkloadTemplatePath)
	assert.Equal(t, refs[0].Template.Spec.Containers[0].Name, "main")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
	}
	pu := toUnstructuredObject(t, pod)
	pu.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"})

	_, prefs, err := extractTemplateRefs(pu, testRegistry(t))
	assert.NilError(t, err)
	assert.Equal(t, len(prefs), 1)
	assert.Equal(t, prefs[0].Path, workload.RootPath)
}

func TestExtractTemplateRefs_UnregisteredUnstructuredKindErrors(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]interface{}{}}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "NoSuchKind"})

	_, _, err := extractTemplateRefs(u, testRegistry(t))
	assert.Assert(t, err != nil, "expected an error for an unregistered Kind")
	assert.Assert(t, strings.Contains(err.Error(), "no workload adapter registered"))
}

func TestExtractTemplateRefs_RoutesByFullGVK(t *testing.T) {
	registry := newVersionedWidgetRegistry(t)
	for _, tc := range []struct {
		name     string
		gvk      schema.GroupVersionKind
		field    string
		wantPath string
	}{
		{"v1 object", widgetV1GVK, "templateV1", "/spec/templateV1"},
		{"v2 object", widgetV2GVK, "templateV2", "/spec/templateV2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
				"apiVersion": %q,
				"kind": "Widget",
				"metadata": {"name": "w"},
				"spec": {%q: {"spec": {"containers": [{"name": "c", "image": "demo"}]}}}
			}`, tc.gvk.GroupVersion().String(), tc.field)
			u := &unstructured.Unstructured{}
			assert.NilError(t, json.Unmarshal([]byte(raw), u))
			u.SetGroupVersionKind(tc.gvk)

			_, refs, err := extractTemplateRefs(u, registry)
			assert.NilError(t, err)
			assert.Equal(t, len(refs), 1)
			assert.Equal(t, refs[0].Path, tc.wantPath)
			assert.Equal(t, refs[0].Template.Spec.Containers[0].Name, "c")
		})
	}

	// An unserved version of a registered Kind must miss instead of falling
	// back to the v1 adapter sharing the same bare Kind.
	miss := &unstructured.Unstructured{}
	miss.SetGroupVersionKind(schema.GroupVersionKind{Group: widgetV1GVK.Group, Version: "v3", Kind: "Widget"})
	_, _, err := extractTemplateRefs(miss, registry)
	assert.Assert(t, err != nil, "unserved version must not resolve to any adapter")
	assert.Assert(t, strings.Contains(err.Error(), "no workload adapter registered"))
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
			// error and surface as a 500 denial, so Allowed plus the
			// version-specific patch path proves version-exact dispatch.
			response := ws.resourceMutation(request)
			assert.Assert(t, response.Allowed, "the matching versioned adapter must handle the request")
			assert.Assert(t, len(response.Patch) > 0, "expected a patch for the selected object")
			patch := string(response.Patch)
			assert.Assert(t, strings.Contains(patch, "/spec/"+tc.ownField), "patch must address the version's own template: %s", patch)
			assert.Assert(t, !strings.Contains(patch, "/spec/"+tc.otherField), "patch must never touch the other version's template: %s", patch)
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
			registry, err := workload.NewRegistry(tc.adapter)
			assert.NilError(t, err)
			u := &unstructured.Unstructured{}
			assert.NilError(t, json.Unmarshal([]byte(tc.json), u))
			patch, err := buildPatch(u, "AppArmor", varmor.RuntimeDefaultMode, varmor.Target{Kind: overlappingGVK.Kind, Name: "o"}, nil,
				"varmor-test-o", varmorpolicy.AuditPolicyIdentity{}, false, false, registry)
			assert.Assert(t, err != nil, "expected overlap rejection for %s, got patch=%q", tc.paths, patch)
			assert.Assert(t, strings.Contains(err.Error(), "overlapping"), "error must mention overlap: %v", err)
		})
	}
}
