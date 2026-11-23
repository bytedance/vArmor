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
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorpolicy "github.com/bytedance/vArmor/internal/policy"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	"github.com/bytedance/vArmor/pkg/workload"
)

// matchAndPatchCustom handles custom resources through the adapter registry.
// It decodes as unstructured (the manager has no typed model for downstream
// CRDs) and records every terminal dispatch outcome in the adapter-dispatch
// metric. Processing failures follow the same fail-open convention as the
// built-in kinds: the error is logged and counted, then the handler returns
// nil so resourceMutation keeps walking the remaining matching policies and
// the object is admitted unmutated rather than denied. A request whose full
// GVK no adapter serves passes through unmutated and is deliberately not
// counted, since no adapter was dispatched.
func (ws *WebhookServer) matchAndPatchCustom(
	request *admissionv1.AdmissionRequest,
	key string,
	target varmor.Target,
	logger logr.Logger,
	policyNamespace, policyName string,
	clusterScope bool,
	policyIdentity varmorpolicy.AuditPolicyIdentity,
) *admissionv1.AdmissionResponse {
	// Routing on the full GVK (including version) lets per-version adapters
	// of one Kind be selected independently. A miss means this exact
	// group/version/kind is unknown to this binary.
	a, ok := ws.registry.LookupGVK(schema.GroupVersionKind{Group: request.Kind.Group, Version: request.Kind.Version, Kind: request.Kind.Kind})
	if !ok {
		return nil
	}
	// A name-targeted policy evaluated against a different object of the same
	// Kind is a real dispatch attempt that selects nothing; count it like the
	// label-selector non-selection path below.
	if target.Name != "" && target.Name != request.Name {
		ws.recordAdapterDispatch(a.Name(), dispatchResultNotSelected)
		return nil
	}

	enforcer := ""
	var mode varmor.VarmorPolicyMode
	var networkProxyConfig *varmor.NetworkProxyConfig
	if clusterScope {
		enforcer, mode, networkProxyConfig = ws.policyCacher.GetClusterPolicyEntry(key)
		policyNamespace = varmorconfig.Namespace
	} else {
		enforcer, mode, networkProxyConfig = ws.policyCacher.GetPolicyEntry(key)
	}

	obj, err := deserializeCustomWorkload(request, a)
	if err != nil {
		logger.Error(err, "deserializeCustomWorkload()")
		ws.recordAdapterDispatch(a.Name(), dispatchResultDecodeError)
		return nil
	}

	matched := target.Name != "" && target.Name == obj.GetName()
	if target.Selector != nil {
		selector, err := metav1.LabelSelectorAsSelector(target.Selector)
		if err != nil {
			// Policies are admitted without parsing the selector, so a
			// malformed one can still reach this path. Keep the fail-open
			// convention but make the failure visible: log it and count it
			// like every other terminal dispatch outcome.
			logger.Error(err, "metav1.LabelSelectorAsSelector()")
			ws.recordAdapterDispatch(a.Name(), dispatchResultSelectorError)
			return nil
		}
		matched = selector.Matches(labels.Set(obj.GetLabels()))
	}
	if !matched {
		ws.recordAdapterDispatch(a.Name(), dispatchResultNotSelected)
		return nil
	}

	apName := varmorprofile.GenerateArmorProfileName(policyNamespace, policyName, clusterScope)
	logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
	patch, err := buildCustomPatch(obj, a, enforcer, mode, target, networkProxyConfig, apName, policyIdentity, ws.bpfExclusiveMode, varmorconfig.AppArmorGA)
	if err != nil {
		logger.Error(err, "buildCustomPatch()")
		ws.recordAdapterDispatch(a.Name(), dispatchResultTemplateExtractError)
		return nil
	}
	// An empty patch means the selected object produced no injection op
	// (e.g. every targeted container opted out); count it separately from a
	// real mutation.
	result := dispatchResultPatched
	if patch == "" {
		result = dispatchResultPatchSkippedUnconfined
	}
	ws.recordAdapterDispatch(a.Name(), result)
	logger.V(2).Info("mutating resource", "json patch", patch)
	return successResponse(request.UID, []byte(patch))
}

// deserializeCustomWorkload decodes a custom resource as unstructured — the
// manager has no typed model for downstream CRDs — and verifies the in-payload
// GVK matches both the admission request and the adapter selected for that
// GVK. A mismatch is returned as an error; the caller logs it, records the
// decode_error dispatch result and fails open (returns nil) rather than
// mutating the wrong object shape.
func deserializeCustomWorkload(request *admissionv1.AdmissionRequest, a workload.Adapter) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(request.Object.Raw, obj); err != nil {
		return nil, err
	}
	expected := schema.GroupVersionKind{Group: request.Kind.Group, Version: request.Kind.Version, Kind: request.Kind.Kind}
	if obj.GetObjectKind().GroupVersionKind() != expected || expected != a.GVK() {
		return nil, fmt.Errorf("object identity does not match admission request or adapter")
	}
	return obj, nil
}

// buildCustomPatch renders the JSON Patch for a custom resource. The adapter
// is already resolved by matchAndPatchCustom, so it directly supplies the pod
// templates; overlapping template pointers are guarded, the object- and
// template-level metadata maps are ensured, and then each template's
// per-container injection is delegated to the shared buildPodTemplatePatch.
// All failures (malformed templates, overlapping or invalid pointers) return
// errors; the custom dispatch path logs and counts them, then fails open
// (returns nil) so the object is admitted unmutated rather than denied.
func buildCustomPatch(obj *unstructured.Unstructured, adapter workload.Adapter, enforcer string,
	mode varmor.VarmorPolicyMode, target varmor.Target, networkProxyConfig *varmor.NetworkProxyConfig,
	profileName string, id varmorpolicy.AuditPolicyIdentity, bpfExclusiveMode bool, appArmorGA bool) (patch string, err error) {
	e := varmortypes.GetEnforcerType(enforcer)

	refs, err := adapter.PodTemplates(obj)
	if err != nil {
		return "", err
	}
	// Objects without templates need no injection or mutation metadata.
	if len(refs) == 0 {
		return "", nil
	}

	var jsonPatch string
	if _, ok := obj.Object["metadata"].(map[string]interface{}); !ok {
		jsonPatch += `{"op": "add", "path": "/metadata", "value": {}},`
	}

	// The object-level (root) annotations map is always ensured first. nil-ness
	// (rather than len) is checked to preserve the exact pre-refactor output.
	if obj.GetAnnotations() == nil {
		jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
	}

	// One patch set is emitted per pod template; a custom resource may carry
	// several, so their pointers must be distinct and non-overlapping.
	for index, ref := range refs {
		if ref.Template == nil {
			return "", fmt.Errorf("template at %q is nil", ref.Path)
		}
		for _, previous := range refs[:index] {
			if previous.Path == ref.Path || strings.HasPrefix(ref.Path, previous.Path+"/") || strings.HasPrefix(previous.Path, ref.Path+"/") {
				return "", fmt.Errorf("overlapping template paths %q and %q", previous.Path, ref.Path)
			}
		}
		template, err := templateAtPointer(obj.Object, ref.Path)
		if err != nil {
			return "", err
		}
		if ref.Path != "" {
			// Both parent nodes are ensured through unstructured map checks
			// here so the shared buildPodTemplatePatch stays injection-only.
			// A missing metadata node implies a missing annotations node too;
			// reading a nil map is safe, so the second check works regardless
			// of which branch just ran.
			metadata, hasMetadata := template["metadata"].(map[string]interface{})
			if !hasMetadata {
				path, err := json.Marshal(ref.Path + "/metadata")
				if err != nil {
					return "", err
				}
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": %s, "value": {}},`, path)
			}
			if _, ok := metadata["annotations"]; !ok {
				path, err := json.Marshal(ref.Path + "/metadata/annotations")
				if err != nil {
					return "", err
				}
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": %s, "value": {}},`, path)
			}
		}
		jsonPatch += buildPodTemplatePatch(ref, e, mode, target, networkProxyConfig, profileName, id, bpfExclusiveMode, appArmorGA)
	}

	return finalizePatch(jsonPatch), nil
}
