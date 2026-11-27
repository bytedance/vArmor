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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorpolicy "github.com/bytedance/vArmor/internal/policy"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	"github.com/bytedance/vArmor/pkg/workload"
)

func (ws *WebhookServer) matchAndPatch(request *admissionv1.AdmissionRequest, key string, target varmor.Target, logger logr.Logger) *admissionv1.AdmissionResponse {
	policyNamespace, policyName, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}
	logger.V(2).Info("policy matching", "policy namespace", policyNamespace, "policy name", policyName)

	clusterScope := policyNamespace == ""
	if !clusterScope && policyNamespace != request.Namespace {
		// Namespace="" means a cluster-scoped resource, which a
		// namespaced policy cannot protect: its ArmorProfile and
		// NetworkProxy Secret are created inside the policy's namespace.
		// The Kind match keeps ordinary cross-namespace skips silent.
		if request.Namespace == "" && request.Kind.Kind == target.Kind {
			logger.Info("namespaced VarmorPolicy cannot protect a cluster-scoped resource; use a VarmorClusterPolicy instead",
				"policy namespace", policyNamespace, "policy name", policyName,
				"resource kind", request.Kind.Kind, "resource name", request.Name)
		}
		return nil
	}

	// Capture the owning policy's identity before policyNamespace is
	// overwritten with the vArmor install namespace below. It is threaded down
	// to the NetworkProxy sidecar env so the in-sidecar kata audit sink can
	// attribute violation records to the policy.
	var policyIdentity varmorpolicy.AuditPolicyIdentity
	if clusterScope {
		policyIdentity = varmorpolicy.AuditPolicyIdentity{Kind: "VarmorClusterPolicy", Name: policyName}
	} else {
		policyIdentity = varmorpolicy.AuditPolicyIdentity{Kind: "VarmorPolicy", Name: policyName, Namespace: policyNamespace}
	}

	if request.Kind.Kind != target.Kind {
		return nil
	}

	// Built-in kinds keep their historical dispatch (typed decode,
	// name/label selection, fail-open); every other Kind is a custom
	// resource routed through the adapter registry, whose construction
	// guarantees the two dispatch sets never overlap.
	if workload.IsBuiltInKind(request.Kind.Kind) {
		return ws.matchAndPatchNative(request, key, target, logger, policyNamespace, policyName, clusterScope, policyIdentity)
	}
	return ws.matchAndPatchCustom(request, key, target, logger, policyNamespace, policyName, clusterScope, policyIdentity)
}

// matchAndPatchNative preserves the historical built-in-kind behavior
// exactly: typed decoding through the shared deserializer, name/label
// selection, and fail-open error handling where every error is logged and
// returns nil so policy fallback and admission continue. It emits no adapter
// dispatch metrics.
func (ws *WebhookServer) matchAndPatchNative(
	request *admissionv1.AdmissionRequest,
	key string,
	target varmor.Target,
	logger logr.Logger,
	policyNamespace, policyName string,
	clusterScope bool,
	policyIdentity varmorpolicy.AuditPolicyIdentity,
) *admissionv1.AdmissionResponse {
	enforcer := ""
	var mode varmor.VarmorPolicyMode
	var networkProxyConfig *varmor.NetworkProxyConfig
	if clusterScope {
		enforcer, mode, networkProxyConfig = ws.policyCacher.GetClusterPolicyEntry(key)
		policyNamespace = varmorconfig.Namespace
	} else {
		enforcer, mode, networkProxyConfig = ws.policyCacher.GetPolicyEntry(key)
	}

	obj, err := ws.deserializeWorkload(request)
	if err != nil {
		logger.Error(err, "ws.deserializeWorkload()")
		return nil
	}

	m, err := meta.Accessor(obj)
	if err != nil {
		logger.Error(err, "meta.Accessor()")
		return nil
	}

	apName := varmorprofile.GenerateArmorProfileName(policyNamespace, policyName, clusterScope)
	if target.Name != "" && target.Name == m.GetName() {
		logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
		patch, err := buildNativePatch(obj, enforcer, mode, target, networkProxyConfig, apName, policyIdentity, ws.bpfExclusiveMode, varmorconfig.AppArmorGA)
		if err != nil {
			logger.Error(err, "ws.buildNativePatch()")
			return nil
		}
		logger.V(2).Info("mutating resource", "json patch", patch)
		return successResponse(request.UID, []byte(patch))
	} else if target.Selector != nil {
		selector, err := metav1.LabelSelectorAsSelector(target.Selector)
		if err != nil {
			return nil
		}
		if selector.Matches(labels.Set(m.GetLabels())) {
			logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
			patch, err := buildNativePatch(obj, enforcer, mode, target, networkProxyConfig, apName, policyIdentity, ws.bpfExclusiveMode, varmorconfig.AppArmorGA)
			if err != nil {
				logger.Error(err, "ws.buildNativePatch()")
				return nil
			}
			logger.V(2).Info("mutating resource", "json patch", patch)
			return successResponse(request.UID, []byte(patch))
		}
	}

	return nil
}

// deserializeWorkload decodes a built-in-kind request into its typed Go
// object through the shared scheme deserializer. It is the historical
// fail-open decode path: callers log the error and return nil. The returned
// type is one of *appsv1.Deployment, *appsv1.StatefulSet,
// *appsv1.DaemonSet or *corev1.Pod, matching the Kind switch in
// matchAndPatch.
func (ws *WebhookServer) deserializeWorkload(request *admissionv1.AdmissionRequest) (interface{}, error) {
	switch request.Kind.Kind {
	case "Deployment":
		deploy := appsv1.Deployment{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &deploy)
		return &deploy, err
	case "StatefulSet":
		statusful := appsv1.StatefulSet{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &statusful)
		return &statusful, err
	case "DaemonSet":
		daemon := appsv1.DaemonSet{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &daemon)
		return &daemon, err
	case "Pod":
		pod := corev1.Pod{}
		_, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &pod)
		return &pod, err
	}
	return nil, fmt.Errorf("unsupported kind")
}

// buildNativePatch renders the JSON Patch for one of the four built-in
// workload kinds. Dispatch, typed decoding and selection stay in
// matchAndPatchNative; here each kind contributes its hard-coded root
// annotation prelude and its single pod-template location, including the
// template-level annotations map ensure, after which the actual
// per-container injection is delegated to the shared buildPodTemplatePatch
// so native and custom paths emit identical operations for a given
// template. It carries no registry.
func buildNativePatch(obj interface{}, enforcer string,
	mode varmor.VarmorPolicyMode, target varmor.Target, networkProxyConfig *varmor.NetworkProxyConfig,
	profileName string, id varmorpolicy.AuditPolicyIdentity, bpfExclusiveMode bool, appArmorGA bool) (patch string, err error) {

	var jsonPatch string
	e := varmortypes.GetEnforcerType(enforcer)

	// Every built-in kind exposes exactly one pod template at a fixed path.
	// The root annotation map is ensured before the template-level ops so the
	// operation order matches the historical per-kind switch exactly.
	var ref workload.PodTemplateRef
	switch target.Kind {
	case "Deployment":
		deploy := obj.(*appsv1.Deployment)
		if deploy.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}
		ref = workload.PodTemplateRef{Path: workload.WorkloadTemplatePath, Template: &deploy.Spec.Template}
	case "StatefulSet":
		statefulSet := obj.(*appsv1.StatefulSet)
		if statefulSet.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}
		ref = workload.PodTemplateRef{Path: workload.WorkloadTemplatePath, Template: &statefulSet.Spec.Template}
	case "DaemonSet":
		daemonSet := obj.(*appsv1.DaemonSet)
		if daemonSet.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}
		ref = workload.PodTemplateRef{Path: workload.WorkloadTemplatePath, Template: &daemonSet.Spec.Template}
	case "Pod":
		pod := obj.(*corev1.Pod)
		if pod.Annotations == nil {
			jsonPatch += `{"op": "add", "path": "/metadata/annotations", "value": {}},`
		}
		ref = workload.PodTemplateRef{Path: workload.RootPath, Template: &corev1.PodTemplateSpec{ObjectMeta: pod.ObjectMeta, Spec: pod.Spec}}
	default:
		return "", fmt.Errorf("unsupported workload kind %q", target.Kind)
	}

	// A nested workload template owns its own annotations map; a root Pod
	// (ref.Path == "") shares the object-level map ensured above, so only a
	// non-empty template path (the apps/v1 workload kinds) seeds a
	// template-level map here. The op must precede the
	// enforcer ops because their "replace" children require the parent map to
	// already exist (RFC 6902). This reproduces the historical per-kind
	// switch op-for-op and keeps Pod from adding the same map twice.
	if ref.Path != "" && ref.Template.Annotations == nil {
		jsonPatch += fmt.Sprintf(`{"op": "add", "path": "%s/metadata/annotations", "value": {}},`, ref.Path)
	}

	jsonPatch += buildPodTemplatePatch(ref, e, mode, target, networkProxyConfig, profileName, id, bpfExclusiveMode, appArmorGA)

	return finalizePatch(jsonPatch), nil
}

// finalizePatch closes a JSON Patch operation list: it appends the mutatedAt
// marker, strips the trailing comma of the last operation and wraps the list
// in a JSON Patch array. An empty input means no injection op was produced, so
// the empty string is returned and the caller leaves the object unmutated.
func finalizePatch(jsonPatch string) string {
	if len(jsonPatch) == 0 {
		return ""
	}
	jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "/metadata/annotations/webhook.varmor.org~1mutatedAt", "value": "%s"},`, time.Now().Format(time.RFC3339))
	return "[" + jsonPatch[:len(jsonPatch)-1] + "]"
}

// buildPodTemplatePatch renders the per-container injection operations
// (NetworkProxy, BPF, AppArmor, Seccomp) for a single pod template located at
// ref.Path. It deliberately contains injection logic only: both callers must
// ensure the template's metadata/annotations parent map exists first, since
// every enforcer op below is a "replace" against an annotation child path,
// which RFC 6902 rejects when an intermediate node is missing. All JSON Patch
// literals are shared with the pre-refactor implementation; the only
// per-template input is the template path (empty for a root Pod,
// "/spec/template" for the workload kinds, or an arbitrary path for a custom
// multi-template adapter), which the builder helpers splice in verbatim.
func buildPodTemplatePatch(ref workload.PodTemplateRef, e varmortypes.Enforcer,
	mode varmor.VarmorPolicyMode, target varmor.Target, networkProxyConfig *varmor.NetworkProxyConfig,
	profileName string, id varmorpolicy.AuditPolicyIdentity, bpfExclusiveMode bool, appArmorGA bool) string {

	var jsonPatch string

	// templatePath is the RFC 6901 path to this template: "" for a root Pod,
	// "/spec/template" for the built-in workload kinds, and an arbitrary path
	// for a custom multi-template adapter. The enforcer builders splice it in
	// verbatim, so the built-in kinds keep their exact historical patch paths.
	templatePath := ref.Path
	tpl := ref.Template

	// NetworkProxy. Skip without app containers: spec/containers serializes
	// to null for a zero-slice PodSpec (no omitempty), so the sidecar append
	// fails to apply and the request is rejected even under Ignore; there is
	// no traffic to proxy anyway.
	if (e&varmortypes.NetworkProxy) != 0 && len(tpl.Spec.Containers) > 0 {
		if _, ok := tpl.Annotations["pod.networkproxy.security.beta.varmor.org"]; !ok {
			if len(tpl.Spec.InitContainers) == 0 {
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": "%s/spec/initContainers", "value": []},`, ref.Path)
			}

			if len(tpl.Spec.Volumes) == 0 {
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": "%s/spec/volumes", "value": []},`, ref.Path)
			}

			microVM := varmorconfig.IsMicroVMPod(tpl.Labels, tpl.Annotations, tpl.Spec.RuntimeClassName)
			jsonPatch += buildNetworkProxyPatch(profileName, id, templatePath, networkProxyConfig, microVM)
		}
	}

	for index, container := range tpl.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// NetworkProxy MITM: inject CA bundle volumeMount + env vars
		// into target containers when MITM is enabled on the policy.
		if (e&varmortypes.NetworkProxy) != 0 && container.Name != "varmor-network-proxy" &&
			networkProxyConfig != nil && networkProxyConfig.MITM != nil && len(networkProxyConfig.MITM.Domains) > 0 {
			jsonPatch += buildNetworkProxyMITMTargetPatch(templatePath, container, index)
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := tpl.Annotations[key]; !ok || value != "unconfined" {
				jsonPatch += buildBpfPatch(appArmorGA, templatePath, bpfExclusiveMode, profileName, container, index)
			}
		}
		// AppArmor
		if (e&varmortypes.AppArmor) != 0 && !isAppArmorUnconfined(tpl, container, appArmorGA) {
			jsonPatch += buildAppArmorPatch(appArmorGA, templatePath, profileName, container, index)
			if appArmorGA && container.SecurityContext == nil {
				// AppArmor already added the parent; Seccomp must not add it again.
				container.SecurityContext = &corev1.SecurityContext{}
			}
		}
		// Seccomp
		if (e&varmortypes.Seccomp) != 0 && !skipSeccompInjection(tpl, container) {
			jsonPatch += buildSeccompPatch(templatePath, profileName, container, index, mode)
		}
	}

	return jsonPatch
}

func isAppArmorUnconfined(tpl *corev1.PodTemplateSpec, container corev1.Container, appArmorGA bool) bool {
	if tpl.Annotations["container.apparmor.security.beta.varmor.org/"+container.Name] == "unconfined" {
		return true
	}
	if !appArmorGA {
		return tpl.Annotations["container.apparmor.security.beta.kubernetes.io/"+container.Name] == "unconfined"
	}
	containerContext := container.SecurityContext
	podContext := tpl.Spec.SecurityContext
	return (containerContext != nil && containerContext.AppArmorProfile != nil && containerContext.AppArmorProfile.Type == corev1.AppArmorProfileTypeUnconfined) ||
		(podContext != nil && podContext.AppArmorProfile != nil && podContext.AppArmorProfile.Type == corev1.AppArmorProfileTypeUnconfined)
}

func skipSeccompInjection(tpl *corev1.PodTemplateSpec, container corev1.Container) bool {
	if tpl.Annotations["container.seccomp.security.beta.varmor.org/"+container.Name] == "unconfined" {
		return true
	}
	containerContext := container.SecurityContext
	podContext := tpl.Spec.SecurityContext
	return (containerContext != nil && containerContext.Privileged != nil && *containerContext.Privileged) ||
		(containerContext != nil && containerContext.SeccompProfile != nil && containerContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined) ||
		(podContext != nil && podContext.SeccompProfile != nil && podContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined)
}

func buildBpfPatch(
	appArmorGA bool,
	templatePath string,
	bpfExclusiveMode bool,
	profileName string,
	container corev1.Container,
	index int) string {

	var jsonPatch string

	jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/metadata/annotations/container.bpf.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, templatePath, container.Name, profileName)

	if bpfExclusiveMode {
		if !appArmorGA {
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "unconfined"},`, templatePath, container.Name)
		} else {
			if container.SecurityContext == nil {
				jsonPatch += fmt.Sprintf(`{"op": "add", "path": "%s/spec/containers/%d/securityContext", "value": {}},`, templatePath, index)
			}
			jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/spec/containers/%d/securityContext/appArmorProfile", "value": {"type": "Unconfined"}},`, templatePath, index)
		}
	}

	return jsonPatch
}

func buildAppArmorPatch(
	appArmorGA bool,
	templatePath string,
	profileName string,
	container corev1.Container,
	index int) string {

	var jsonPatch string

	if !appArmorGA {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1%s", "value": "localhost/%s"},`, templatePath, container.Name, profileName)
	} else {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/metadata/annotations/container.apparmor.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, templatePath, container.Name, profileName)
		if container.SecurityContext == nil {
			jsonPatch += fmt.Sprintf(`{"op": "add", "path": "%s/spec/containers/%d/securityContext", "value": {}},`, templatePath, index)
		}
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/spec/containers/%d/securityContext/appArmorProfile", "value": {"type": "Localhost", "localhostProfile": "%s"}},`, templatePath, index, profileName)
	}

	return jsonPatch
}

func buildSeccompPatch(
	templatePath string,
	profileName string,
	container corev1.Container,
	index int, mode varmor.VarmorPolicyMode) string {

	var jsonPatch string

	jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/metadata/annotations/container.seccomp.security.beta.varmor.org~1%s", "value": "localhost/%s"},`, templatePath, container.Name, profileName)
	if container.SecurityContext == nil {
		jsonPatch += fmt.Sprintf(`{"op": "add", "path": "%s/spec/containers/%d/securityContext", "value": {}},`, templatePath, index)
	}
	if mode == varmor.RuntimeDefaultMode {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/spec/containers/%d/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}},`, templatePath, index)
	} else {
		jsonPatch += fmt.Sprintf(`{"op": "replace", "path": "%s/spec/containers/%d/securityContext/seccompProfile", "value": {"type": "Localhost", "localhostProfile": "%s"}},`, templatePath, index, profileName)
	}

	return jsonPatch
}

// jsonString encodes v as a JSON string literal (including the surrounding
// double quotes and all necessary escaping) so it can be spliced safely into a
// JSONPatch value position. It is used for the policy identity and metadata
// fields injected into the NetworkProxy sidecar env, which originate from
// user-controlled policy names/namespaces and must not be able to break out of
// the enclosing JSON string.
func jsonString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func buildNetworkProxyPatch(profileName string, id varmorpolicy.AuditPolicyIdentity, templatePath string, networkProxyConfig *varmor.NetworkProxyConfig, microVM bool) string {
	var sb strings.Builder

	proxyUID := varmorconfig.DefaultProxyUID
	proxyPort := varmorconfig.DefaultProxyPort
	proxyAdminPort := varmorconfig.DefaultProxyAdminPort
	if networkProxyConfig != nil {
		if networkProxyConfig.ProxyUID != nil {
			proxyUID = *networkProxyConfig.ProxyUID
		}
		if networkProxyConfig.ProxyPort != nil {
			proxyPort = *networkProxyConfig.ProxyPort
		}
		if networkProxyConfig.ProxyAdminPort != nil {
			proxyAdminPort = *networkProxyConfig.ProxyAdminPort
		}
	}

	mitmEnabled := networkProxyConfig != nil && networkProxyConfig.MITM != nil && len(networkProxyConfig.MITM.Domains) > 0

	// sidecarRunAsUser is always 0: see the securityContext comment below.
	// proxyUID is still used for the iptables uid-owner RETURN exemption and
	// for VARMOR_ENVOY_UID (the uid the entrypoint drops to before Envoy).
	var sidecarRunAsUser int64 = 0

	// --- 1. add annotation ---
	sb.WriteString(fmt.Sprintf(
		`{"op": "add", "path": "%s/metadata/annotations/pod.networkproxy.security.beta.varmor.org", "value": "localhost/%s"},`, templatePath, profileName,
	))

	// --- 2. initContainer: varmor-network-proxy-init ---
	// Override Pod-level UID/non-root defaults for iptables initialization.
	// The sidecar below also needs an explicit non-root override to start as root.
	sb.WriteString(fmt.Sprintf(
		`{"op": "add", "path": "%s/spec/initContainers/-", "value": `+
			`{"name": "varmor-network-proxy-init", `+
			`"image": "%s", `+
			`"securityContext": {"runAsUser": 0, "runAsNonRoot": false, "capabilities": {"add": ["NET_ADMIN"]}}, `+
			`"resources": {"requests": {"cpu": "10m", "memory": "16Mi"}}, `+
			`"command": ["sh", "-c", %s]}},`,
		templatePath, varmorconfig.ProxyInitImage, iptablesScript(proxyUID, proxyPort, proxyAdminPort),
	))

	// --- 3. sidecar container: varmor-network-proxy ---
	// When MITM is enabled, the sidecar additionally mounts the per-policy
	// leaf/key and upstream CA bundle under /etc/envoy/tls (see
	// varmorconfig.MITMCertsMountDir). Envoy watches this directory for
	// leaf rotation and upstream trust store updates.
	sidecarVolumeMounts := `{"name": "varmor-network-proxy-config", "mountPath": "/etc/envoy", "readOnly": true}`
	if mitmEnabled {
		sidecarVolumeMounts += `, {"name": "varmor-network-proxy-mitm-tls", "mountPath": "/etc/envoy/tls", "readOnly": true}`
	}
	// Audit: on runc, mount the node-local ALS socket directory (hostPath) at
	// the same absolute path the agent listens on, so the CDS cluster pipe.path
	// resolves identically. Envoy only connects to the socket as a gRPC client
	// and never writes to the directory, so it is mounted read-only. On kata the
	// hostPath cannot cross the VM boundary, so no volume/volumeMount is
	// injected: the in-sidecar audit sink bind(2)s the socket inode directly in
	// the container's own rootfs at the same path, and Envoy connects locally.
	if !microVM {
		sidecarVolumeMounts += fmt.Sprintf(
			`, {"name": "%s", "mountPath": "%s", "readOnly": true}`,
			varmorconfig.AuditNetworkProxyVolumeName, varmorconfig.AuditNetworkProxySocketDir,
		)
	}

	// Compute sidecar resource requirements based on MITM status and user overrides.
	var proxyResourceOverride *varmor.ProxyResourceOverride
	if networkProxyConfig != nil {
		proxyResourceOverride = networkProxyConfig.Resources
	}
	proxyResources := varmorpolicy.ResolveProxyResources(proxyResourceOverride, mitmEnabled)
	proxyResourcesJSON := varmorpolicy.MarshalProxyResourcesJSON(proxyResources)

	// auditNodeMetadataOverlayJSON is the Envoy "--config-yaml" overlay encoded
	// as a JSON string so it can be embedded verbatim inside the JSONPatch. The
	// overlay supplies node.metadata (pod_name / pod_namespace / pod_uid) whose
	// $(POD_*) references the kubelet expands from the Downward API env vars
	// before Envoy starts; Envoy then merges it onto the static bootstrap node.
	// This mirrors the controller path (varmorpolicy.AuditNodeMetadataOverlay).
	overlayBytes, _ := json.Marshal(varmorpolicy.AuditNodeMetadataOverlay)
	auditNodeMetadataOverlayJSON := string(overlayBytes)

	// Audit sink env: the in-sidecar kata audit sink reads NODE_NAME (node
	// attribution), the policy identity (PROFILE_NAME/POLICY_KIND/POLICY_NAME/
	// POLICY_NAMESPACE), VARMOR_ENVOY_UID (the uid the image entrypoint drops
	// to before exec-ing Envoy, kept in sync with proxyUID), VARMOR_NAMESPACE
	// and, when the manager carries cluster metadata, AUDIT_EVENT_METADATA.
	// These are injected on every sidecar so the custom Envoy image stays
	// runtime-agnostic; on runc the entrypoint's connect(2) self-check succeeds
	// and the sink is never started, so the values are simply unused.
	//
	// VARMOR_NAMESPACE carries the manager's own namespace (the namespace where
	// the vArmor components are deployed) so the sink can populate the
	// varmorNamespace audit-metadata field correctly. It must NOT be derived
	// from the Downward API metadata.namespace: inside the sidecar that would
	// be the business Pod's namespace, not the vArmor namespace.
	sinkEnv := fmt.Sprintf(
		`{"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}, `+
			`{"name": "PROFILE_NAME", "value": %s}, `+
			`{"name": "POLICY_KIND", "value": %s}, `+
			`{"name": "POLICY_NAME", "value": %s}, `+
			`{"name": "POLICY_NAMESPACE", "value": %s}, `+
			`{"name": "VARMOR_NAMESPACE", "value": %s}, `+
			`{"name": "VARMOR_ENVOY_UID", "value": %s}`,
		jsonString(profileName), jsonString(id.Kind), jsonString(id.Name),
		jsonString(id.Namespace), jsonString(varmorconfig.Namespace),
		jsonString(strconv.FormatInt(proxyUID, 10)),
	)
	if md := os.Getenv("AUDIT_EVENT_METADATA"); md != "" {
		sinkEnv += fmt.Sprintf(`, {"name": "AUDIT_EVENT_METADATA", "value": %s}`, jsonString(md))
	}

	// Audit: carry the Pod identity into the sidecar via the Downward API. The
	// kubelet expands the $(POD_*) references in the sidecar's "--config-yaml"
	// overlay from these env vars before Envoy starts, so the agent can
	// attribute ALS records to a precise Pod. (Envoy does not expand "%ENV()%"
	// inside node.metadata; that operator is access-log only.) The kata audit
	// sink env vars are appended after the Pod identity vars.
	sidecarEnv := `"env": [` +
		`{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}, ` +
		`{"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}}, ` +
		`{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}, ` +
		sinkEnv + `], `

	sb.WriteString(fmt.Sprintf(
		`{"op": "add", "path": "%s/spec/containers/-", "value": `+
			`{"name": "varmor-network-proxy", `+
			`"image": "%s", `+
			// Option B (kata): the sidecar always starts as root (runAsUser 0) so
			// the custom Envoy image entrypoint can run its runtime self-check
			// and, on kata, bind the in-sidecar audit sink before dropping to the
			// Envoy uid (VARMOR_ENVOY_UID = proxyUID) and exec-ing Envoy. On runc
			// the entrypoint drops to proxyUID immediately, so this is harmless.
			`"securityContext": {"runAsUser": %d, "runAsNonRoot": false}, `+
			// codeql[go/unsafe-quote-injection]: false positive. The token spliced
			// here is the json.Marshal output above (a fully-quoted, escaped JSON
			// string literal), NOT the raw overlay — hence no surrounding quotes.
			// Any " inside the overlay is already escaped to \", so it cannot break
			// out of the enclosing string. The value is also a compile-time const,
			// not external input.
			`"args": ["-c", "/etc/envoy/bootstrap.yaml", "--config-yaml", `+auditNodeMetadataOverlayJSON+`, "-l", "info"], `+
			`"readinessProbe": {"tcpSocket": {"port": %d}, "initialDelaySeconds": 2, "periodSeconds": 5}, `+
			`"resources": %s, `+
			`%s`+
			`"volumeMounts": [%s]}}, `,
		templatePath, varmorconfig.ProxyImage, sidecarRunAsUser, proxyPort, proxyResourcesJSON, sidecarEnv, sidecarVolumeMounts,
	))

	// --- 4. volumes ---
	// Always-on volume: the shared Envoy config Secret.
	sb.WriteString(fmt.Sprintf(
		`{"op": "add", "path": "%s/spec/volumes/-", "value": `+
			`{"name": "varmor-network-proxy-config", "secret": {"secretName": "%s", "items": [{"key": "bootstrap.yaml", "path": "bootstrap.yaml"}, {"key": "lds.yaml", "path": "lds.yaml"}, {"key": "cds.yaml", "path": "cds.yaml"}]}}},`,
		templatePath, profileName,
	))

	// Audit volume: on runc, the node-local ALS socket directory shared with the
	// agent. A hostPath (DirectoryOrCreate) mounting the leaf socketDir (not the
	// socket file) so the sidecar reconnects after the agent recreates the
	// socket inode on restart. On kata this hostPath is omitted entirely (it
	// cannot cross the micro-VM boundary and is rejected at admission by some
	// serverless providers); the in-sidecar sink binds the socket in the
	// container's own rootfs instead.
	if !microVM {
		sb.WriteString(fmt.Sprintf(
			`{"op": "add", "path": "%s/spec/volumes/-", "value": `+
				`{"name": "%s", "hostPath": {"path": "%s", "type": "DirectoryOrCreate"}}},`,
			templatePath, varmorconfig.AuditNetworkProxyVolumeName, varmorconfig.AuditNetworkProxySocketDir,
		))
	}

	if mitmEnabled {
		// MITM-only volume #1: per-policy MITM leaf certificate, leaf
		// private key and upstream CA bundle. Projected into the Envoy
		// sidecar at /etc/envoy/tls as leaf.crt / leaf.key /
		// ca-bundle.crt (see varmorconfig.MITMLeafCertPath,
		// varmorconfig.MITMLeafKeyPath, varmorconfig.MITMUpstreamTrustedCAPath).
		sb.WriteString(fmt.Sprintf(
			`{"op": "add", "path": "%s/spec/volumes/-", "value": `+
				`{"name": "varmor-network-proxy-mitm-tls", "secret": {"secretName": "%s", "items": [`+
				`{"key": "mitm-cert-sds.yaml", "path": "mitm-cert-sds.yaml"}, `+
				`{"key": "mitm-validation-sds.yaml", "path": "mitm-validation-sds.yaml"}, `+
				`{"key": "mitm-leaf.crt", "path": "leaf.crt"}, `+
				`{"key": "mitm-leaf.key", "path": "leaf.key"}, `+
				`{"key": "mitm-ca-bundle.crt", "path": "ca-bundle.crt"}]}}},`,
			templatePath, profileName,
		))

		// MITM-only volume #2: the concatenated Mozilla + vArmor-CA
		// trust bundle exposed to the application containers as
		// /etc/varmor/ca-bundle/ca-certificates.crt (see
		// varmorconfig.MITMCABundlePath). Projected separately (no
		// private keys) so application containers only see the public
		// trust store.
		sb.WriteString(fmt.Sprintf(
			`{"op": "add", "path": "%s/spec/volumes/-", "value": `+
				`{"name": "varmor-network-proxy-mitm-ca-bundle", "secret": {"secretName": "%s", "items": [`+
				`{"key": "mitm-ca-bundle.crt", "path": "ca-certificates.crt"}]}}},`,
			templatePath, profileName,
		))
	}

	return sb.String()
}

// buildNetworkProxyMITMTargetPatch emits JSON-Patch operations that inject
// the vArmor CA bundle into a single application container when TLS MITM
// is enabled on the policy. The bundle is mounted at
// varmorconfig.MITMCABundlePath (/etc/varmor/ca-bundle/ca-certificates.crt)
// and advertised to common TLS runtimes via SSL_CERT_FILE,
// REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS and CURL_CA_BUNDLE.
//
// The caller is responsible for gating on `(enforcer & NetworkProxy) != 0`
// and `networkProxyConfig.MITM != nil`.
func buildNetworkProxyMITMTargetPatch(templatePath string, container corev1.Container, index int) string {
	var sb strings.Builder

	containerPath := templatePath + "/spec/containers"

	// Idempotency: skip if the container already has the MITM CA bundle volumeMount.
	hasMITMMount := false
	for _, vm := range container.VolumeMounts {
		if vm.Name == "varmor-network-proxy-mitm-ca-bundle" {
			hasMITMMount = true
			break
		}
	}
	if !hasMITMMount {
		if len(container.VolumeMounts) == 0 {
			sb.WriteString(fmt.Sprintf(
				`{"op": "add", "path": "%s/%d/volumeMounts", "value": []},`, containerPath, index,
			))
		}
		sb.WriteString(fmt.Sprintf(
			`{"op": "add", "path": "%s/%d/volumeMounts/-", "value": `+
				`{"name": "varmor-network-proxy-mitm-ca-bundle", "mountPath": "%s", "readOnly": true}},`,
			containerPath, index, varmorconfig.MITMCABundleMountDir,
		))
	}

	// Idempotency: only inject env vars that don't already exist.
	existingEnvs := make(map[string]bool, len(container.Env))
	for _, ev := range container.Env {
		existingEnvs[ev.Name] = true
	}
	var envVarsToAdd []string
	for _, name := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		if !existingEnvs[name] {
			envVarsToAdd = append(envVarsToAdd, name)
		}
	}
	if len(envVarsToAdd) > 0 {
		if len(container.Env) == 0 {
			sb.WriteString(fmt.Sprintf(
				`{"op": "add", "path": "%s/%d/env", "value": []},`, containerPath, index,
			))
		}
		for _, name := range envVarsToAdd {
			sb.WriteString(fmt.Sprintf(
				`{"op": "add", "path": "%s/%d/env/-", "value": {"name": "%s", "value": "%s"}},`,
				containerPath, index, name, varmorconfig.MITMCABundlePath,
			))
		}
	}

	return sb.String()
}

// iptablesScript builds the proxy-init shell script that redirects the
// Pod's outbound TCP traffic to the Envoy sidecar. The generated string is
// embedded into the mutating webhook's JSON patch (wrapped in double quotes),
// so it MUST NOT contain any double-quote character.
//
// The script asks the varmor-choose-backend helper (shipped in the proxyinit
// image) which iptables backend is already in use in the target Pod netns,
// and drives all rules through that backend (${IPT}/${IPT6}). This keeps
// vArmor's rules visible to, and coherent with, rules other components
// (e.g. a PaaS kata mesh init using legacy) have already installed in the
// same netns. On a fresh netns the helper returns nft, matching the previous
// default. If both backends already carry rules the helper prints CONFLICT
// and the script aborts rather than guessing.
func iptablesScript(proxyUID int64, proxyPort uint16, proxyAdminPort uint16) string {
	script := fmt.Sprintf(
		`set -ex\n`+
			`ENVOY_UID=%d\n`+
			`ENVOY_PORT=%d\n`+
			`ENVOY_ADMIN_PORT=%d\n`+
			`IPT=$(/usr/local/bin/varmor-choose-backend iptables-legacy iptables-nft)\n`+
			`IPT6=$(/usr/local/bin/varmor-choose-backend ip6tables-legacy ip6tables-nft)\n`+
			`if [ ${IPT} = CONFLICT ]; then echo varmor-proxy-init: both legacy and nft rules present in netns, refusing to inject; exit 1; fi\n`+
			`if [ ${IPT6} = CONFLICT ]; then echo varmor-proxy-init: both legacy and nft ipv6 rules present in netns, refusing to inject; exit 1; fi\n`+
			`${IPT} -t nat -N VARMOR_OUTPUT\n`+
			`${IPT} -t nat -N VARMOR_REDIRECT\n`+
			`${IPT} -t nat -A OUTPUT -p tcp -j VARMOR_OUTPUT\n`+
			`${IPT} -t nat -A VARMOR_OUTPUT -m owner --uid-owner ${ENVOY_UID} -j RETURN\n`+
			`${IPT} -t nat -A VARMOR_OUTPUT -d 127.0.0.0/8 -j RETURN\n`+
			`${IPT} -t nat -A VARMOR_OUTPUT -p tcp -j VARMOR_REDIRECT\n`+
			`${IPT} -t nat -A VARMOR_REDIRECT -p tcp -j REDIRECT --to-ports ${ENVOY_PORT}\n`+
			`${IPT} -t filter -A OUTPUT -p tcp --dport ${ENVOY_ADMIN_PORT} -m owner ! --uid-owner ${ENVOY_UID} -j DROP\n`+
			`${IPT6} -t nat -N VARMOR_OUTPUT\n`+
			`${IPT6} -t nat -N VARMOR_REDIRECT\n`+
			`${IPT6} -t nat -A OUTPUT -p tcp -j VARMOR_OUTPUT\n`+
			`${IPT6} -t nat -A VARMOR_OUTPUT -m owner --uid-owner ${ENVOY_UID} -j RETURN\n`+
			`${IPT6} -t nat -A VARMOR_OUTPUT -d ::1/128 -j RETURN\n`+
			`${IPT6} -t nat -A VARMOR_OUTPUT -p tcp -j VARMOR_REDIRECT\n`+
			`${IPT6} -t nat -A VARMOR_REDIRECT -p tcp -j REDIRECT --to-ports ${ENVOY_PORT}\n`+
			`${IPT6} -t filter -A OUTPUT -p tcp --dport ${ENVOY_ADMIN_PORT} -m owner ! --uid-owner ${ENVOY_UID} -j DROP`,
		proxyUID, proxyPort, proxyAdminPort,
	)
	return fmt.Sprintf(`"%s"`, script)
}
