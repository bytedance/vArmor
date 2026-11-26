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

// Package workload defines the pluggable workload Adapter extension point.
//
// An Adapter knows how to identify a workload type (its GVK/GVR) and where the
// Pod templates live inside an instance of that type. The actual security
// injection logic (AppArmor, BPF, Seccomp, NetworkProxy) stays in the vArmor
// core and is shared by every adapter; an adapter never re-implements it.
//
// This package is a leaf of the vArmor import graph: it imports only
// Kubernetes api/apimachinery types and no other vArmor package (and no
// client-go), so adapters can be implemented and unit tested hermetically.
package workload

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Template path vocabulary shared by the core mutation logic and adapters.
// The registry only holds custom (CRD) adapters; the four built-in kinds are
// dispatched by a hard-coded switch, but they reuse the same path constants so
// the shared JSON-Patch renderer has a single notion of template location.
const (
	// RootPath is the template path for a root-level Pod.
	RootPath = ""
	// WorkloadTemplatePath is the template path for the apps/v1 workload kinds.
	WorkloadTemplatePath = "/spec/template"
)

// Adapter describes one workload type that vArmor can mutate. Implementations
// compiled into the manager binary typically self-register through Register
// from an init function; the composition root then builds the immutable
// runtime Registry from every registered adapter. Adapters can still be
// passed explicitly to NewRegistry in tests. Identity methods must return
// stable values for the lifetime of the process.
//
// Each adapter serves exactly one API version. When a CRD exposes several
// served versions whose Pod-template locations differ, ship one adapter per
// version: they share the API group and bare Kind but return distinct
// GVK()/GVR() versions, and their Name() values must remain unique (by
// convention the name encodes the version, e.g. "widget-v1"). Versions whose
// template layout is identical should instead be handled by a single adapter
// rather than duplicated.
type Adapter interface {
	// Name is the stable key identifying this adapter, independent of the
	// API group/version; it must be unique across all registered adapters.
	// For multi-version adapters sharing one Kind, include the version in
	// the name (e.g. "widget-v1", "widget-v2").
	Name() string

	// GVK returns the GroupVersionKind that identifies the object's type, as
	// carried in an AdmissionRequest.Kind and in apiVersion/kind fields. The
	// registry routes admissions on the full GVK, including its version, so
	// per-version adapters never receive objects of another version.
	GVK() schema.GroupVersionKind

	// GVR returns the GroupVersionResource that identifies the REST collection
	// the API server routes on and that webhook rules are expressed in. Its
	// group and version must match GVK(), and its resource must name the same type.
	// Adapters serving different versions of one Kind must return the same
	// resource name because all versions share one REST collection.
	GVR() schema.GroupVersionResource

	// PodTemplates returns every Pod template contained in obj together with
	// the RFC 6901 JSON Pointer at which each template lives (e.g.
	// "/spec/template"). For a Pod the path is the empty string. The returned
	// PodTemplateSpec values are decoded copies: the core may mutate them while
	// building patches, but it never writes back through obj, so the input
	// unstructured object is left untouched. Returned templates must be
	// non-nil and return distinct, non-overlapping paths, which the core
	// validates while building patches. The registry holds custom adapters
	// only: the four built-in kinds never implement this interface and are
	// rendered through a hard-coded single-template path, so no Adapter
	// implementation is exempt from the overlap check. An empty result
	// means the object has no templates to inject; malformed templates
	// return an error.
	PodTemplates(obj *unstructured.Unstructured) ([]PodTemplateRef, error)

	// DefaultWebhookOptions returns the webhook defaults for this adapter;
	// runtime configuration may override individual fields. Versioned
	// adapters of one Kind merge into one entry that keeps the first
	// adapter's MatchConditions, so they must declare the same
	// Name/Expression set (order irrelevant); the registry enforces this.
	DefaultWebhookOptions() WebhookOptions
}

// PodTemplateRef pairs a Pod template with the JSON Pointer at which it is
// located inside the enclosing workload object.
type PodTemplateRef struct {
	// Path is the RFC 6901 JSON Pointer to the template. It is the empty
	// string for a root-level Pod and typically "/spec/template" for the
	// built-in workload kinds.
	Path string

	// Template is the pod template found at Path.
	Template *corev1.PodTemplateSpec
}

// WebhookOptions captures the admission-webhook behavior an adapter wants by
// default. The runtime configuration may override these values.
type WebhookOptions struct {
	// FailurePolicy is the admission failure policy (Ignore or Fail).
	FailurePolicy admissionregistrationv1.FailurePolicyType

	// TimeoutSeconds is the webhook timeout; zero means use the manager
	// global default.
	TimeoutSeconds int32

	// MatchConditions are optional CEL conditions evaluated by the API server
	// before the request is sent to the webhook.
	MatchConditions []admissionregistrationv1.MatchCondition

	// Operations are the admission operations this webhook applies to.
	Operations []admissionregistrationv1.OperationType
}
