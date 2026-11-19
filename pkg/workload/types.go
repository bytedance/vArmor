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
// This package is a leaf package: it depends only on Kubernetes
// apimachinery/api types and has no dependency on any vArmor internal package
// or on client-go discovery, so adapters can be implemented and unit tested
// hermetically.
package workload

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Adapter describes one workload type that vArmor can mutate. Implementations
// compiled into the manager binary typically self-register through Register
// from an init function; the composition root then builds the immutable
// runtime Registry from the registered, config-enabled subset. Adapters can
// still be passed explicitly to NewRegistry in tests. Identity methods must
// return stable values for the lifetime of the process.
type Adapter interface {
	// Name is the stable key used for this adapter in the workloadAdapters
	// runtime configuration. It must be unique across all registered adapters
	// and independent of the API group/version.
	Name() string

	// GVK returns the GroupVersionKind that identifies the object's type, as
	// carried in an AdmissionRequest.Kind and in apiVersion/kind fields.
	GVK() schema.GroupVersionKind

	// GVR returns the GroupVersionResource that identifies the REST collection
	// the API server routes on and that webhook rules are expressed in. Its
	// group and version must match GVK(), and its resource must name the same type.
	GVR() schema.GroupVersionResource

	// PodTemplates returns every Pod template contained in obj together with
	// the RFC 6901 JSON Pointer at which each template lives (e.g.
	// "/spec/template"). For a Pod the path is the empty string. The returned
	// PodTemplateSpec values are decoded copies: the core may mutate them while
	// building patches, but it never writes back through obj, so the input
	// unstructured object is left untouched. Returned templates must be
	// non-nil; custom adapters must additionally return distinct,
	// non-overlapping paths, which the core validates while building patches.
	// The built-in adapters are exempt from that check because each built-in
	// kind has exactly one template at a fixed path. An empty result means the
	// object has no templates to inject; malformed templates return an error.
	PodTemplates(obj *unstructured.Unstructured) ([]PodTemplateRef, error)

	// DefaultWebhookOptions returns the webhook defaults for this adapter;
	// runtime configuration may override individual fields.
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

	// TimeoutSeconds is the webhook timeout; zero means "use the manager
	// global default".
	TimeoutSeconds int32

	// MatchConditions are optional CEL conditions evaluated by the API server
	// before the request is sent to the webhook.
	MatchConditions []admissionregistrationv1.MatchCondition

	// Operations are the admission operations this webhook applies to.
	Operations []admissionregistrationv1.OperationType
}
