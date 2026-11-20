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

package workload

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// FakeAdapter is a minimal Adapter for tests that need a workload kind with an
// arbitrary identity but no real Pod-template behavior: PodTemplates is a
// no-op. It is a value type configured through exported fields so tests can
// build it with struct literals.
//
// The field names differ from the Adapter method names because Go forbids a
// type from declaring a field and a method with the same identifier.
type FakeAdapter struct {
	AdapterName string
	AdapterGVK  schema.GroupVersionKind
	AdapterGVR  schema.GroupVersionResource
	// Options is returned verbatim by DefaultWebhookOptions; the zero value
	// means "no adapter-specific defaults".
	Options WebhookOptions
}

var _ Adapter = FakeAdapter{}

func (f FakeAdapter) Name() string                     { return f.AdapterName }
func (f FakeAdapter) GVK() schema.GroupVersionKind     { return f.AdapterGVK }
func (f FakeAdapter) GVR() schema.GroupVersionResource { return f.AdapterGVR }

// PodTemplates returns no refs: a FakeAdapter models a registered workload
// kind without carrying any Pod templates.
func (f FakeAdapter) PodTemplates(*unstructured.Unstructured) ([]PodTemplateRef, error) {
	return nil, nil
}

func (f FakeAdapter) DefaultWebhookOptions() WebhookOptions { return f.Options }
