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
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeAdapter is a minimal Adapter used to exercise registry semantics without
// pulling in any concrete workload implementation.
type fakeAdapter struct {
	name string
	gvk  schema.GroupVersionKind
	gvr  schema.GroupVersionResource
}

func (f fakeAdapter) Name() string                     { return f.name }
func (f fakeAdapter) GVK() schema.GroupVersionKind     { return f.gvk }
func (f fakeAdapter) GVR() schema.GroupVersionResource { return f.gvr }
func (f fakeAdapter) PodTemplates(obj *unstructured.Unstructured) ([]PodTemplateRef, error) {
	return nil, nil
}
func (f fakeAdapter) DefaultWebhookOptions() WebhookOptions { return WebhookOptions{} }

func gvk(group, version, kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
}

func gvr(group, version, resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
}

func TestNewRegistry_AndLookup(t *testing.T) {
	r, err := NewRegistry(fakeAdapter{name: "a", gvk: gvk("example.com", "v1", "Widget"), gvr: gvr("example.com", "v1", "widgets")})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	got, ok := r.Lookup(schema.GroupKind{Group: "example.com", Kind: "Widget"})
	if !ok || got.Name() != "a" {
		t.Fatalf("Lookup by GroupKind failed: got %v ok %v", got, ok)
	}
	if !r.IsRegisteredKind("Widget") {
		t.Fatal("IsRegisteredKind(Widget) = false, want true")
	}
	if _, ok := r.LookupByKind("Widget"); !ok {
		t.Fatal("LookupByKind(Widget) miss")
	}
	if r.IsRegisteredKind("Gadget") {
		t.Fatal("IsRegisteredKind(Gadget) = true, want false")
	}
	for _, gk := range []schema.GroupKind{
		{Group: "other.com", Kind: "Widget"},
		{Group: "example.com", Kind: "Gadget"},
	} {
		if got, ok := r.Lookup(gk); ok || got != nil {
			t.Fatalf("Lookup(%s) = %v, %t, want nil, false", gk, got, ok)
		}
	}
}

func TestNewRegistry_EmptyIsValid(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("empty registry should be valid: %v", err)
	}
	if got := r.List(); len(got) != 0 {
		t.Fatalf("empty registry List() = %v, want none", got)
	}
}

func TestNewRegistry_InvalidAdaptersReturnErrors(t *testing.T) {
	base := func(overrides ...fakeAdapter) []Adapter {
		adapters := []Adapter{fakeAdapter{name: "a", gvk: gvk("g.io", "v1", "A"), gvr: gvr("g.io", "v1", "as")}}
		for _, o := range overrides {
			adapters = append(adapters, o)
		}
		return adapters
	}
	testCases := []struct {
		name     string
		adapters []Adapter
	}{
		{
			name:     "nil adapter",
			adapters: []Adapter{nil},
		},
		{
			name:     "empty name",
			adapters: []Adapter{fakeAdapter{name: "", gvk: gvk("g.io", "v1", "A"), gvr: gvr("g.io", "v1", "as")}},
		},
		{
			name:     "empty kind",
			adapters: []Adapter{fakeAdapter{name: "noname", gvk: gvk("g.io", "v1", ""), gvr: gvr("g.io", "v1", "xs")}},
		},
		{
			name:     "empty GVR resource",
			adapters: []Adapter{fakeAdapter{name: "x", gvk: gvk("g.io", "v1", "A"), gvr: gvr("g.io", "v1", "")}},
		},
		{
			name:     "GVR group mismatch",
			adapters: []Adapter{fakeAdapter{name: "x", gvk: gvk("g.io", "v1", "A"), gvr: gvr("other.io", "v1", "as")}},
		},
		{
			name:     "GVR version mismatch",
			adapters: []Adapter{fakeAdapter{name: "x", gvk: gvk("g.io", "v1", "A"), gvr: gvr("g.io", "v2", "as")}},
		},
		{
			name:     "duplicate name",
			adapters: base(fakeAdapter{name: "a", gvk: gvk("g.io", "v1", "B"), gvr: gvr("g.io", "v1", "bs")}),
		},
		{
			name:     "duplicate GVK",
			adapters: base(fakeAdapter{name: "b", gvk: gvk("g.io", "v1", "A"), gvr: gvr("g.io", "v1", "bs")}),
		},
		{
			name:     "duplicate bare Kind across groups",
			adapters: base(fakeAdapter{name: "b", gvk: gvk("g2.io", "v1", "A"), gvr: gvr("g2.io", "v1", "as")}),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRegistry(tc.adapters...); err == nil {
				t.Fatal("expected NewRegistry to reject the invalid adapter set, got nil error")
			}
		})
	}
}

func TestRegistry_ListSorted(t *testing.T) {
	r, err := NewRegistry(
		fakeAdapter{name: "c", gvk: gvk("g.io", "v1", "C"), gvr: gvr("g.io", "v1", "cs")},
		fakeAdapter{name: "a", gvk: gvk("g.io", "v1", "A"), gvr: gvr("g.io", "v1", "as")},
		fakeAdapter{name: "b", gvk: gvk("g.io", "v1", "B"), gvr: gvr("g.io", "v1", "bs")},
	)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	got := r.List()
	if len(got) != 3 || got[0].Name() != "a" || got[1].Name() != "b" || got[2].Name() != "c" {
		t.Fatalf("List not sorted: %v", got)
	}
}
