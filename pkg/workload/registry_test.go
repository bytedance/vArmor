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
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

func gvk(group, version, kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: group, Version: version, Kind: kind}
}

func gvr(group, version, resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
}

func TestNewRegistry_AndLookup(t *testing.T) {
	r, err := NewRegistry(FakeAdapter{AdapterName: "a", AdapterGVK: gvk("example.com", "v1", "Widget"), AdapterGVR: gvr("example.com", "v1", "widgets")})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	got, ok := r.LookupGVK(gvk("example.com", "v1", "Widget"))
	if !ok || got.Name() != "a" {
		t.Fatalf("LookupGVK failed: got %v ok %v", got, ok)
	}
	if !r.IsRegisteredKind("Widget") {
		t.Fatal("IsRegisteredKind(Widget) = false, want true")
	}
	if byKind, ok := r.LookupByKind("Widget"); !ok || byKind.Name() != "a" {
		t.Fatalf("LookupByKind(Widget) = %v, %t, want adapter a", byKind, ok)
	}
	if r.IsRegisteredKind("Gadget") {
		t.Fatal("IsRegisteredKind(Gadget) = true, want false")
	}
	// A miss on any GVK dimension (group, version or kind) must resolve to
	// no adapter rather than falling back to another version of the same Kind.
	for _, miss := range []schema.GroupVersionKind{
		gvk("other.com", "v1", "Widget"),
		gvk("example.com", "v2", "Widget"),
		gvk("example.com", "v1", "Gadget"),
	} {
		if got, ok := r.LookupGVK(miss); ok || got != nil {
			t.Fatalf("LookupGVK(%s) = %v, %t, want nil, false", miss, got, ok)
		}
	}
}

func TestNewRegistry_MultiVersionSameKind(t *testing.T) {
	v1 := FakeAdapter{AdapterName: "widget-v1", AdapterGVK: gvk("g.io", "v1", "Widget"), AdapterGVR: gvr("g.io", "v1", "widgets")}
	v2 := FakeAdapter{AdapterName: "widget-v2", AdapterGVK: gvk("g.io", "v2", "Widget"), AdapterGVR: gvr("g.io", "v2", "widgets")}

	r, err := NewRegistry(v1, v2)
	if err != nil {
		t.Fatalf("adapters serving different versions of one Kind must coexist: %v", err)
	}

	// Admission routing is version-exact: each GVK resolves its own adapter
	// and must never fall through to the other served version.
	for _, want := range []FakeAdapter{v1, v2} {
		got, ok := r.LookupGVK(want.AdapterGVK)
		if !ok || got.Name() != want.AdapterName {
			t.Fatalf("LookupGVK(%s) = %v, %t, want adapter %q", want.AdapterGVK, got, ok, want.AdapterName)
		}
	}
	if got, ok := r.LookupGVK(gvk("g.io", "v3", "Widget")); ok || got != nil {
		t.Fatalf("unserved version must miss: LookupGVK returned %v, %t", got, ok)
	}

	// The group-less Target.Kind resolves regardless of which version an
	// object arrives as. LookupByKind exposes the first-registered adapter.
	if !r.IsRegisteredKind("Widget") {
		t.Fatal("IsRegisteredKind(Widget) = false, want true")
	}
	first, ok := r.LookupByKind("Widget")
	if !ok || first.Name() != "widget-v1" {
		t.Fatalf("LookupByKind(Widget) = %v, %t, want first-registered widget-v1", first, ok)
	}
	if got := r.List(); len(got) != 2 {
		t.Fatalf("List() returned %d adapters, want 2", len(got))
	}
}

// TestIsBuiltInKind locks the membership gate shared by registry admission,
// policy validation and mutation dispatch, including its exact-case match.
func TestIsBuiltInKind(t *testing.T) {
	testCases := []struct {
		kind string
		want bool
	}{
		{"Pod", true},
		{"Deployment", true},
		{"StatefulSet", true},
		{"DaemonSet", true},
		{"pod", false},
		{"deployment", false},
		{"", false},
		{"Job", false},
		{"CronJob", false},
		{"Widget", false},
	}
	for _, tc := range testCases {
		t.Run(tc.kind, func(t *testing.T) {
			if got := IsBuiltInKind(tc.kind); got != tc.want {
				t.Fatalf("IsBuiltInKind(%q) = %t, want %t", tc.kind, got, tc.want)
			}
		})
	}
}

// TestNewRegistry_MultiVersionMatchConditions covers the acceptance side of
// the MatchConditions guard; divergent cases are in the error table below.
func TestNewRegistry_MultiVersionMatchConditions(t *testing.T) {
	conditions := []admissionregistrationv1.MatchCondition{
		{Name: "exclude-lease-objects", Expression: "!has(object.metadata.labels['lease'])"},
	}
	testCases := []struct {
		name      string
		v1Options WebhookOptions
		v2Options WebhookOptions
	}{
		{
			name:      "identical non-empty conditions are accepted",
			v1Options: WebhookOptions{MatchConditions: conditions},
			// A separate slice with identical content proves value, not
			// pointer, comparison.
			v2Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "exclude-lease-objects", Expression: "!has(object.metadata.labels['lease'])"},
			}},
		},
		{
			name:      "nil and empty-slice conditions are equivalent",
			v1Options: WebhookOptions{},
			v2Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{}},
		},
		{
			name: "same condition set in a different order is accepted",
			v1Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "exclude-lease-objects", Expression: "!has(object.metadata.labels['lease'])"},
				{Name: "exclude-dry-run", Expression: "!dryRun()"},
			}},
			v2Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "exclude-dry-run", Expression: "!dryRun()"},
				{Name: "exclude-lease-objects", Expression: "!has(object.metadata.labels['lease'])"},
			}},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v1 := FakeAdapter{
				AdapterName: "widget-v1",
				AdapterGVK:  gvk("g.io", "v1", "Widget"),
				AdapterGVR:  gvr("g.io", "v1", "widgets"),
				Options:     tc.v1Options,
			}
			v2 := FakeAdapter{
				AdapterName: "widget-v2",
				AdapterGVK:  gvk("g.io", "v2", "Widget"),
				AdapterGVR:  gvr("g.io", "v2", "widgets"),
				Options:     tc.v2Options,
			}
			r, err := NewRegistry(v1, v2)
			if err != nil {
				t.Fatalf("versioned adapters with compatible MatchConditions must coexist: %v", err)
			}
			if got := r.List(); len(got) != 2 {
				t.Fatalf("List() returned %d adapters, want 2", len(got))
			}
		})
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
	base := func(overrides ...FakeAdapter) []Adapter {
		adapters := []Adapter{FakeAdapter{AdapterName: "a", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "as")}}
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
			adapters: []Adapter{FakeAdapter{AdapterName: "", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "as")}},
		},
		{
			name:     "empty kind",
			adapters: []Adapter{FakeAdapter{AdapterName: "noname", AdapterGVK: gvk("g.io", "v1", ""), AdapterGVR: gvr("g.io", "v1", "xs")}},
		},
		{
			name:     "empty GVR resource",
			adapters: []Adapter{FakeAdapter{AdapterName: "x", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "")}},
		},
		{
			name:     "GVR group mismatch",
			adapters: []Adapter{FakeAdapter{AdapterName: "x", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("other.io", "v1", "as")}},
		},
		{
			name:     "GVR version mismatch",
			adapters: []Adapter{FakeAdapter{AdapterName: "x", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v2", "as")}},
		},
		{
			name:     "duplicate name",
			adapters: base(FakeAdapter{AdapterName: "a", AdapterGVK: gvk("g.io", "v1", "B"), AdapterGVR: gvr("g.io", "v1", "bs")}),
		},
		{
			name:     "duplicate GVK",
			adapters: base(FakeAdapter{AdapterName: "b", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "bs")}),
		},
		{
			name:     "duplicate bare Kind across groups",
			adapters: base(FakeAdapter{AdapterName: "b", AdapterGVK: gvk("g2.io", "v1", "A"), AdapterGVR: gvr("g2.io", "v1", "as")}),
		},
		{
			name: "GVR resource mismatch across served versions",
			// Same group/Kind, distinct version is allowed, but every served
			// version of a CRD shares one REST collection: the plural resource
			// must match or webhook rules would become incoherent.
			adapters: base(FakeAdapter{AdapterName: "b", AdapterGVK: gvk("g.io", "v2", "A"), AdapterGVR: gvr("g.io", "v2", "av2s")}),
		},
		{
			name:     "core group is reserved for the built-in Pod",
			adapters: []Adapter{FakeAdapter{AdapterName: "core-widget", AdapterGVK: gvk("", "v1", "Widget"), AdapterGVR: gvr("", "v1", "widgets")}},
		},
		{
			name:     "apps group is reserved for the built-in workload kinds",
			adapters: []Adapter{FakeAdapter{AdapterName: "apps-widget", AdapterGVK: gvk("apps", "v1", "Widget"), AdapterGVR: gvr("apps", "v1", "widgets")}},
		},
		{
			name:     "built-in Kind Pod is reserved in any group",
			adapters: []Adapter{FakeAdapter{AdapterName: "shadow-pod", AdapterGVK: gvk("custom.io", "v1", "Pod"), AdapterGVR: gvr("custom.io", "v1", "pods")}},
		},
		{
			name:     "built-in Kind Deployment is reserved in any group",
			adapters: []Adapter{FakeAdapter{AdapterName: "shadow-deploy", AdapterGVK: gvk("custom.io", "v1", "Deployment"), AdapterGVR: gvr("custom.io", "v1", "deployments")}},
		},
		{
			name:     "built-in Kind StatefulSet is reserved in any group",
			adapters: []Adapter{FakeAdapter{AdapterName: "shadow-sts", AdapterGVK: gvk("custom.io", "v1", "StatefulSet"), AdapterGVR: gvr("custom.io", "v1", "statefulsets")}},
		},
		{
			name:     "built-in Kind DaemonSet is reserved in any group",
			adapters: []Adapter{FakeAdapter{AdapterName: "shadow-ds", AdapterGVK: gvk("custom.io", "v1", "DaemonSet"), AdapterGVR: gvr("custom.io", "v1", "daemonsets")}},
		},
		{
			name:     "invalid API group characters",
			adapters: []Adapter{FakeAdapter{AdapterName: "x", AdapterGVK: gvk("my_team.io", "v1", "A"), AdapterGVR: gvr("my_team.io", "v1", "as")}},
		},
		{
			name:     "invalid GVR resource characters",
			adapters: []Adapter{FakeAdapter{AdapterName: "x", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "BadName")}},
		},
		{
			name:     "invalid GVK Kind characters",
			adapters: []Adapter{FakeAdapter{AdapterName: "x", AdapterGVK: gvk("g.io", "v1", "Bad Kind"), AdapterGVR: gvr("g.io", "v1", "bs")}},
		},
		{
			name: "duplicate group/resource tuple claimed by distinct Kinds",
			// Same (group, plural) as the base adapter but a different Kind:
			// both would render one entry name and fuse through the merge.
			adapters: base(FakeAdapter{AdapterName: "b", AdapterGVK: gvk("g.io", "v1", "B"), AdapterGVR: gvr("g.io", "v1", "as")}),
		},
		{
			name: "divergent MatchConditions across served versions",
			adapters: base(FakeAdapter{
				AdapterName: "b",
				AdapterGVK:  gvk("g.io", "v2", "A"),
				AdapterGVR:  gvr("g.io", "v2", "as"),
				Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
					{Name: "skip-leases", Expression: "!has(object.metadata.labels['lease'])"},
				}},
			}),
		},
		{
			name: "same condition Names with different Expressions across served versions",
			adapters: []Adapter{
				FakeAdapter{
					AdapterName: "a-v1", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "as"),
					Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
						{Name: "skip-leases", Expression: "!has(object.metadata.labels['lease'])"},
					}},
				},
				FakeAdapter{
					AdapterName: "a-v2", AdapterGVK: gvk("g.io", "v2", "A"), AdapterGVR: gvr("g.io", "v2", "as"),
					Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
						{Name: "skip-leases", Expression: "!has(object.metadata.annotations['lease'])"},
					}},
				},
			},
		},
		{
			name: "condition renamed across served versions",
			adapters: []Adapter{
				FakeAdapter{
					AdapterName: "a-v1", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "as"),
					Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
						{Name: "skip-leases", Expression: "!has(object.metadata.labels['lease'])"},
					}},
				},
				FakeAdapter{
					AdapterName: "a-v2", AdapterGVK: gvk("g.io", "v2", "A"), AdapterGVR: gvr("g.io", "v2", "as"),
					Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
						{Name: "exclude-leases", Expression: "!has(object.metadata.labels['lease'])"},
					}},
				},
			},
		},
		{
			name: "extra condition on a later served version",
			adapters: []Adapter{
				FakeAdapter{
					AdapterName: "a-v1", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "as"),
					Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
						{Name: "skip-leases", Expression: "!has(object.metadata.labels['lease'])"},
					}},
				},
				FakeAdapter{
					AdapterName: "a-v2", AdapterGVK: gvk("g.io", "v2", "A"), AdapterGVR: gvr("g.io", "v2", "as"),
					Options: WebhookOptions{MatchConditions: []admissionregistrationv1.MatchCondition{
						{Name: "skip-leases", Expression: "!has(object.metadata.labels['lease'])"},
						{Name: "exclude-dry-run", Expression: "!dryRun()"},
					}},
				},
			},
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
		FakeAdapter{AdapterName: "c", AdapterGVK: gvk("g.io", "v1", "C"), AdapterGVR: gvr("g.io", "v1", "cs")},
		FakeAdapter{AdapterName: "a", AdapterGVK: gvk("g.io", "v1", "A"), AdapterGVR: gvr("g.io", "v1", "as")},
		FakeAdapter{AdapterName: "b", AdapterGVK: gvk("g.io", "v1", "B"), AdapterGVR: gvr("g.io", "v1", "bs")},
	)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	got := r.List()
	if len(got) != 3 || got[0].Name() != "a" || got[1].Name() != "b" || got[2].Name() != "c" {
		t.Fatalf("List not sorted: %v", got)
	}
}

// TestWebhookNameIndex drives the uniqueness guard with synthetic names,
// since a real SHA-256 collision cannot be constructed on demand.
func TestWebhookNameIndex(t *testing.T) {
	t.Run("first claim succeeds", func(t *testing.T) {
		idx := webhookNameIndex{}
		if err := idx.add("mutate-a.g.io.varmor.org", "mutate-a.g.io.varmor.org", "a-v1"); err != nil {
			t.Fatalf("first claim rejected: %v", err)
		}
	})

	t.Run("same raw identity may reclaim the rendered name", func(t *testing.T) {
		// Served versions share one raw identity and must merge, not error.
		idx := webhookNameIndex{}
		if err := idx.add("rendered", "raw-identity", "a-v1"); err != nil {
			t.Fatalf("first claim rejected: %v", err)
		}
		if err := idx.add("rendered", "raw-identity", "a-v2"); err != nil {
			t.Fatalf("re-claim by the same identity rejected: %v", err)
		}
	})

	t.Run("distinct identities sharing a rendered name are rejected", func(t *testing.T) {
		idx := webhookNameIndex{}
		if err := idx.add("rendered", "raw-one", "a-v1"); err != nil {
			t.Fatalf("first claim rejected: %v", err)
		}
		if err := idx.add("rendered", "raw-two", "b-v1"); err == nil {
			t.Fatal("expected a name collision to be rejected, got nil error")
		}
	})
}

// TestNewRegistry_OverLongIdentityAccepted: over-long identities still
// register through truncation, and served versions share one entry name.
func TestNewRegistry_OverLongIdentityAccepted(t *testing.T) {
	resource := strings.Repeat("a", 63) // maximum DNS label length
	group := strings.Repeat("b.", 126) + "b"
	if len(group) != validation.DNS1123SubdomainMaxLength {
		t.Fatalf("test setup: group length %d, want 253", len(group))
	}

	v1 := FakeAdapter{AdapterName: "long-v1", AdapterGVK: gvk(group, "v1", "Long"), AdapterGVR: gvr(group, "v1", resource)}
	v2 := FakeAdapter{AdapterName: "long-v2", AdapterGVK: gvk(group, "v2", "Long"), AdapterGVR: gvr(group, "v2", resource)}

	r, err := NewRegistry(v1, v2)
	if err != nil {
		t.Fatalf("over-long identity must register through truncation, got error: %v", err)
	}
	if len(r.List()) != 2 {
		t.Fatalf("expected both served versions registered, got %d", len(r.List()))
	}

	rendered, truncated := WebhookEntryName(v1)
	if !truncated {
		t.Fatal("test setup: identity must overflow the raw name limit")
	}
	if errs := validation.IsDNS1123Subdomain(rendered); len(errs) != 0 {
		t.Fatalf("rendered entry name invalid: %v", errs)
	}
}
