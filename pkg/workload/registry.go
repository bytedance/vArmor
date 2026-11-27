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
	"cmp"
	"fmt"
	"slices"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Registry holds the workload adapters available to a manager process. The
// composition root (cmd/varmor) builds exactly one Registry via NewRegistry
// from every adapter in the global catalog populated via Register. It is
// immutable afterwards, so admission routing cannot change at runtime and
// the read methods need no locking.
type Registry struct {
	// byGVK is the admission-routing index. Admission requests carry the
	// full GroupVersionKind, so two adapters may serve different versions
	// of one GroupKind and remain independently addressable here.
	byGVK map[schema.GroupVersionKind]Adapter
	// byKind backs resolution of the group-less, version-less Target.Kind
	// carried by a VarmorPolicy. One bare Kind maps to every served-version
	// adapter (usually one). LookupByKind returns the first-registered
	// entry; callers must only rely on the boolean and never on which
	// version was returned.
	byKind map[string][]Adapter
	// groupByKind records the single API group allowed for each bare Kind,
	// keeping the group-less Target.Kind unambiguous across adapters.
	groupByKind map[string]string
	// resourceByKind records the single GVR resource of each bare Kind so
	// versioned adapters sharing one Kind can be checked against the common
	// REST collection in O(1) instead of scanning earlier registrations.
	resourceByKind map[string]string
	// resourceByGroup maps each (group, resource) tuple to its owning Kind,
	// rejecting two Kinds that would fuse into one webhook entry name.
	resourceByGroup map[string]string
	// names makes duplicate Name detection O(1); construction order is
	// still preserved separately in order for first-registered resolution.
	names map[string]struct{}
	// webhookNames indexes rendered entry names to reject distinct
	// identities collapsing onto one name through a hash-suffix collision.
	webhookNames webhookNameIndex
	// order preserves construction order; List() sorts it for determinism.
	order []Adapter
}

// webhookNameClaim records the raw identity behind a rendered entry name and
// the adapter that first claimed it.
type webhookNameClaim struct {
	raw         string
	adapterName string
}

// webhookNameIndex maps a rendered entry name to its claim. Re-claims are
// allowed only for the same raw identity (served versions of one Kind).
type webhookNameIndex map[string]webhookNameClaim

func (idx webhookNameIndex) add(rendered, raw, adapterName string) error {
	if existing, ok := idx[rendered]; ok && existing.raw != raw {
		return fmt.Errorf("workload: adapter %q renders webhook entry name %q, colliding with adapter %q that has a distinct resource/group identity", adapterName, rendered, existing.adapterName)
	}
	idx[rendered] = webhookNameClaim{raw: raw, adapterName: adapterName}
	return nil
}

// NewRegistry validates and indexes the custom adapters, failing at startup
// on nil/empty or non-DNS-1123 identities, GVR/GVK mismatches, duplicate
// names, GVKs or (group, resource) tuples, reserved built-in Kinds or
// core/apps groups, and divergent adapters across served versions of one
// Kind. Adapters serving different versions of one group/Kind are allowed.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	r := &Registry{
		byGVK:           map[schema.GroupVersionKind]Adapter{},
		byKind:          map[string][]Adapter{},
		groupByKind:     map[string]string{},
		resourceByKind:  map[string]string{},
		resourceByGroup: map[string]string{},
		names:           map[string]struct{}{},
		webhookNames:    webhookNameIndex{},
	}
	for _, a := range adapters {
		if a == nil {
			return nil, fmt.Errorf("workload: cannot register a nil adapter")
		}
		name := a.Name()
		gvk := a.GVK()
		kind := gvk.Kind
		if name == "" {
			return nil, fmt.Errorf("workload: adapter %T returned an empty Name()", a)
		}
		if kind == "" {
			return nil, fmt.Errorf("workload: adapter %q returned an empty GVK Kind", name)
		}
		// Native dispatch matches the bare Kind without consulting the
		// group, so reusing a reserved Kind name would shadow this adapter.
		if IsBuiltInKind(kind) {
			return nil, fmt.Errorf("workload: adapter %q claims built-in Kind %q in group %q; the native kind switch dispatches on the Kind name without consulting the group, so this adapter would be shadowed and must use a different Kind", name, kind, gvk.Group)
		}
		// Mirror the CRD spec.names.kind rule so an adapter that cannot
		// correspond to an installed CRD fails at startup.
		if errs := validation.IsQualifiedName(kind); len(errs) > 0 {
			return nil, fmt.Errorf("workload: adapter %q has invalid GVK Kind %q: %s", name, kind, strings.Join(errs, ", "))
		}
		// The registry holds custom (CRD) adapters only. The four built-in
		// kinds — core/v1 Pod and the apps/v1 workloads — keep their own
		// hard-coded, fail-open dispatch and typed decode path, so an
		// adapter claiming either API group would shadow that path and is a
		// configuration error.
		if gvk.Group == "" || gvk.Group == "apps" {
			return nil, fmt.Errorf("workload: adapter %q claims built-in API group %q; the core and apps groups are served by the built-in kind switch and cannot be registered as custom adapters", name, gvk.Group)
		}
		// Group renders into admission rules and the entry name, both
		// validated by the API server as DNS-1123 subdomains.
		if errs := validation.IsDNS1123Subdomain(gvk.Group); len(errs) > 0 {
			return nil, fmt.Errorf("workload: adapter %q has invalid API group %q: %s", name, gvk.Group, strings.Join(errs, ", "))
		}
		// GVR feeds the generated webhook rules directly, so an inconsistent
		// identity would route admissions to the wrong REST resource. The
		// resource name cannot be machine-checked against Kind, but its group
		// and version must match GVK exactly.
		gvr := a.GVR()
		if gvr.Resource == "" {
			return nil, fmt.Errorf("workload: adapter %q returned an empty GVR Resource", name)
		}
		if gvr.Group != gvk.Group || gvr.Version != gvk.Version {
			return nil, fmt.Errorf("workload: adapter %q GVR %s group/version must match its GVK %s", name, gvr, gvk)
		}
		// The plural resource renders into rules and the entry name as a
		// DNS-1123 label.
		if errs := validation.IsDNS1123Label(gvr.Resource); len(errs) > 0 {
			return nil, fmt.Errorf("workload: adapter %q has invalid GVR resource %q: %s", name, gvr.Resource, strings.Join(errs, ", "))
		}
		if _, exists := r.names[name]; exists {
			return nil, fmt.Errorf("workload: duplicate adapter name %q", name)
		}
		if existing, ok := r.byGVK[gvk]; ok {
			return nil, fmt.Errorf("workload: adapter %q duplicates GVK %s already registered by %q", name, gvk, existing.Name())
		}
		// A bare Kind must belong to exactly one API group: Target.Kind has
		// no group field, so a cross-group collision could never be resolved
		// deterministically. Within one group, additional adapters are
		// treated as further served versions of the same Kind.
		if group, ok := r.groupByKind[kind]; ok {
			if group != gvk.Group {
				return nil, fmt.Errorf("workload: adapter %q claims bare Kind %q in group %q, already registered in group %q; Target.Kind is group-less and must map to one group", name, kind, gvk.Group, group)
			}
			// Every served version of a CRD addresses the same REST
			// collection, so versioned adapters of one Kind must share the
			// plural resource name. Diverging values would produce
			// incoherent webhook rules.
			if expected := r.resourceByKind[kind]; expected != gvr.Resource {
				return nil, fmt.Errorf("workload: adapter %q GVR resource %q for Kind %q must match resource %q used by adapter %q; all served versions share one REST collection", name, gvr.Resource, kind, expected, r.byKind[kind][0].Name())
			}
			// The merged entry keeps only the first adapter's
			// MatchConditions, so served versions must declare the same
			// Name/Expression set.
			first := r.byKind[kind][0]
			if !matchConditionsEqual(first.DefaultWebhookOptions().MatchConditions, a.DefaultWebhookOptions().MatchConditions) {
				return nil, fmt.Errorf("workload: adapter %q declares MatchConditions that differ from adapter %q serving the same Kind %q; versioned adapters share one webhook entry whose MatchConditions come from the first adapter, so divergent conditions would be silently dropped", name, first.Name(), kind)
			}
		} else {
			r.groupByKind[kind] = gvk.Group
			r.resourceByKind[kind] = gvr.Resource
		}
		// One (group, resource) tuple renders one webhook entry name; a
		// second Kind claiming it would fuse through the merge. Same-Kind
		// re-claims are additional served versions and stay allowed.
		resourceKey := gvr.Group + "/" + gvr.Resource
		if ownerKind, ok := r.resourceByGroup[resourceKey]; ok && ownerKind != kind {
			return nil, fmt.Errorf("workload: adapter %q claims (group, resource) %q for Kind %q, already claimed by Kind %q; each REST collection maps to exactly one Kind", name, resourceKey, kind, ownerKind)
		}
		r.resourceByGroup[resourceKey] = kind
		// Reject distinct identities rendering the same entry name; in
		// practice only a hash-suffix collision can trigger this.
		entryName, _ := WebhookEntryName(a)
		if err := r.webhookNames.add(entryName, rawWebhookEntryName(a), name); err != nil {
			return nil, err
		}
		r.names[name] = struct{}{}
		r.byGVK[gvk] = a
		r.byKind[kind] = append(r.byKind[kind], a)
		r.order = append(r.order, a)
	}
	return r, nil
}

// matchConditionsEqual compares CEL conditions as a Name→Expression set:
// order is irrelevant (conditions form an AND gate with unique Names) and
// nil equals empty. Any renamed, added, removed or re-expressed condition
// is divergence, since the merged entry keeps only the first adapter's set.
func matchConditionsEqual(a, b []admissionregistrationv1.MatchCondition) bool {
	if len(a) != len(b) {
		return false
	}
	expressions := make(map[string]string, len(a))
	for _, c := range a {
		expressions[c.Name] = c.Expression
	}
	for _, c := range b {
		if expr, ok := expressions[c.Name]; !ok || expr != c.Expression {
			return false
		}
	}
	return true
}

// LookupGVK returns the adapter serving the exact GroupVersionKind. Admission
// requests always carry a version, allowing per-version adapters to be
// selected unambiguously; an unknown group, version or kind misses.
func (r *Registry) LookupGVK(gvk schema.GroupVersionKind) (Adapter, bool) {
	a, ok := r.byGVK[gvk]
	return a, ok
}

// LookupByKind returns the first-registered adapter for the bare Kind string.
// It backs the group-less Target.Kind resolution: the boolean reports whether
// any served version of the Kind is registered, and the returned adapter must
// not be used for version-specific decisions (admission routes through
// LookupGVK instead).
func (r *Registry) LookupByKind(kind string) (Adapter, bool) {
	adapters, ok := r.byKind[kind]
	if !ok || len(adapters) == 0 {
		return nil, false
	}
	return adapters[0], true
}

// IsRegisteredKind reports whether any adapter handles the bare Kind.
func (r *Registry) IsRegisteredKind(kind string) bool {
	_, ok := r.LookupByKind(kind)
	return ok
}

// List returns all adapters sorted by Name for deterministic iteration
// (webhook entry generation, tests).
func (r *Registry) List() []Adapter {
	out := make([]Adapter, len(r.order))
	copy(out, r.order)
	slices.SortFunc(out, func(a, b Adapter) int { return cmp.Compare(a.Name(), b.Name()) })
	return out
}
