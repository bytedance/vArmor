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
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Registry holds the workload adapters available to a manager process. The
// composition root (cmd/varmor) takes the config-enabled subset of the
// global catalog populated via Register and builds exactly one Registry via
// NewRegistry. It is immutable afterwards, so admission routing cannot
// change at runtime and the read methods need no locking.
type Registry struct {
	// byKind indexes the bare Kind string. vArmor's Target carries a Kind
	// without an API group, so a bare Kind must map to exactly one adapter.
	byKind map[string]Adapter
	// order preserves construction order; List() sorts it for determinism.
	order []Adapter
}

// NewRegistry validates and indexes the given adapters. It returns an error
// on any nil adapter, empty identity, GVR/GVK mismatch, or collision
// (duplicate Name or bare Kind) so that ambiguous Target.Kind values or
// misrouted admissions fail at startup.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	r := &Registry{
		byKind: map[string]Adapter{},
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
		for _, existing := range r.order {
			if existing.Name() == name {
				return nil, fmt.Errorf("workload: duplicate adapter name %q", name)
			}
		}
		if existing, ok := r.byKind[kind]; ok {
			return nil, fmt.Errorf("workload: adapter %q duplicates bare Kind %q already registered by %q; Target.Kind is group-less and must be unique", name, kind, existing.Name())
		}
		r.byKind[kind] = a
		r.order = append(r.order, a)
	}
	return r, nil
}

// Lookup returns the adapter registered for the given GroupKind. A bare Kind
// is unique in the registry, but the registered adapter may belong to a
// different API group than the one requested, so the group is checked before
// returning a match.
func (r *Registry) Lookup(gk schema.GroupKind) (Adapter, bool) {
	a, ok := r.byKind[gk.Kind]
	if !ok {
		return nil, false
	}
	if a.GVK().Group != gk.Group {
		return nil, false
	}
	return a, true
}

// LookupByKind returns the adapter for the bare Kind string. It backs the
// group-less Target.Kind resolution.
func (r *Registry) LookupByKind(kind string) (Adapter, bool) {
	a, ok := r.byKind[kind]
	return a, ok
}

// IsRegisteredKind reports whether any adapter handles the bare Kind.
func (r *Registry) IsRegisteredKind(kind string) bool {
	_, ok := r.byKind[kind]
	return ok
}

// List returns all adapters sorted by Name for deterministic iteration
// (webhook entry generation, tests).
func (r *Registry) List() []Adapter {
	out := make([]Adapter, len(r.order))
	copy(out, r.order)
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
