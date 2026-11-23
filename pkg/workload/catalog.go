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

import "sync"

// Two-layer adapter model:
//
//   - The global catalog (this file) holds every adapter compiled into the
//     binary. Adapter packages populate it from init functions via Register,
//     so linking a package is sufficient to make its adapter discoverable.
//   - The runtime Registry (registry.go) is an immutable, validated object
//     built by the composition root from every adapter in the catalog. It
//     stays the single validation point for nil adapters, identity
//     collisions and GVR/GVK consistency, and it stays the seam tests use to
//     construct arbitrary adapter worlds without touching global state.
//
// The catalog cannot itself enforce an `enabled` policy because init
// functions run before any configuration (flags, ConfigMaps, API clients)
// exists.
var (
	catalogMu sync.RWMutex
	catalog   []Adapter
)

// Register appends an adapter to the process-wide catalog. Adapter packages
// call it from an init function so that merely linking the package into the
// binary makes the adapter discoverable; the Go linker only runs init for
// packages reachable from the import graph, so a blank import in the wiring
// layer is still required to compile an adapter in.
//
// Register intentionally performs no validation. Nil adapters, identity
// collisions and GVR/GVK mismatches surface as structured errors when the
// composition root builds the runtime Registry via NewRegistry, rather than
// as pre-logging panics from init.
func Register(a Adapter) {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	catalog = append(catalog, a)
}

// RegisteredAdapters returns a defensive copy of every adapter compiled into
// the binary, in registration order. The composition root constructs the
// immutable runtime Registry from this full set; any future
// workloadAdapters `enabled` filtering will be applied at the same seam.
// Callers may freely mutate the returned slice without affecting subsequent
// registrations or readers.
func RegisteredAdapters() []Adapter {
	catalogMu.RLock()
	defer catalogMu.RUnlock()
	return append([]Adapter(nil), catalog...)
}

// resetCatalogForTest empties the catalog. It is unexported because only
// in-package tests need to control catalog state directly; external packages
// build isolated registries through NewRegistry and never read the catalog.
func resetCatalogForTest() {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	catalog = nil
}
