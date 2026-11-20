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
)

func newCatalogFake(name string) FakeAdapter {
	return FakeAdapter{
		AdapterName: name,
		AdapterGVK:  gvk("example.com", "v1", name),
		AdapterGVR:  gvr("example.com", "v1", name+"s"),
	}
}

func TestRegister_AppendsInRegistrationOrder(t *testing.T) {
	t.Cleanup(resetCatalogForTest)

	first, second := newCatalogFake("First"), newCatalogFake("Second")
	Register(first)
	Register(second)

	got := RegisteredAdapters()
	if len(got) != 2 {
		t.Fatalf("RegisteredAdapters() returned %d adapters, want 2", len(got))
	}
	if got[0].Name() != "First" || got[1].Name() != "Second" {
		t.Fatalf("registration order not preserved: %q, %q", got[0].Name(), got[1].Name())
	}
}

func TestRegisteredAdapters_ReturnsDefensiveCopy(t *testing.T) {
	t.Cleanup(resetCatalogForTest)

	Register(newCatalogFake("Solo"))

	snapshot := RegisteredAdapters()
	snapshot[0] = nil
	snapshot = append(snapshot, newCatalogFake("Injected"))

	again := RegisteredAdapters()
	if len(again) != 1 || again[0] == nil || again[0].Name() != "Solo" {
		t.Fatalf("catalog mutated through returned slice: %v", again)
	}
}

func TestCatalog_ValidationDeferredToNewRegistry(t *testing.T) {
	t.Cleanup(resetCatalogForTest)

	// Register itself must accept a nil adapter without panicking; the
	// structured failure is produced when the runtime registry is built.
	Register(nil)
	if got := RegisteredAdapters(); len(got) != 1 {
		t.Fatalf("catalog should hold the unvalidated entry, got %d", len(got))
	}
	if _, err := NewRegistry(RegisteredAdapters()...); err == nil {
		t.Fatal("NewRegistry must reject a nil adapter sourced from the catalog")
	}
}

func TestCatalog_EmptyByDefault(t *testing.T) {
	t.Cleanup(resetCatalogForTest)
	resetCatalogForTest()

	if got := RegisteredAdapters(); len(got) != 0 {
		t.Fatalf("reset catalog should be empty, got %v", got)
	}
}
