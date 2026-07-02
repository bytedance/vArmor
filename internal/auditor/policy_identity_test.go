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

package audit

import (
	"sync"
	"testing"
)

// newIdentityTestAuditor returns a minimal Auditor with only the policy
// identity cache initialised, so the identity API can be exercised without the
// full NewAuditor construction (which requires host state such as audit log
// files).
func newIdentityTestAuditor() *Auditor {
	return &Auditor{
		policyIdentityCache: make(map[string]PolicyIdentity),
	}
}

func TestPolicyIdentityUpsertLookupDelete(t *testing.T) {
	auditor := newIdentityTestAuditor()

	// Miss on an unknown profile yields a zero value and ok=false.
	if id, ok := auditor.lookupPolicyIdentity("varmor-demo-nginx"); ok || id != (PolicyIdentity{}) {
		t.Fatalf("expected miss for unknown profile, got id=%+v ok=%v", id, ok)
	}

	// Upsert a namespaced VarmorPolicy identity.
	ns := PolicyIdentity{Kind: "VarmorPolicy", Name: "nginx", Namespace: "demo"}
	auditor.UpsertPolicyIdentity("varmor-demo-nginx", ns)
	if id, ok := auditor.lookupPolicyIdentity("varmor-demo-nginx"); !ok || id != ns {
		t.Fatalf("expected namespaced identity %+v, got id=%+v ok=%v", ns, id, ok)
	}

	// Upsert overwrites the existing entry.
	updated := PolicyIdentity{Kind: "VarmorPolicy", Name: "nginx", Namespace: "demo2"}
	auditor.UpsertPolicyIdentity("varmor-demo-nginx", updated)
	if id, _ := auditor.lookupPolicyIdentity("varmor-demo-nginx"); id != updated {
		t.Fatalf("expected upsert to overwrite, got %+v", id)
	}

	// Cluster-scoped identity carries an empty namespace.
	cluster := PolicyIdentity{Kind: "VarmorClusterPolicy", Name: "block-exec", Namespace: ""}
	auditor.UpsertPolicyIdentity("varmor-cluster-varmor-block-exec", cluster)
	if id, ok := auditor.lookupPolicyIdentity("varmor-cluster-varmor-block-exec"); !ok || id != cluster {
		t.Fatalf("expected cluster identity %+v, got id=%+v ok=%v", cluster, id, ok)
	}

	// Delete removes only the targeted entry.
	auditor.DeletePolicyIdentity("varmor-demo-nginx")
	if _, ok := auditor.lookupPolicyIdentity("varmor-demo-nginx"); ok {
		t.Fatalf("expected deleted profile to miss")
	}
	if _, ok := auditor.lookupPolicyIdentity("varmor-cluster-varmor-block-exec"); !ok {
		t.Fatalf("expected unrelated entry to survive delete")
	}
}

// TestPolicyIdentityConcurrentAccess exercises the RWMutex under -race by
// running concurrent upserts, deletes and lookups against the cache.
func TestPolicyIdentityConcurrentAccess(t *testing.T) {
	auditor := newIdentityTestAuditor()

	const workers = 16
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(workers * 3)

	// Writers: upsert.
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				auditor.UpsertPolicyIdentity("varmor-demo-nginx",
					PolicyIdentity{Kind: "VarmorPolicy", Name: "nginx", Namespace: "demo"})
			}
		}()
	}

	// Deleters.
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				auditor.DeletePolicyIdentity("varmor-demo-nginx")
			}
		}()
	}

	// Readers.
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, _ = auditor.lookupPolicyIdentity("varmor-demo-nginx")
			}
		}()
	}

	wg.Wait()
}
