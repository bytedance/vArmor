// Copyright 2024 vArmor Authors
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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Test_RateLimit_ConcurrentBoundary exercises the subscriber-count 0<->1
// boundary that drives setRateLimit/restoreRateLimit. Multiple subscribers are
// concurrently added and removed so the count repeatedly crosses 0<->1, which
// is exactly where savedRateLimit is saved and restored.
//
// Before the rateLimitMu fix, the count check and the sysctl read-modify-write
// were decoupled across the chsMu release, so a concurrent Add could observe an
// already-zeroed sysctl value and overwrite savedRateLimit with 0. After that,
// restoreRateLimit (guarded by savedRateLimit != 0) would silently skip and the
// host printk_ratelimit would be left permanently at 0.
//
// This test fakes the sysctl layer with an in-memory value seeded to a non-zero
// original. It asserts two invariants that only hold when the boundary decision
// and the save/restore are atomic:
//  1. savedRateLimit is never corrupted to 0 while a save is in effect.
//  2. After all churn drains to zero subscribers, the fake sysctl value is
//     restored to the original non-zero value.
//
// Run with -race to also catch any unsynchronized access to savedRateLimit.
func Test_RateLimit_ConcurrentBoundary(t *testing.T) {
	const originalRateLimit uint64 = 5

	// fakeSysctl is an in-memory stand-in for /proc/sys/kernel/printk_ratelimit.
	var sysctlMu sync.Mutex
	fakeSysctl := originalRateLimit

	origRead := sysctlRead
	origWrite := sysctlWrite
	defer func() {
		sysctlRead = origRead
		sysctlWrite = origWrite
	}()

	sysctlRead = func(path string) (string, error) {
		sysctlMu.Lock()
		defer sysctlMu.Unlock()
		return fmt.Sprintf("%d", fakeSysctl), nil
	}
	sysctlWrite = func(path string, value uint64) error {
		sysctlMu.Lock()
		defer sysctlMu.Unlock()
		fakeSysctl = value
		return nil
	}

	auditor := &Auditor{
		auditEventChs: make(map[string]chan<- string),
		bpfEventChs:   make(map[string]chan<- BpfEvent),
		log:           log.Log.WithName("test"),
	}

	var corrupted int32

	const workers = 8
	const iters = 3000
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ac := make(chan string, 1)
			bc := make(chan BpfEvent, 1)
			acPtr := ac
			bcPtr := bc
			name := fmt.Sprintf("subscriber-%d", id)
			for i := 0; i < iters; i++ {
				auditor.AddBehaviorEventNotifyChs(name, &acPtr, &bcPtr)
				// This worker's own subscriber keeps the count >= 1 until its
				// Delete below, so savedRateLimit must still remember the
				// original non-zero value. Read it under rateLimitMu to stay
				// race-free with concurrent set/restore.
				auditor.rateLimitMu.Lock()
				saved := auditor.savedRateLimit
				auditor.rateLimitMu.Unlock()
				if saved == 0 {
					atomic.StoreInt32(&corrupted, 1)
				}
				auditor.DeleteBehaviorEventNotifyCh(name)
			}
		}(w)
	}

	wg.Wait()

	if atomic.LoadInt32(&corrupted) != 0 {
		t.Fatal("savedRateLimit was corrupted to 0 while a subscriber was active; the boundary decision and sysctl save/restore are not atomic")
	}

	// All subscribers gone: the host sysctl must be restored to the original.
	sysctlMu.Lock()
	final := fakeSysctl
	sysctlMu.Unlock()
	if final != originalRateLimit {
		t.Fatalf("printk_ratelimit not restored: got %d, want %d", final, originalRateLimit)
	}
}
