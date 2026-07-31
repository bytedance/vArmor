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
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Test_SubscriberChs_ConcurrentAccess exercises the subscriber channel maps
// under concurrent mutation and reads. It mirrors the production goroutine
// layout: BehaviorModeller.Run/stop add and remove subscribers while the
// audit-log tail goroutine (processAuditEvent) and the BPF ringbuf goroutine
// (readFromAuditEventRingBuf) look them up. Before chsMu guarded these maps,
// this raced and could trip "fatal error: concurrent map read and map write".
// Run with -race to detect a regression.
func Test_SubscriberChs_ConcurrentAccess(t *testing.T) {
	auditor := &Auditor{
		auditEventChs: make(map[string]chan<- string),
		bpfEventChs:   make(map[string]chan<- BpfEvent),
		log:           log.Log.WithName("test"),
	}

	// Keep one permanent subscriber so len(auditEventChs) never hits the
	// 1 / 0 boundary during the churn below, which would otherwise invoke
	// setRateLimit/restoreRateLimit and touch the host sysctl. This test
	// targets the map race only.
	keepAudit := make(chan string, 1)
	keepBpf := make(chan BpfEvent, 1)
	kaCh := (chan<- string)(keepAudit)
	kbCh := (chan<- BpfEvent)(keepBpf)
	auditor.auditEventChs["keepalive"] = kaCh
	auditor.bpfEventChs["keepalive"] = kbCh

	const workers = 8
	const iters = 2000
	var wg sync.WaitGroup

	// Writers: churn distinct subscribers so len stays >= 1 (keepalive).
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
				auditor.DeleteBehaviorEventNotifyCh(name)
			}
		}(w)
	}

	// Readers: hit every guarded read path.
	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("subscriber-%d", id)
			for i := 0; i < iters; i++ {
				_, _ = auditor.auditEventChByProfile(name)
				_, _ = auditor.bpfEventChByProfile(name)
				_ = auditor.snapshotAuditEventChs()
			}
		}(r)
	}

	wg.Wait()

	// keepalive must survive the churn.
	if _, ok := auditor.auditEventChByProfile("keepalive"); !ok {
		t.Fatal("keepalive audit subscriber was unexpectedly removed")
	}
	if _, ok := auditor.bpfEventChByProfile("keepalive"); !ok {
		t.Fatal("keepalive bpf subscriber was unexpectedly removed")
	}
}
