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

package tracer

import (
	"fmt"
	"sync"
	"testing"
)

func TestProcessEventChs_ConcurrentAccess(t *testing.T) {
	tracer := &ProcessTracer{processEventChs: make(map[string]chan<- BpfProcessEvent)}
	eventCh := make(chan BpfProcessEvent, 1)
	tracer.processEventChs["keepalive"] = eventCh

	const workers = 8
	const iterations = 500
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("subscriber-%d", id)
			for i := 0; i < iterations; i++ {
				tracer.AddProcessEventNotifyCh(name, &eventCh)
				tracer.DeleteProcessEventNotifyCh(name)
			}
		}(worker)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tracer.snapshotProcessEventChs()
			}
		}()
	}
	wg.Wait()

	if len(tracer.snapshotProcessEventChs()) != 1 {
		t.Fatal("keepalive subscriber was unexpectedly removed")
	}
}
