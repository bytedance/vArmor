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

package runtime

import (
	"fmt"
	"sync"
	"testing"

	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

func TestTaskNotifyChs_ConcurrentAccess(t *testing.T) {
	monitor := &RuntimeMonitor{
		taskStartChs:      make(map[string]chan<- varmortypes.ContainerInfo),
		taskDeleteChs:     make(map[string]chan<- varmortypes.ContainerInfo),
		taskDeleteSyncChs: make(map[string]chan<- bool),
	}
	startCh := make(chan varmortypes.ContainerInfo, 1)
	deleteCh := make(chan varmortypes.ContainerInfo, 1)
	syncCh := make(chan bool, 1)
	monitor.AddTaskNotifyChs("keepalive", &startCh, &deleteCh, &syncCh)

	const workers = 8
	const iterations = 500
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("subscriber-%d", id)
			for i := 0; i < iterations; i++ {
				monitor.AddTaskNotifyChs(name, &startCh, &deleteCh, &syncCh)
				monitor.DeleteTaskNotifyChs(name)
			}
		}(worker)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				monitor.snapshotTaskStartChs()
				monitor.snapshotTaskDeleteChs()
				monitor.snapshotTaskDeleteSyncChs()
			}
		}()
	}
	wg.Wait()

	if len(monitor.snapshotTaskStartChs()) != 1 ||
		len(monitor.snapshotTaskDeleteChs()) != 1 ||
		len(monitor.snapshotTaskDeleteSyncChs()) != 1 {
		t.Fatal("keepalive subscriber was unexpectedly removed")
	}
}
