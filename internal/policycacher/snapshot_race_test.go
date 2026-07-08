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

package policycacher

import (
	"fmt"
	"sync"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// Test_SnapshotClusterPolicyEnforcers_ConcurrentAccess reproduces the data
// race between the ProxyConfigPropagator (which reads the cluster-policy
// enforcer/mode maps on Namespace add events) and the PolicyCacher informer
// handlers (which mutate those maps on ClusterPolicy add/update/delete events).
//
// Before the fix the propagator ranged over ClusterPolicyEnforcer directly
// without holding the cacher lock, which under `go test -race` reports a data
// race and can trigger a "concurrent map iteration and map write" fatal error.
// SnapshotClusterPolicyEnforcers takes the read lock and returns copies, so a
// reader can iterate safely while writers mutate the maps concurrently.
func Test_SnapshotClusterPolicyEnforcers_ConcurrentAccess(t *testing.T) {
	c := &PolicyCacher{
		ClusterPolicyEnforcer: make(map[string]string),
		ClusterPolicyMode:     make(map[string]varmor.VarmorPolicyMode),
	}

	const (
		writers = 8
		readers = 8
		iters   = 2000
	)

	var wg sync.WaitGroup

	// Writers mirror the cacher's informer handlers: mutate the maps under the
	// write lock.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				key := fmt.Sprintf("ns-%d/policy-%d", w, i%16)
				c.mutex.Lock()
				c.ClusterPolicyEnforcer[key] = "NetworkProxy"
				c.ClusterPolicyMode[key] = varmor.BehaviorModelingMode
				c.mutex.Unlock()

				c.mutex.Lock()
				delete(c.ClusterPolicyEnforcer, key)
				delete(c.ClusterPolicyMode, key)
				c.mutex.Unlock()
			}
		}(w)
	}

	// Readers mirror the propagator: snapshot then iterate outside the lock.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				enforcerByKey, modeByKey := c.SnapshotClusterPolicyEnforcers()
				for key := range enforcerByKey {
					_ = enforcerByKey[key]
					_ = modeByKey[key]
				}
			}
		}()
	}

	wg.Wait()
}
