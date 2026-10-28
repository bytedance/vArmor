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

package bpfenforcer

import (
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

// No kernel work: these benchmarks isolate reconciliation bookkeeping. Retry
// cases include the same O(K) pending-set rearming in both compared versions.
type noopProfileOperations struct{}

func (noopProfileOperations) applyProfile(uint32, varmor.ProfileMode, varmor.BpfContent) error {
	return nil
}
func (noopProfileOperations) deleteProfile(uint32)             {}
func (noopProfileOperations) setPodIps(uint32, []string) error { return nil }
func (noopProfileOperations) removePodIps(uint32) error        { return nil }

func BenchmarkBpfReconcileBookkeeping(b *testing.B) {
	for _, n := range []int{16, 64, 256} {
		for _, scenario := range []string{"unchanged", "retry-one", "retry-eight", "update-all", "update-shared"} {
			b.Run(fmt.Sprintf("N=%d/%s", n, scenario), func(b *testing.B) {
				e, _ := newTestEnforcer()
				e.profileOps = noopProfileOperations{}
				content := testContent("/benchmark")
				mode := varmor.ProfileModeEnforce
				if err := e.SaveAndApplyBpfProfile("p", mode, content); err != nil {
					b.Fatal(err)
				}
				ids := make([]string, n)
				for i := range ids {
					ids[i] = fmt.Sprint(i)
					ns := uint32(i + 1)
					if scenario == "update-shared" {
						ns = uint32(i/4 + 1)
					}
					registerTestContainer(e, "p", ids[i], enforceID{mntNsID: ns})
				}
				if err := e.SaveAndApplyBpfProfile("p", mode, content); err != nil {
					b.Fatal(err)
				}
				pending := e.bpfProfileCache["p"].pendingContainers
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					switch scenario {
					case "retry-one":
						pending[ids[0]] = struct{}{}
					case "retry-eight":
						for _, id := range ids[:8] {
							pending[id] = struct{}{}
						}
					case "update-all", "update-shared":
						if mode == varmor.ProfileModeEnforce {
							mode = varmor.ProfileModeComplain
						} else {
							mode = varmor.ProfileModeEnforce
						}
					}
					if err := e.SaveAndApplyBpfProfile("p", mode, content); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

type benchmarkGatedOperations struct {
	profileOperations
	entered chan struct{}
	release chan struct{}
	armed   bool
}

func (ops *benchmarkGatedOperations) applyProfile(ns uint32, mode varmor.ProfileMode, content varmor.BpfContent) error {
	if ops.armed {
		ops.armed = false
		close(ops.entered)
		<-ops.release
	}
	return ops.profileOperations.applyProfile(ns, mode, content)
}

type benchmarkStartEvent struct {
	info   varmortypes.ContainerInfo
	queued time.Time
}

type benchmarkEventLatency struct {
	queue time.Duration
	write time.Duration
}

// This one-consumer harness preserves the production channel capacity and
// invokes the real TaskStart handler. Queue latency ends at dispatch; write
// latency ends when the handler returns (including lock wait and bookkeeping).
// It excludes containerd notification and Kubernetes metadata retrieval.
// In the overlap case a gate ensures the burst arrives while an update owns
// the lock. update-us measures remaining work after releasing that gate;
// it excludes preparation before the first kernel call and the gate wait.
func benchmarkBpfEventOverlap(b *testing.B, e *BpfEnforcer, n int, overlap bool) {
	const burst = 32
	content := varmor.BpfContent{Files: make([]varmor.FileContent, 16)}
	for i := range content.Files {
		content.Files[i] = testContent(fmt.Sprintf("/benchmark/%d", i)).Files[0]
		content.Files[i].Pattern.Flags = PreciseMatch | PrefixMatch
	}
	mode := varmor.ProfileModeEnforce
	if err := e.SaveAndApplyBpfProfile("bulk", mode, content); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < n; i++ {
		registerTestContainer(e, "bulk", fmt.Sprint(i), enforceID{mntNsID: uint32(i + 1)})
	}
	if err := e.SaveAndApplyBpfProfile("bulk", mode, content); err != nil {
		b.Fatal(err)
	}
	ops := &benchmarkGatedOperations{profileOperations: e.profileOps}
	e.profileOps = ops
	info := varmortypes.ContainerInfo{ContainerName: "app", PID: uint32(os.Getpid()),
		PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/events"}}
	var queues, writes, updates []time.Duration
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		b.StopTimer()
		if err := e.DeleteBpfProfile("events"); err != nil {
			b.Fatal(err)
		}
		if err := e.SaveAndApplyBpfProfile("events", mode, content); err != nil {
			b.Fatal(err)
		}
		events := make(chan benchmarkStartEvent, 100)
		done := make(chan benchmarkEventLatency, burst)
		workerDone := make(chan struct{})
		go func() {
			defer close(workerDone)
			for event := range events {
				dispatched := time.Now()
				e.handleTaskStart(event.info)
				done <- benchmarkEventLatency{queue: dispatched.Sub(event.queued), write: time.Since(event.queued)}
			}
		}()
		type updateResult struct {
			finished time.Time
			err      error
		}
		updated := make(chan updateResult, 1)
		if overlap {
			ops.entered, ops.release = make(chan struct{}), make(chan struct{})
			ops.armed = true
			if mode == varmor.ProfileModeEnforce {
				mode = varmor.ProfileModeComplain
			} else {
				mode = varmor.ProfileModeEnforce
			}
			go func() {
				err := e.SaveAndApplyBpfProfile("bulk", mode, content)
				updated <- updateResult{finished: time.Now(), err: err}
			}()
			<-ops.entered
		}
		b.StartTimer()
		for i := 0; i < burst; i++ {
			info.ContainerID = fmt.Sprintf("event-%d", i)
			events <- benchmarkStartEvent{info: info, queued: time.Now()}
		}
		close(events)
		released := time.Now()
		if overlap {
			close(ops.release)
		}
		for i := 0; i < burst; i++ {
			latency := <-done
			queues = append(queues, latency.queue)
			writes = append(writes, latency.write)
		}
		<-workerDone
		if overlap {
			result := <-updated
			if result.err != nil {
				b.Fatal(result.err)
			}
			updates = append(updates, result.finished.Sub(released))
		}
		b.StopTimer()
		if len(e.bpfProfileCache["events"].containerCache) != burst {
			b.Fatal("not all synthetic start events applied successfully")
		}
		b.StartTimer()
	}
	b.StopTimer()
	for name, values := range map[string][]time.Duration{"queue": queues, "write": writes, "update": updates} {
		if len(values) == 0 {
			continue
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		for label, percentile := range map[string]float64{"p95": .95, "p99": .99, "max": 1} {
			value := values[int(math.Ceil(percentile*float64(len(values))))-1]
			b.ReportMetric(float64(value)/float64(time.Microsecond), name+"-"+label+"-us")
		}
	}
	b.ReportMetric(float64(len(writes)), "events")
}
