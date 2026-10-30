//go:build linux && bpfintegration

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
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

// Run with -benchtime=30x -count=3 -cpu=2. Conditional overlap measurements
// deliberately stay separate from the no-update baseline. The 32-event burst
// uses distinct private mount namespaces; bulk targets use distinct
// synthetic IDs. These are map-write completion times, not container startup
// or end-to-end protection SLAs. No programs are attached and no maps pinned.
func BenchmarkBpfKernelEventOverlap(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires privileges to create BPF maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	starts := benchmarkIndependentStarts(b, 32)
	for _, n := range []int{64, 192} {
		for _, overlap := range []bool{false, true} {
			b.Run(fmt.Sprintf("N=%d/overlap=%t", n, overlap), func(b *testing.B) {
				e, _ := newTestEnforcer()
				spec, err := e.loadBpfSpec()
				if err != nil {
					b.Fatal(err)
				}
				for name := range spec.Programs {
					delete(spec.Programs, name)
				}
				for _, m := range spec.Maps {
					m.Pinning = ebpf.PinNone
					if m.Type == ebpf.ProgramArray {
						m.Contents = nil
					}
				}
				for _, m := range []struct {
					name        string
					size, limit uint32
				}{
					{"v_file_outer", PathRuleSize, MaxBpfFileRuleCount},
					{"v_bprm_outer", PathRuleSize, MaxBpfBprmRuleCount},
					{"v_net_outer", NetRuleSize, MaxBpfNetworkRuleCount},
					{"v_mount_outer", MountRuleSize, e.maxMountRuleCount},
				} {
					spec.Maps[m.name].InnerMap = &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: m.size, MaxEntries: m.limit}
				}
				collection, err := ebpf.NewCollection(spec)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(collection.Close)
				if err := collection.Assign(&e.objs.bpfMaps); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() {
					if err := e.objs.bpfMaps.Close(); err != nil {
						b.Error(err)
					}
				})
				e.profileOps = e
				benchmarkBpfEventOverlap(b, e, n, overlap, starts)
			})
		}
	}
}

// Keep one idle child per event alive outside the measured interval. Each child
// is created in its own mount namespace and is always reaped during cleanup.
func benchmarkIndependentStarts(b *testing.B, count int) []varmortypes.ContainerInfo {
	b.Helper()
	starts := make([]varmortypes.ContainerInfo, count)
	seen := make(map[uint32]bool)
	for i := range starts {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBpfProfile_ProbeProcess$")
		cmd.Env = append(os.Environ(), "VARMOR_BPF_PROBE=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
		input, err := cmd.StdinPipe()
		require.NoError(b, err)
		b.Cleanup(func() { _ = input.Close() })
		output, err := cmd.StdoutPipe()
		require.NoError(b, err)
		b.Cleanup(func() { _ = output.Close() })
		cmd.Stderr = os.Stderr
		require.NoError(b, cmd.Start())
		b.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		responses := bufio.NewScanner(output)
		require.True(b, responses.Scan())
		require.Equal(b, "ready", responses.Text())
		pid := uint32(cmd.Process.Pid)
		ns, err := varmorutils.ReadMntNsID(pid)
		require.NoError(b, err)
		require.Greater(b, ns, uint32(192), "must not overlap synthetic bulk IDs")
		require.False(b, seen[ns], "event containers must have independent mount namespaces")
		seen[ns] = true
		starts[i] = varmortypes.ContainerInfo{ContainerID: fmt.Sprintf("event-%d", i), ContainerName: "app", PID: pid, MntNsID: ns,
			PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/events"}}
	}
	return starts
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
func benchmarkBpfEventOverlap(b *testing.B, e *BpfEnforcer, n int, overlap bool, starts []varmortypes.ContainerInfo) {
	burst := len(starts)
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
		for _, info := range starts {
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
