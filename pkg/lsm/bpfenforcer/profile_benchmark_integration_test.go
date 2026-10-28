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
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Run with -benchtime=30x -count=3 -cpu=2. Conditional overlap measurements
// deliberately stay separate from the no-update baseline. The 32-event burst
// uses one real process namespace (shared aliases); bulk targets use distinct
// synthetic IDs. These are map-write completion times, not container startup
// or end-to-end protection SLAs. No programs are attached and no maps pinned.
func BenchmarkBpfKernelEventOverlap(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires privileges to create BPF maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	for _, n := range []int{64, 192} {
		for _, overlap := range []bool{false, true} {
			b.Run(fmt.Sprintf("N=%d/overlap=%t", n, overlap), func(b *testing.B) {
				spec, err := loadBpf()
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
					{"v_mount_outer", MountRuleSize, MaxBpfMountRuleCountUnrolled},
				} {
					spec.Maps[m.name].InnerMap = &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: m.size, MaxEntries: m.limit}
				}
				collection, err := ebpf.NewCollection(spec)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(collection.Close)
				e, _ := newTestEnforcer()
				if err := collection.Assign(&e.objs.bpfMaps); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() {
					if err := e.objs.bpfMaps.Close(); err != nil {
						b.Error(err)
					}
				})
				e.profileOps = e
				benchmarkBpfEventOverlap(b, e, n, overlap)
			})
		}
	}
}
