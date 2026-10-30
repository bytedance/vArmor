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
		for _, scenario := range []string{"unchanged", "retry-one", "retry-eight", "update-all"} {
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
					case "update-all":
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

// Kernel operations are no-ops. Delete-all includes identical O(N) cache
// setup in both versions; start measures a tracked container's IP change.
func BenchmarkBpfContainerBookkeeping(b *testing.B) {
	for _, n := range []int{16, 64, 256} {
		for _, scenario := range []string{"start", "delete-all"} {
			b.Run(fmt.Sprintf("N=%d/%s", n, scenario), func(b *testing.B) {
				e, _ := newTestEnforcer()
				e.profileOps = noopProfileOperations{}
				content := testContent("/benchmark")
				if err := e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content); err != nil {
					b.Fatal(err)
				}
				ids := make([]string, n)
				for i := range ids {
					ids[i] = fmt.Sprint(i)
					registerTestContainer(e, "p", ids[i], enforceID{mntNsID: uint32(i + 1)})
				}
				if err := e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content); err != nil {
					b.Fatal(err)
				}
				info := varmortypes.ContainerInfo{ContainerID: "event", ContainerName: "app", PID: uint32(os.Getpid()), MntNsID: testMountNamespaceID(b, uint32(os.Getpid())),
					PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/p"}}
				addresses := [][]string{{"10.0.0.1"}, {"10.0.0.2"}}
				if scenario == "start" {
					e.handleTaskStart(info)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if scenario == "start" {
						info.PodIPs = addresses[i%2]
						e.handleTaskStart(info)
					} else {
						if err := e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content); err != nil {
							b.Fatal(err)
						}
						for j, id := range ids {
							registerTestContainer(e, "p", id, enforceID{mntNsID: uint32(j + 1)})
						}
						if err := e.DeleteBpfProfile("p"); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
