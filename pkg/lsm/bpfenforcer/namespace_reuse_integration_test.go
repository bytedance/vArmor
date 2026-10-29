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
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

func TestIndependentNamespaces_ReusedIDCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires private mount namespaces")
	}
	for _, cleanup := range []string{"delete-event", "offline-sync"} {
		t.Run(cleanup, func(t *testing.T) {
			e, ops := newTestEnforcer()
			content := testContent("/protected")
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
			spawn := func(name string) (varmortypes.ContainerInfo, func()) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestBpfProfile_ProbeProcess$")
				cmd.Env = append(os.Environ(), "VARMOR_BPF_PROBE=1")
				cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
				input, err := cmd.StdinPipe()
				require.NoError(t, err)
				t.Cleanup(func() { _ = input.Close() })
				output, err := cmd.StdoutPipe()
				require.NoError(t, err)
				t.Cleanup(func() { _ = output.Close() })
				require.NoError(t, cmd.Start())
				stopped := false
				stop := func() {
					if !stopped {
						stopped = true
						_ = input.Close()
						_ = cmd.Process.Kill()
						_ = cmd.Wait()
					}
				}
				t.Cleanup(stop)
				reader := bufio.NewScanner(output)
				require.True(t, reader.Scan())
				require.Equal(t, "ready", reader.Text())
				return varmortypes.ContainerInfo{ContainerID: name, ContainerName: "app", PID: uint32(cmd.Process.Pid), PodIPs: []string{"10.0.0.1"}, PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/p"}}, stop
			}
			old, stopOld := spawn("old")
			oldID, err := e.newEnforceID(old.PID, old.PodIPs)
			require.NoError(t, err)
			e.handleTaskStart(old)
			require.Contains(t, ops.installed, oldID.mntNsID)
			stopOld() // Old namespace is destroyed BEFORE the new container is created.
			var current varmortypes.ContainerInfo
			var currentID enforceID
			reused := false
			for attempt := 0; attempt < 16; attempt++ {
				candidate, stop := spawn(fmt.Sprintf("new-%d", attempt))
				id, err := e.newEnforceID(candidate.PID, candidate.PodIPs)
				require.NoError(t, err)
				if id.mntNsID == oldID.mntNsID {
					current, currentID, reused = candidate, id, true
					break
				}
				stop()
			}
			if !reused {
				t.Skip("kernel did not reuse a namespace ID in 16 attempts")
			}
			t.Logf("exited PID %d and live PID %d have sequentially used namespace ID %d", old.PID, current.PID, currentID.mntNsID)
			current.PodIPs = []string{"10.0.0.2"}
			e.handleTaskStart(current)
			require.Contains(t, ops.installed, currentID.mntNsID)
			switch cleanup {
			case "delete-event":
				e.handleTaskDelete(old)
			case "offline-sync":
				e.handleTaskDeleteSync()
			}
			require.Contains(t, e.containerCache, current.ContainerID)
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
			require.Contains(t, ops.installed, currentID.mntNsID, "cleanup of exited container must not remove the live container's rules")
			require.Equal(t, current.PodIPs, ops.ips[currentID.mntNsID])
			require.Equal(t, current.ContainerID, e.namespaceOwners[currentID.mntNsID])
			require.NotContains(t, e.containerCache, old.ContainerID)
		})
	}
}
