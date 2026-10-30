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
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// Run with root privileges on a BPF-LSM-enabled Linux host:
// go test -tags=bpfintegration -run TestBpfProfile_KernelFailureRecovery ./pkg/lsm/bpfenforcer

// This helper runs only in a private mount namespace created by the parent.
func TestBpfProfile_ProbeProcess(t *testing.T) {
	if os.Getenv("VARMOR_BPF_PROBE") != "1" {
		return
	}
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		_, err := os.ReadFile(scanner.Text())
		switch {
		case err == nil:
			fmt.Println("allowed")
		case os.IsPermission(err):
			fmt.Println("denied")
		default:
			fmt.Printf("error: %v\n", err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

type failingMountOperations struct {
	*BpfEnforcer
	fail bool
}

func (ops *failingMountOperations) applyProfile(ns uint32, mode varmor.ProfileMode, content varmor.BpfContent) error {
	if !ops.fail {
		return ops.BpfEnforcer.applyProfile(ns, mode, content)
	}
	// Substitute a closed duplicate FD to induce a real map update error
	// after file rules have been written. Never close the live map itself.
	original := ops.objs.V_mountOuter
	broken, err := original.Clone()
	if err != nil {
		return err
	}
	if err := broken.Close(); err != nil {
		return err
	}
	ops.objs.V_mountOuter = broken
	defer func() { ops.objs.V_mountOuter = original }()
	return ops.BpfEnforcer.applyProfile(ns, mode, content)
}

func TestBpfProfile_KernelFailureRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root, BPF LSM and mount namespace privileges")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	e := &BpfEnforcer{bpfProfileCache: make(map[string]bpfProfile), containerCache: make(map[string]enforceID), namespaceOwners: make(map[uint32]string), maxMountRuleCount: MaxBpfMountRuleCountUnrolled, log: logr.Discard()}
	spec, err := e.loadBpfSpec()
	require.NoError(t, err)
	t.Logf("production variant mount rule limit: %d", e.maxMountRuleCount)
	// Create private, unpinned maps and attach only file_open. This must not
	// reuse or remove the maps belonging to a running vArmor agent.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
		if m.Type == ebpf.ProgramArray {
			// Unattached link/rename hooks have tail-call initializers.
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
	for name := range spec.Programs {
		if name != "varmor_file_open" {
			delete(spec.Programs, name)
		}
	}
	collection, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	t.Cleanup(collection.Close)
	require.NoError(t, collection.Assign(&e.objs.bpfMaps))
	t.Cleanup(func() { assert.NoError(t, e.objs.bpfMaps.Close()) })
	ops := &failingMountOperations{BpfEnforcer: e}
	e.profileOps = ops
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["varmor_file_open"]})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, attached.Close()) })

	cmd := exec.Command(os.Args[0], "-test.run=^TestBpfProfile_ProbeProcess$")
	cmd.Env = append(os.Environ(), "VARMOR_BPF_PROBE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	responses := bufio.NewScanner(output)
	require.True(t, responses.Scan())
	require.Equal(t, "ready", responses.Text())
	id, err := e.newEnforceID(uint32(cmd.Process.Pid), nil)
	require.NoError(t, err)
	parent, err := e.newEnforceID(uint32(os.Getpid()), nil)
	require.NoError(t, err)
	require.NotEqual(t, parent.mntNsID, id.mntNsID, "enforcement must be isolated to the child")
	dir := t.TempDir()
	pathA, pathB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	require.NoError(t, os.WriteFile(pathA, []byte("a"), 0600))
	require.NoError(t, os.WriteFile(pathB, []byte("b"), 0600))
	probe := func(path, want string) {
		t.Helper()
		_, err := fmt.Fprintln(input, path)
		require.NoError(t, err)
		require.True(t, responses.Scan())
		require.Equal(t, want, responses.Text())
	}
	content := func(path string) varmor.BpfContent {
		return varmor.BpfContent{Files: []varmor.FileContent{{Mode: DenyMode, Permissions: AaMayRead, Pattern: varmor.PathPattern{Flags: PreciseMatch | PrefixMatch, Prefix: path}}}}
	}
	a, b := content(pathA), content(pathB)
	b.Mounts = []varmor.MountContent{{Mode: DenyMode, Fstype: "tmpfs"}}
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	registerTestContainer(e, "p", "child", id)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	probe(pathA, "denied")
	probe(pathB, "allowed")
	invalid := b.DeepCopy()
	invalid.Mounts = make([]varmor.MountContent, e.maxMountRuleCount+1)
	require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, *invalid))
	probe(pathA, "denied") // Capacity preflight preserves previous rules.
	ops.fail = true
	for attempt := 0; attempt < 2; attempt++ {
		err = e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "applyMountRules"), err.Error())
		assert.Contains(t, e.bpfProfileCache["p"].pendingContainers, "child")
		probe(pathA, "allowed")
		probe(pathB, "allowed") // Existing replacement is not atomic.
	}
	ops.fail = false
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	probe(pathA, "allowed")
	probe(pathB, "denied")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	probe(pathB, "denied")
	require.NoError(t, e.DeleteBpfProfile("p"))
	probe(pathB, "allowed")
}
