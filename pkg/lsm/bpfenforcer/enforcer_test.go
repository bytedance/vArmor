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
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

type fakeProfileOperations struct {
	calls       map[uint32]int
	installed   map[uint32]varmor.BpfContent
	modes       map[uint32]varmor.ProfileMode
	failures    map[uint32]error
	ipFailures  map[uint32]error
	ips         map[uint32][]string
	beforeApply func()
}

func newTestEnforcer() (*BpfEnforcer, *fakeProfileOperations) {
	ops := &fakeProfileOperations{
		calls: make(map[uint32]int), installed: make(map[uint32]varmor.BpfContent),
		modes: make(map[uint32]varmor.ProfileMode), failures: make(map[uint32]error),
		ipFailures: make(map[uint32]error), ips: make(map[uint32][]string),
	}
	return &BpfEnforcer{
		bpfProfileCache: make(map[string]bpfProfile), containerCache: make(map[string]enforceID),
		maxMountRuleCount: MaxBpfMountRuleCountUnrolled, profileOps: ops, log: logr.Discard(),
	}, ops
}

func (ops *fakeProfileOperations) applyProfile(ns uint32, mode varmor.ProfileMode, content varmor.BpfContent) error {
	if ops.beforeApply != nil {
		ops.beforeApply()
	}
	ops.calls[ns]++
	// Model the destructive replacement in applyProfile, not a safe rollback.
	delete(ops.installed, ns)
	delete(ops.modes, ns)
	if err := ops.failures[ns]; err != nil {
		return err
	}
	ops.installed[ns] = *content.DeepCopy()
	ops.modes[ns] = mode
	return nil
}
func (ops *fakeProfileOperations) deleteProfile(ns uint32) {
	delete(ops.installed, ns)
	delete(ops.modes, ns)
}
func (ops *fakeProfileOperations) setPodIps(ns uint32, ips []string) error {
	if err := ops.ipFailures[ns]; err != nil {
		return err
	}
	ops.ips[ns] = append([]string(nil), ips...)
	return nil
}
func (ops *fakeProfileOperations) removePodIps(ns uint32) error { delete(ops.ips, ns); return nil }

func testContent(name string) varmor.BpfContent {
	return varmor.BpfContent{Files: []varmor.FileContent{{Mode: DenyMode, Permissions: AaMayRead, Pattern: varmor.PathPattern{Prefix: name}}}}
}
func registerTestContainer(e *BpfEnforcer, profileName, containerID string, id enforceID) {
	p := e.bpfProfileCache[profileName]
	p.containerCache[containerID] = id
	p.pendingContainers[containerID] = struct{}{}
	e.containerCache[containerID] = id
}

func TestSaveAndApplyBpfProfile_RetryPartialFailure(t *testing.T) {
	e, ops := newTestEnforcer()
	a, b := testContent("/a"), testContent("/b")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	for i := uint32(1); i <= 3; i++ {
		registerTestContainer(e, "p", fmt.Sprint(i), enforceID{mntNsID: i})
	}
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	injected := errors.New("injected map failure")
	ops.failures[2] = injected
	for attempt := 0; attempt < 2; attempt++ {
		err := e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b)
		require.ErrorIs(t, err, injected)
		assert.Contains(t, err.Error(), "container 2, mount namespace 2")
		assert.Equal(t, b, ops.installed[1])
		assert.Equal(t, b, ops.installed[3], "one failure must not starve other containers")
		assert.NotContains(t, ops.installed, uint32(2))
		assert.Equal(t, map[string]struct{}{"2": {}}, e.bpfProfileCache["p"].pendingContainers)
	}
	assert.Equal(t, 2, ops.calls[1], "successful containers must not be rewritten on retry")
	assert.Equal(t, 3, ops.calls[2])
	delete(ops.failures, 2)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	assert.Equal(t, b, ops.installed[2])
	assert.Empty(t, e.bpfProfileCache["p"].pendingContainers)
	before := ops.calls[2]
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	assert.Equal(t, before, ops.calls[2], "fully applied identical profiles are no-ops")
}

func TestSaveAndApplyBpfProfile_ChangeAfterFailure(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		mode       varmor.ProfileMode
	}{
		{"revert", "/a", varmor.ProfileModeEnforce},
		{"new content", "/c", varmor.ProfileModeEnforce},
		{"mode only", "/b", varmor.ProfileModeComplain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ops := newTestEnforcer()
			a, b := testContent("/a"), testContent("/b")
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			for i := uint32(1); i <= 3; i++ {
				registerTestContainer(e, "p", fmt.Sprint(i), enforceID{mntNsID: i})
			}
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			ops.failures[2] = errors.New("failed")
			require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
			delete(ops.failures, 2)
			desired := testContent(tc.path)
			require.NoError(t, e.SaveAndApplyBpfProfile("p", tc.mode, desired))
			for i := uint32(1); i <= 3; i++ {
				assert.Equal(t, desired, ops.installed[i])
				assert.Equal(t, tc.mode, ops.modes[i])
				assert.Equal(t, 3, ops.calls[i])
			}
		})
	}
}

func TestSaveAndApplyBpfProfile_CapacityPreflight(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content varmor.BpfContent
	}{
		{"files", varmor.BpfContent{Files: make([]varmor.FileContent, MaxBpfFileRuleCount+1)}},
		{"processes", varmor.BpfContent{Processes: make([]varmor.FileContent, MaxBpfBprmRuleCount+1)}},
		{"networks", varmor.BpfContent{Networks: make([]varmor.NetworkContent, MaxBpfNetworkRuleCount+1)}},
		{"mounts", varmor.BpfContent{Mounts: make([]varmor.MountContent, MaxBpfMountRuleCountUnrolled+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ops := newTestEnforcer()
			a, b := testContent("/a"), testContent("/b")
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			registerTestContainer(e, "p", "c", enforceID{mntNsID: 1})
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			for i := 0; i < 2; i++ {
				require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, tc.content))
			}
			assert.Equal(t, 1, ops.calls[1])
			assert.Equal(t, a, ops.installed[1])
			assert.Equal(t, a, e.bpfProfileCache["p"].bpfContent)
			// A rejected update must not erase pending work from an earlier update.
			ops.failures[1] = errors.New("failed")
			require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
			require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, tc.content))
			assert.Contains(t, e.bpfProfileCache["p"].pendingContainers, "c")
			assert.Equal(t, b, e.bpfProfileCache["p"].bpfContent)
			// The low-level check must run before even accessing kernel maps.
			require.Error(t, e.applyProfile(1, varmor.ProfileModeEnforce, tc.content))
		})
	}
	for _, limit := range []uint32{MaxBpfMountRuleCountUnrolled, MaxBpfMountRuleCountBpfLoop} {
		e, _ := newTestEnforcer()
		e.maxMountRuleCount = limit
		require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, varmor.BpfContent{Mounts: make([]varmor.MountContent, limit)}))
	}
}

func TestSaveAndApplyBpfProfile_OwnsContent(t *testing.T) {
	e, ops := newTestEnforcer()
	content := testContent("/a")
	content.Networks = []varmor.NetworkContent{{Address: &varmor.NetworkAddress{Ports: []uint16{80}}}}
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
	registerTestContainer(e, "p", "c", enforceID{mntNsID: 1})
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
	content.Files[0].Pattern.Prefix = "/b"
	content.Networks[0].Address.Ports[0] = 443
	assert.Equal(t, "/a", e.bpfProfileCache["p"].bpfContent.Files[0].Pattern.Prefix)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
	assert.Equal(t, 2, ops.calls[1])
	assert.Equal(t, content, ops.installed[1])
}

func TestExpandDiskDevices_PreservesRulesAndChecksExpandedCapacity(t *testing.T) {
	original := varmor.BpfContent{
		Files:  []varmor.FileContent{{Mode: DenyMode, Permissions: AaMayRead, Pattern: varmor.PathPattern{Prefix: "{{.DiskDevices}}"}}, {Pattern: varmor.PathPattern{Prefix: "/other"}}, {Mode: AuditMode, Pattern: varmor.PathPattern{Prefix: "{{.DiskDevices}}"}}},
		Mounts: []varmor.MountContent{{Mode: DenyMode, MountFlags: 123, Pattern: varmor.PathPattern{Prefix: "{{.DiskDevices}}"}}},
	}
	expanded := original.DeepCopy()
	expandDiskDevices(expanded, []string{"sda", "sdb"})
	assert.Len(t, expanded.Files, 5)
	assert.Len(t, expanded.Mounts, 2)
	assert.Equal(t, uint32(DenyMode), expanded.Files[0].Mode)
	assert.Equal(t, uint32(AuditMode), expanded.Files[4].Mode)
	assert.Equal(t, uint32(DenyMode), expanded.Mounts[1].Mode)
	assert.Equal(t, "{{.DiskDevices}}", original.Files[0].Pattern.Prefix)
	devices := make([]string, 51)
	for i := range devices {
		devices[i] = fmt.Sprint(i)
	}
	expanded = original.DeepCopy()
	expandDiskDevices(expanded, devices)
	e, _ := newTestEnforcer()
	require.Error(t, e.validateRuleCapacity(*expanded))
}

func TestPendingContainers_Cleanup(t *testing.T) {
	for _, kind := range []string{"delete", "offline", "profile"} {
		t.Run(kind, func(t *testing.T) {
			e, ops := newTestEnforcer()
			a := testContent("/a")
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			registerTestContainer(e, "p", "c", enforceID{pid: 0xffffffff, mntNsID: 1})
			ops.failures[1] = errors.New("failed")
			require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			switch kind {
			case "delete":
				e.handleTaskDelete(varmortypes.ContainerInfo{ContainerID: "c"})
			case "offline":
				e.handleTaskDeleteSync()
			case "profile":
				require.NoError(t, e.DeleteBpfProfile("p"))
			}
			assert.Empty(t, e.containerCache)
			assert.Empty(t, e.bpfProfileCache["p"].pendingContainers)
			require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
			assert.Equal(t, 1, ops.calls[1])
		})
	}
}

func TestTaskStart_RetryPendingContainer(t *testing.T) {
	e, ops := newTestEnforcer()
	a, b := testContent("/a"), testContent("/b")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	info := varmortypes.ContainerInfo{ContainerID: "c", ContainerName: "app", PID: uint32(os.Getpid()), PodIPs: []string{"10.0.0.1"}, PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/p"}}
	id, err := e.newEnforceID(info.PID, info.PodIPs)
	require.NoError(t, err)
	e.handleTaskStart(info)
	assert.Equal(t, 1, ops.calls[id.mntNsID])
	ops.failures[id.mntNsID] = errors.New("failed")
	require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	e.handleTaskStart(info)
	assert.Equal(t, 3, ops.calls[id.mntNsID])
	assert.Contains(t, e.bpfProfileCache["p"].pendingContainers, "c")
	delete(ops.failures, id.mntNsID)
	e.handleTaskStart(info)
	assert.Equal(t, b, ops.installed[id.mntNsID])
	assert.Empty(t, e.bpfProfileCache["p"].pendingContainers)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	e.handleTaskStart(info)
	assert.Equal(t, 4, ops.calls[id.mntNsID])
	// IP setup errors must not be cached as successfully applied either.
	info.PodIPs = []string{"10.0.0.2"}
	ops.ipFailures[id.mntNsID] = errors.New("IP update failed")
	e.handleTaskStart(info)
	require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	delete(ops.ipFailures, id.mntNsID)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	assert.Equal(t, info.PodIPs, ops.ips[id.mntNsID])
}

func TestBpfEnforcer_ConcurrentLifecycle(t *testing.T) {
	e, _ := newTestEnforcer()
	content := testContent("/a")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
	info := varmortypes.ContainerInfo{ContainerID: "c", ContainerName: "app", PID: uint32(os.Getpid()), PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/p"}}
	var wg sync.WaitGroup
	for _, action := range []func(){
		func() { assert.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content)) },
		func() { e.handleTaskStart(info) }, func() { e.handleTaskDelete(info) }, func() { e.handleTaskDeleteSync() },
		func() { assert.NoError(t, e.DeleteBpfProfile("p")) }, func() { e.IsBpfProfileExist("p") },
	} {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				f()
			}
		}(action)
	}
	wg.Wait()
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, content))
	e.handleTaskStart(info)
	assert.Empty(t, e.bpfProfileCache["p"].pendingContainers)
	assert.Len(t, e.bpfProfileCache["p"].containerCache, 1)
}

func TestPendingContainers_SharedMountNamespace(t *testing.T) {
	e, ops := newTestEnforcer()
	a, b := testContent("/a"), testContent("/b")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	registerTestContainer(e, "p", "c1", enforceID{mntNsID: 1})
	registerTestContainer(e, "p", "c2", enforceID{mntNsID: 1})
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	assert.Equal(t, 1, ops.calls[1])
	ops.failures[1] = errors.New("failed")
	require.Error(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	assert.Len(t, e.bpfProfileCache["p"].pendingContainers, 2)
	assert.Equal(t, 2, ops.calls[1], "each namespace is attempted once per reconciliation")
	delete(ops.failures, 1)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, b))
	assert.Empty(t, e.bpfProfileCache["p"].pendingContainers)
	e.handleTaskDelete(varmortypes.ContainerInfo{ContainerID: "c1"})
	assert.Equal(t, b, ops.installed[1], "a live alias must keep its rules")
	e.handleTaskDelete(varmortypes.ContainerInfo{ContainerID: "c2"})
	assert.NotContains(t, ops.installed, uint32(1))
}

func TestTaskStart_ChangedIdentityFailure(t *testing.T) {
	e, ops := newTestEnforcer()
	a := testContent("/a")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	info := varmortypes.ContainerInfo{ContainerID: "c", ContainerName: "app", PID: uint32(os.Getpid()), PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/p"}}
	id, err := e.newEnforceID(info.PID, nil)
	require.NoError(t, err)
	oldID := id
	oldID.mntNsID--
	registerTestContainer(e, "p", "c", oldID)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	ops.failures[id.mntNsID] = errors.New("failed")
	e.handleTaskStart(info)
	assert.NotContains(t, ops.installed, oldID.mntNsID)
	assert.Equal(t, id, e.bpfProfileCache["p"].containerCache["c"])
	assert.Contains(t, e.bpfProfileCache["p"].pendingContainers, "c")
	delete(ops.failures, id.mntNsID)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	assert.Equal(t, a, ops.installed[id.mntNsID])
}

func TestTaskStart_FirstFailureIsNotCachedAsProtected(t *testing.T) {
	e, ops := newTestEnforcer()
	a := testContent("/a")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	info := varmortypes.ContainerInfo{ContainerID: "c", ContainerName: "app", PID: uint32(os.Getpid()), PodIPs: []string{"10.0.0.1"}, PodAnnotations: map[string]string{"container.bpf.security.beta.varmor.org/app": "localhost/p"}}
	id, err := e.newEnforceID(info.PID, info.PodIPs)
	require.NoError(t, err)
	ops.failures[id.mntNsID] = errors.New("failed")
	e.handleTaskStart(info)
	assert.Empty(t, e.containerCache)
	assert.Empty(t, e.bpfProfileCache["p"].containerCache)
	assert.Empty(t, ops.ips)
	delete(ops.failures, id.mntNsID)
	e.handleTaskStart(info)
	assert.Equal(t, a, ops.installed[id.mntNsID])
	assert.Contains(t, e.containerCache, "c")
}

func TestNewEnforceID_OwnsPodIPs(t *testing.T) {
	e, _ := newTestEnforcer()
	ips := []string{"10.0.0.1"}
	id, err := e.newEnforceID(uint32(os.Getpid()), ips)
	require.NoError(t, err)
	ips[0] = "10.0.0.2"
	assert.Equal(t, []string{"10.0.0.1"}, id.ips)
}

func TestTaskDeleteSync_ReusedPID(t *testing.T) {
	e, ops := newTestEnforcer()
	a := testContent("/a")
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	id, err := e.newEnforceID(uint32(os.Getpid()), nil)
	require.NoError(t, err)
	id.mntNsID-- // The PID now belongs to a different mount namespace.
	registerTestContainer(e, "p", "c", id)
	require.NoError(t, e.SaveAndApplyBpfProfile("p", varmor.ProfileModeEnforce, a))
	e.handleTaskDeleteSync()
	assert.Empty(t, e.containerCache)
	assert.Empty(t, e.bpfProfileCache["p"].containerCache)
	assert.Empty(t, ops.installed)
}
