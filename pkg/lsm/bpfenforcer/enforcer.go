// Copyright 2023 vArmor Authors
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

// Package bpfenforcer manages the BPF programs and interacts with them through the BPF maps
package bpfenforcer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	lsmutils "github.com/bytedance/vArmor/pkg/lsm/utils"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

type enforceID struct {
	pid     uint32
	mntNsID uint32
	ips     []string
}

type bpfProfile struct {
	mode              varmor.ProfileMode
	bpfContent        varmor.BpfContent
	containerCache    map[string]enforceID // local cache <containerID: enforceID>
	pendingContainers map[string]struct{}  // tracked containers awaiting the desired profile
}

// profileOperations isolates kernel operations from reconciliation bookkeeping.
// Production uses the enforcer itself; tests can inject application failures.
type profileOperations interface {
	applyProfile(uint32, varmor.ProfileMode, varmor.BpfContent) error
	deleteProfile(uint32)
	setPodIps(uint32, []string) error
	removePodIps(uint32) error
}

// BpfEnforcer requires each supported container to have its own mount
// namespace. Namespace IDs can be reused after a container exits, so kernel
// entries must only be changed by the currently recorded owner.
type BpfEnforcer struct {
	// mu serializes cache transitions with their associated kernel operations.
	mu                sync.RWMutex
	closed            bool
	profileOps        profileOperations
	TaskStartCh       chan varmortypes.ContainerInfo
	TaskDeleteCh      chan varmortypes.ContainerInfo
	TaskDeleteSyncCh  chan bool
	objs              bpfObjects
	capableLink       link.Link
	openFileLink      link.Link
	pathSymlinkLink   link.Link
	pathLinkLink      link.Link
	pathRenameLink    link.Link
	bprmLink          link.Link
	sockConnLink      link.Link
	socketLink        link.Link
	ptraceLink        link.Link
	mountLink         link.Link
	moveMountLink     link.Link
	umountLink        link.Link
	maxMountRuleCount uint32
	bpfProfileCache   map[string]bpfProfile // <profileName: bpfProfile>
	containerCache    map[string]enforceID  // global cache <containerID: enforceID>
	namespaceOwners   map[uint32]string     // mount namespace ID -> current container ID
	log               logr.Logger
}

// NewBpfEnforcer creates a BpfEnforcer, and initialize the BPF settings and resources
func NewBpfEnforcer(log logr.Logger) (*BpfEnforcer, error) {
	enforcer := BpfEnforcer{
		TaskStartCh:      make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteCh:     make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteSyncCh: make(chan bool, 1),
		objs:             bpfObjects{},
		bpfProfileCache:  make(map[string]bpfProfile),
		containerCache:   make(map[string]enforceID),
		namespaceOwners:  make(map[uint32]string),
		log:              log,
	}

	enforcer.profileOps = &enforcer
	err := enforcer.initBPF()
	if err != nil {
		return nil, err
	}
	return &enforcer, nil
}

// initBPF initializes the BPF settings and resources
func (enforcer *BpfEnforcer) initBPF() error {
	// Allow the current process to lock memory for eBPF resources
	enforcer.log.Info("remove memory lock")
	err := rlimit.RemoveMemlock()
	if err != nil {
		return fmt.Errorf("RemoveMemlock() failed: %v", err)
	}

	// Parse the ebpf program
	enforcer.log.Info("parses the ebpf program into a CollectionSpec")
	var (
		collectionSpec *ebpf.CollectionSpec
		variant        string
	)
	// Detect bpf_loop helper availability (kernel >= 5.17).
	// NOTE: cilium/ebpf v0.20 HaveProgramHelper does not set AttachType for
	// LSM/Tracing program types, which makes the probe fail with EINVAL.
	// Use Kprobe as the probe target since helper availability is kernel-wide.
	if features.HaveProgramHelper(ebpf.Kprobe, asm.FnLoop) == nil {
		collectionSpec, err = loadBpfLoop()
		variant = "bpf_loop"
	} else {
		collectionSpec, err = loadBpf()
		variant = "unrolled"
	}
	if err != nil {
		return err
	}
	enforcer.log.Info("selected bpf variant", "variant", variant)

	// Set mount rule count based on BPF variant
	if variant == "bpf_loop" {
		enforcer.maxMountRuleCount = MaxBpfMountRuleCountBpfLoop
	} else {
		enforcer.maxMountRuleCount = MaxBpfMountRuleCountUnrolled
	}

	// Create a mock inner map for the file rules
	fileInnerMap := ebpf.MapSpec{
		Name:       "v_file_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  PathRuleSize,
		MaxEntries: MaxBpfFileRuleCount,
	}
	collectionSpec.Maps["v_file_outer"].InnerMap = &fileInnerMap

	// Create a mock inner map for the bprm rules
	bprmInnerMap := ebpf.MapSpec{
		Name:       "v_bprm_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  PathRuleSize,
		MaxEntries: MaxBpfFileRuleCount,
	}
	collectionSpec.Maps["v_bprm_outer"].InnerMap = &bprmInnerMap

	// Create a mock inner map for the network rules
	netInnerMap := ebpf.MapSpec{
		Name:       "v_net_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  NetRuleSize,
		MaxEntries: MaxBpfNetworkRuleCount,
	}
	collectionSpec.Maps["v_net_outer"].InnerMap = &netInnerMap

	mountInnerMap := ebpf.MapSpec{
		Name:       "v_mount_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  MountRuleSize,
		MaxEntries: enforcer.maxMountRuleCount,
	}
	collectionSpec.Maps["v_mount_outer"].InnerMap = &mountInnerMap

	// Set the mnt ns id to the BPF program
	initMntNsID, err := varmorutils.ReadMntNsID(1)
	if err != nil {
		return err
	}
	collectionSpec.Variables["init_mnt_ns"].Set(initMntNsID)

	// Load pre-compiled programs and maps into the kernel.
	if err := os.MkdirAll(PinPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create bpf fs subpath: %+v", err)
	}
	enforcer.log.Info("load ebpf program and maps into the kernel")
	err = collectionSpec.LoadAndAssign(&enforcer.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: PinPath,
		},
	})
	if err != nil {
		return err
	}

	// Attach BPF program to the hook points of LSM framework
	enforcer.log.Info("attach VarmorCapable to the LSM hook point")
	capableLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorCapable,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorCapable) failed: %v", err)
	}
	enforcer.capableLink = capableLink

	enforcer.log.Info("attach VarmorFileOpen to the LSM hook point")
	openFileLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorFileOpen,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorFileOpen) failed: %v", err)
	}
	enforcer.openFileLink = openFileLink

	enforcer.log.Info("attach VarmorPathSymlink to the LSM hook point")
	pathSymlinkLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathSymlink,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorPathSymlink) failed: %v", err)
	}
	enforcer.pathSymlinkLink = pathSymlinkLink

	enforcer.log.Info("attach VarmorPathLink to the LSM hook point")
	pathLinkLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathLink,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorPathLink) failed: %v", err)
	}
	enforcer.pathLinkLink = pathLinkLink

	enforcer.log.Info("attach VarmorPathRename to the LSM hook point")
	pathRenameLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathRename,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorPathRename) failed: %v", err)
	}
	enforcer.pathRenameLink = pathRenameLink

	enforcer.log.Info("attach VarmorBprmCheckSecurity to the LSM hook point")
	bprmLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorBprmCheckSecurity,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorBprmCheckSecurity) failed: %v", err)
	}
	enforcer.bprmLink = bprmLink

	enforcer.log.Info("attach VarmorSocketCreate to the LSM hook point")
	socketLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorSocketCreate,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorSocketCreate) failed: %v", err)
	}
	enforcer.socketLink = socketLink

	enforcer.log.Info("attach VarmorSocketConnect to the LSM hook point")
	sockConnLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorSocketConnect,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorSocketConnect) failed: %v", err)
	}
	enforcer.sockConnLink = sockConnLink

	enforcer.log.Info("attach VarmorPtraceAccessCheck to the LSM hook point")
	ptraceLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPtraceAccessCheck,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorPtraceAccessCheck) failed: %v", err)
	}
	enforcer.ptraceLink = ptraceLink

	enforcer.log.Info("attach VarmorMount to the LSM hook point")
	mountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorMount,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorMount) failed: %v", err)
	}
	enforcer.mountLink = mountLink

	enforcer.log.Info("attach VarmorMoveMount to the LSM hook point")
	moveMountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorMoveMount,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorMoveMount) failed: %v", err)
	}
	enforcer.moveMountLink = moveMountLink

	enforcer.log.Info("attach VarmorUmount to the LSM hook point")
	umountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorUmount,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM(VarmorUmount) failed: %v", err)
	}
	enforcer.umountLink = umountLink

	return nil
}

// Close close the BPF resources
func (enforcer *BpfEnforcer) Close() {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	if enforcer.closed {
		return
	}
	enforcer.closed = true
	enforcer.log.Info("unload the bpf resources")
	enforcer.capableLink.Close()
	enforcer.openFileLink.Close()
	enforcer.pathSymlinkLink.Close()
	enforcer.pathLinkLink.Close()
	enforcer.pathRenameLink.Close()
	enforcer.bprmLink.Close()
	enforcer.sockConnLink.Close()
	enforcer.socketLink.Close()
	enforcer.ptraceLink.Close()
	enforcer.mountLink.Close()
	enforcer.moveMountLink.Close()
	enforcer.umountLink.Close()
	enforcer.objs.V_auditRb.Unpin()
	os.RemoveAll(PinPath)
	enforcer.objs.Close()
}

func (enforcer *BpfEnforcer) setPodIps(mntNsID uint32, addresses []string) error {
	if len(addresses) > 2 {
		return fmt.Errorf("pods may be allocated at most 1 value for each of IPv4 and IPv6")
	}

	var podIP bpfPodIp
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			return fmt.Errorf("the address is not a valid textual representation of an IP address")
		}
		if ip.To4() != nil {
			podIP.Flags |= Ipv4Match
			copy(podIP.Ipv4[:], ip.To4())
		} else {
			podIP.Flags |= Ipv6Match
			copy(podIP.Ipv6[:], ip.To16())
		}
	}
	return enforcer.objs.V_podIp.Put(&mntNsID, podIP)
}

func (enforcer *BpfEnforcer) removePodIps(mntNsID uint32) error {
	return enforcer.objs.V_podIp.Delete(&mntNsID)
}

func (enforcer *BpfEnforcer) eventHandler(stopCh <-chan struct{}) {
	logger := enforcer.log.WithName("eventHandler()")
	logger.Info("start handling the containerd events")
	for {
		select {
		case info := <-enforcer.TaskStartCh:
			enforcer.handleTaskStart(info)
		case info := <-enforcer.TaskDeleteCh:
			enforcer.handleTaskDelete(info)
		case <-enforcer.TaskDeleteSyncCh:
			enforcer.handleTaskDeleteSync()
		case <-stopCh:
			logger.Info("stop handling the containerd events")
			return
		}
	}
}

func (enforcer *BpfEnforcer) handleTaskStart(info varmortypes.ContainerInfo) {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	if enforcer.closed {
		return
	}
	logger := enforcer.log.WithName("handleTaskStart()")
	key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", info.ContainerName)
	value := info.PodAnnotations[key]
	if !strings.HasPrefix(value, "localhost/") {
		return
	}
	profileName := strings.TrimPrefix(value, "localhost/")
	profile, ok := enforcer.bpfProfileCache[profileName]
	if !ok {
		return
	}
	id, err := enforcer.newEnforceID(info.PID, info.PodIPs)
	if err != nil {
		logger.Error(err, "newEnforceID() failed")
		return
	}
	oldID, tracked := profile.containerCache[info.ContainerID]
	_, pending := profile.pendingContainers[info.ContainerID]
	if tracked && reflect.DeepEqual(oldID, id) && !pending &&
		enforcer.namespaceOwners[id.mntNsID] == info.ContainerID {
		return
	}

	logger.Info("applying profile to target container", "profile name", profileName,
		"container id", info.ContainerID, "pod namespace", info.PodNamespace,
		"pod name", info.PodName, "pid", id.pid, "mnt ns id", id.mntNsID)

	// Keep an already tracked container recoverable, including an identity
	// change. Never let a failed event replay leave it marked as applied.
	if previous, exists := enforcer.containerCache[info.ContainerID]; exists &&
		(!tracked || previous.mntNsID != id.mntNsID) {
		enforcer.removeContainerLocked(info.ContainerID)
	}
	if tracked {
		profile.containerCache[info.ContainerID] = id
		enforcer.containerCache[info.ContainerID] = id
		profile.pendingContainers[info.ContainerID] = struct{}{}
	}
	enforcer.claimNamespaceLocked(info.ContainerID, id.mntNsID)
	if err := enforcer.applyContainerProfile(id, profile); err != nil {
		logger.Error(err, "apply container profile failed", "profile name", profileName,
			"container id", info.ContainerID, "mnt ns id", id.mntNsID)
		// First-time TaskStart failures retain the existing reporting behavior.
		// They are not registered as successfully protected containers.
		if !tracked {
			if len(id.ips) > 0 {
				if cleanupErr := enforcer.profileOps.removePodIps(id.mntNsID); cleanupErr != nil && !errors.Is(cleanupErr, ebpf.ErrKeyNotExist) {
					logger.Error(cleanupErr, "removePodIps() failed")
				}
			}
			delete(enforcer.namespaceOwners, id.mntNsID)
		}
		return
	}
	enforcer.containerCache[info.ContainerID] = id
	profile.containerCache[info.ContainerID] = id
	delete(profile.pendingContainers, info.ContainerID)
	enforcer.bpfProfileCache[profileName] = profile
}

// applyContainerProfile also restores Pod IPs when retrying an event failure.
func (enforcer *BpfEnforcer) applyContainerProfile(id enforceID, profile bpfProfile) error {
	if len(id.ips) > 0 {
		if err := enforcer.profileOps.setPodIps(id.mntNsID, id.ips); err != nil {
			return fmt.Errorf("setPodIps: %w", err)
		}
	}
	return enforcer.profileOps.applyProfile(id.mntNsID, profile.mode, profile.bpfContent)
}

// claimNamespaceLocked retires the previous container before any writes for
// a new owner, including failed first-time applications. Otherwise a late
// deletion or an old pending retry could change the new container's rules.
func (enforcer *BpfEnforcer) claimNamespaceLocked(containerID string, nsID uint32) {
	if previous, exists := enforcer.namespaceOwners[nsID]; exists && previous != containerID {
		enforcer.removeContainerLocked(previous)
	}
	enforcer.namespaceOwners[nsID] = containerID
}

// removeContainerLocked is shared by explicit deletion and offline cleanup.
func (enforcer *BpfEnforcer) removeContainerLocked(containerID string) {
	if id, ok := enforcer.containerCache[containerID]; ok {
		delete(enforcer.containerCache, containerID)
		if enforcer.namespaceOwners[id.mntNsID] == containerID {
			delete(enforcer.namespaceOwners, id.mntNsID)
			if err := enforcer.profileOps.removePodIps(id.mntNsID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				enforcer.log.Error(err, "removePodIps() failed", "container id", containerID)
			}
			enforcer.profileOps.deleteProfile(id.mntNsID)
		}
	}
	for _, profile := range enforcer.bpfProfileCache {
		delete(profile.containerCache, containerID)
		delete(profile.pendingContainers, containerID)
	}
}

func (enforcer *BpfEnforcer) handleTaskDelete(info varmortypes.ContainerInfo) {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	if !enforcer.closed {
		enforcer.removeContainerLocked(info.ContainerID)
	}
}

func (enforcer *BpfEnforcer) handleTaskDeleteSync() {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	if enforcer.closed {
		return
	}
	for containerID, id := range enforcer.containerCache {
		current, err := enforcer.newEnforceID(id.pid, nil)
		if err != nil || current.mntNsID != id.mntNsID {
			enforcer.log.Info("removing exited container", "container id", containerID,
				"pid", id.pid, "mnt ns id", id.mntNsID)
			// A reused PID does not keep an exited container alive in the cache.
			enforcer.removeContainerLocked(containerID)
		}
	}
}

func (enforcer *BpfEnforcer) Run(stopCh <-chan struct{}) {
	enforcer.startupGC()
	enforcer.eventHandler(stopCh)
}

func (enforcer *BpfEnforcer) pretreatment(bpfContent *varmor.BpfContent) error {
	needsDevices := false
	for _, file := range bpfContent.Files {
		needsDevices = needsDevices || file.Pattern.Prefix == "{{.DiskDevices}}"
	}
	for _, mount := range bpfContent.Mounts {
		needsDevices = needsDevices || mount.Pattern.Prefix == "{{.DiskDevices}}"
	}
	if !needsDevices {
		return nil
	}
	devices, err := lsmutils.RetrieveDiskDeviceList()
	if err != nil {
		return fmt.Errorf("retrieve disk devices: %w", err)
	}
	expandDiskDevices(bpfContent, devices)
	return nil
}

func expandDiskDevices(content *varmor.BpfContent, devices []string) {
	var files []varmor.FileContent
	for _, file := range content.Files {
		if file.Pattern.Prefix != "{{.DiskDevices}}" {
			files = append(files, file)
			continue
		}
		for _, device := range devices {
			expanded := file
			expanded.Pattern.Prefix = "/dev/" + device
			files = append(files, expanded)
		}
	}
	var mounts []varmor.MountContent
	for _, mount := range content.Mounts {
		if mount.Pattern.Prefix != "{{.DiskDevices}}" {
			mounts = append(mounts, mount)
			continue
		}
		for _, device := range devices {
			expanded := mount
			expanded.Pattern.Prefix = "/dev/" + device
			mounts = append(mounts, expanded)
		}
	}
	content.Files = files
	content.Mounts = mounts
}

// SaveAndApplyBpfProfile caches the desired profile and applies it to tracked
// containers. Content equality alone does not establish successful application.
func (enforcer *BpfEnforcer) SaveAndApplyBpfProfile(profileName string, mode varmor.ProfileMode, bpfContent varmor.BpfContent) error {
	// Preprocessing must not mutate the caller or alias the cached snapshot.
	content := bpfContent.DeepCopy()
	if err := enforcer.pretreatment(content); err != nil {
		return err
	}

	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	if enforcer.closed {
		return fmt.Errorf("BPF enforcer is closed")
	}
	// Reject deterministic capacity errors before replacing either the cached
	// desired state or any existing kernel rules. Preserve pending work too.
	if err := enforcer.validateRuleCapacity(*content); err != nil {
		return err
	}
	profile, exists := enforcer.bpfProfileCache[profileName]
	if !exists {
		profile = bpfProfile{
			containerCache:    make(map[string]enforceID),
			pendingContainers: make(map[string]struct{}),
		}
	}
	if !exists || mode != profile.mode || !reflect.DeepEqual(*content, profile.bpfContent) {
		profile.mode = mode
		profile.bpfContent = *content
		// Include every container on changes and reverts: some may have
		// applied the previous desired version before another one failed.
		for containerID := range profile.containerCache {
			profile.pendingContainers[containerID] = struct{}{}
		}
		enforcer.bpfProfileCache[profileName] = profile
	}

	// Independent mount namespaces let us retry each pending container
	// directly, without grouping or scanning already applied containers.
	var applyErrors []error
	for containerID := range profile.pendingContainers {
		id := profile.containerCache[containerID]
		if enforcer.namespaceOwners[id.mntNsID] != containerID {
			enforcer.removeContainerLocked(containerID)
			continue
		}
		if err := enforcer.applyContainerProfile(id, profile); err != nil {
			applyErrors = append(applyErrors, fmt.Errorf("profile %s, container %s, mount namespace %d: %w",
				profileName, containerID, id.mntNsID, err))
			continue
		}
		delete(profile.pendingContainers, containerID)
	}
	return errors.Join(applyErrors...)
}

// DeleteBpfProfile unloads a profile and discards its pending applications.
func (enforcer *BpfEnforcer) DeleteBpfProfile(profileName string) error {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	if enforcer.closed {
		return fmt.Errorf("BPF enforcer is closed")
	}
	if profile, ok := enforcer.bpfProfileCache[profileName]; ok {
		for containerID := range profile.containerCache {
			enforcer.removeContainerLocked(containerID)
		}
		delete(enforcer.bpfProfileCache, profileName)
	}
	return nil
}

func (enforcer *BpfEnforcer) IsBpfProfileExist(profileName string) bool {
	enforcer.mu.RLock()
	defer enforcer.mu.RUnlock()
	_, ok := enforcer.bpfProfileCache[profileName]
	return !enforcer.closed && ok
}
