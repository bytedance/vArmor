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

package bpfenforcer

import (
	"fmt"
	"os"
	"reflect"

	"github.com/cilium/ebpf"
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
}

type bpfProfile struct {
	bpfContent     varmor.BpfContent
	containerCache map[string]enforceID // local cache <containerID: enforceID>
}

type BpfEnforcer struct {
	TaskStartCh      chan varmortypes.ContainerInfo
	TaskDeleteCh     chan varmortypes.ContainerInfo
	TaskDeleteSyncCh chan bool
	objs             bpfObjects
	capableLink      link.Link
	openFileLink     link.Link
	pathSymlinkLink  link.Link
	pathLinkLink     link.Link
	pathRenameLink   link.Link
	bprmLink         link.Link
	sockConnLink     link.Link
	ptraceLink       link.Link
	mountLink        link.Link
	moveMountLink    link.Link
	umountLink       link.Link
	bpfProfileCache  map[string]bpfProfile // <profileName: bpfProfile>
	containerCache   map[string]enforceID  // global cache <containerID: enforceID>
	log              logr.Logger
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
		log:              log,
	}

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
	collectionSpec, err := loadBpf()
	if err != nil {
		return err
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
		MaxEntries: MaxBpfMountRuleCount,
	}
	collectionSpec.Maps["v_mount_outer"].InnerMap = &mountInnerMap

	// Set the mnt ns id to the BPF program
	initMntNsId, err := varmorutils.ReadMntNsID(1)
	if err != nil {
		return err
	}
	collectionSpec.RewriteConstants(map[string]interface{}{
		"init_mnt_ns": initMntNsId,
	})

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
		return err
	}
	enforcer.capableLink = capableLink

	enforcer.log.Info("attach VarmorFileOpen to the LSM hook point")
	openFileLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorFileOpen,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM() failed: %v", err)
	}
	enforcer.openFileLink = openFileLink

	enforcer.log.Info("attach VarmorPathSymlink to the LSM hook point")
	pathSymlinkLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathSymlink,
	})
	if err != nil {
		return err
	}
	enforcer.pathSymlinkLink = pathSymlinkLink

	enforcer.log.Info("attach VarmorPathLink to the LSM hook point")
	pathLinkLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathLink,
	})
	if err != nil {
		return err
	}
	enforcer.pathLinkLink = pathLinkLink

	enforcer.log.Info("attach VarmorPathRename to the LSM hook point")
	pathRenameLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathRename,
	})
	if err != nil {
		return err
	}
	enforcer.pathRenameLink = pathRenameLink

	enforcer.log.Info("attach VarmorBprmCheckSecurity to the LSM hook point")
	bprmLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorBprmCheckSecurity,
	})
	if err != nil {
		return fmt.Errorf("link.AttachLSM() failed: %v", err)
	}
	enforcer.bprmLink = bprmLink

	enforcer.log.Info("attach VarmorSocketConnect to the LSM hook point")
	sockConnLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorSocketConnect,
	})
	if err != nil {
		return err
	}
	enforcer.sockConnLink = sockConnLink

	enforcer.log.Info("attach VarmorPtraceAccessCheck to the LSM hook point")
	ptraceLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPtraceAccessCheck,
	})
	if err != nil {
		return err
	}
	enforcer.ptraceLink = ptraceLink

	enforcer.log.Info("attach VarmorMount to the LSM hook point")
	mountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorMount,
	})
	if err != nil {
		return err
	}
	enforcer.mountLink = mountLink

	enforcer.log.Info("attach VarmorMoveMount to the LSM hook point")
	moveMountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorMoveMount,
	})
	if err != nil {
		return nil
	}
	enforcer.moveMountLink = moveMountLink

	enforcer.log.Info("attach VarmorUmount to the LSM hook point")
	umountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorUmount,
	})
	if err != nil {
		return nil
	}
	enforcer.umountLink = umountLink

	return nil
}

// Close close the BPF resources
func (enforcer *BpfEnforcer) Close() {
	enforcer.log.Info("unload the bpf resources")
	enforcer.capableLink.Close()
	enforcer.openFileLink.Close()
	enforcer.pathSymlinkLink.Close()
	enforcer.pathLinkLink.Close()
	enforcer.pathRenameLink.Close()
	enforcer.bprmLink.Close()
	enforcer.sockConnLink.Close()
	enforcer.ptraceLink.Close()
	enforcer.mountLink.Close()
	enforcer.moveMountLink.Close()
	enforcer.umountLink.Close()
	enforcer.objs.V_auditRb.Unpin()
	os.RemoveAll(PinPath)
	enforcer.objs.Close()

}

func (enforcer *BpfEnforcer) eventHandler(stopCh <-chan struct{}) {
	logger := enforcer.log.WithName("eventHandler()")
	logger.Info("start handling the containerd events")

	for {
		select {
		case info := <-enforcer.TaskStartCh:
			// Handle the creation event of target container
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", info.ContainerName)
			value, ok := info.PodAnnotations[key]
			if !ok {
				break
			}

			profileName := value[len("localhost/"):]
			if profile, ok := enforcer.bpfProfileCache[profileName]; ok {
				logger.Info("target container was created",
					"profile name", profileName,
					"pod namespace", info.PodNamespace,
					"pod name", info.PodName,
					"container name", info.ContainerName,
					"container id", info.ContainerID,
					"pid", info.PID, "mnt ns id", info.MntNsID)

				// create an enforceID
				enforceID, err := enforcer.newEnforceID(info.PID)
				if err != nil {
					logger.Error(err, "newEnforceID() failed")
					break
				}

				// nothing needs to change if the container has been protected
				if oldEnforceID, ok := enforcer.containerCache[info.ContainerID]; ok {
					if reflect.DeepEqual(oldEnforceID, enforceID) {
						break
					}
				}

				// apply the BPF profile for the target container
				err = enforcer.applyProfile(enforceID.mntNsID, profile.bpfContent)
				if err != nil {
					logger.Error(err, "applyProfile() failed")
					break
				}

				// cache the enforceID
				enforcer.containerCache[info.ContainerID] = enforceID
				profile.containerCache[info.ContainerID] = enforceID
				enforcer.bpfProfileCache[profileName] = profile
			}

		case info := <-enforcer.TaskDeleteCh:
			// Handle the deletion event of target container
			if enforceID, ok := enforcer.containerCache[info.ContainerID]; ok {
				logger.Info("target container was deleted",
					"container id", info.ContainerID,
					"pid", info.PID)

				// delete the BPF profile of the container
				enforcer.deleteProfile(enforceID.mntNsID)

				// delete the container from the global cache
				delete(enforcer.containerCache, info.ContainerID)

				// delete the container from the local cache
				for profileName, profile := range enforcer.bpfProfileCache {
					if _, ok := profile.containerCache[info.ContainerID]; ok {
						delete(profile.containerCache, info.ContainerID)
						enforcer.bpfProfileCache[profileName] = profile
						break
					}
				}
			}

		case <-enforcer.TaskDeleteSyncCh:
			// Handle those containers that exit while the monitor was offline
			for profileName, profile := range enforcer.bpfProfileCache {
				for containerID, enforceID := range profile.containerCache {
					_, err := enforcer.newEnforceID(enforceID.pid)
					if err != nil {
						// maybe the container had already exited
						logger.Info("the target container exited while the monitor was offline",
							"container id", containerID,
							"pid", enforceID.pid)

						// delete the BPF profile of the container
						enforcer.deleteProfile(enforceID.mntNsID)

						// delete the container from the global cache
						delete(enforcer.containerCache, containerID)

						// delete the container from the local cache
						delete(profile.containerCache, containerID)
						enforcer.bpfProfileCache[profileName] = profile
					}
				}
			}

		case <-stopCh:
			logger.Info("stop handling the containerd events")
			return
		}
	}
}

func (enforcer *BpfEnforcer) Run(stopCh <-chan struct{}) {
	enforcer.eventHandler(stopCh)
}

func (enforcer *BpfEnforcer) pretreatment(bpfContent *varmor.BpfContent) {
	// Disk Device
	for index, file := range bpfContent.Files {
		if file.Pattern.Prefix == "{{.DiskDevices}}" {
			bpfContent.Files = append(bpfContent.Files[:index], bpfContent.Files[index+1:]...)

			devices, err := lsmutils.RetrieveDiskDeviceList()
			if err != nil {
				enforcer.log.Error(err, "lsmutils.RetrieveDiskDeviceList()")
				break
			}

			for _, device := range devices {
				content := varmor.FileContent{
					Permissions: file.Permissions,
					Pattern: varmor.PathPattern{
						Flags:  file.Pattern.Flags,
						Prefix: "/dev/" + device,
					},
				}
				bpfContent.Files = append(bpfContent.Files, content)
			}
		}
	}

	for index, mount := range bpfContent.Mounts {
		if mount.Pattern.Prefix == "{{.DiskDevices}}" {
			bpfContent.Mounts = append(bpfContent.Mounts[:index], bpfContent.Mounts[index+1:]...)

			devices, err := lsmutils.RetrieveDiskDeviceList()
			if err != nil {
				enforcer.log.Error(err, "lsmutils.RetrieveDiskDeviceList()")
				break
			}

			for _, device := range devices {
				content := varmor.MountContent{
					MountFlags:        mount.MountFlags,
					ReverseMountflags: mount.ReverseMountflags,
					Fstype:            mount.Fstype,
					Pattern: varmor.PathPattern{
						Flags:  mount.Pattern.Flags,
						Prefix: "/dev/" + device,
					},
				}
				bpfContent.Mounts = append(bpfContent.Mounts, content)
			}
			break
		}
	}
}

// SaveAndApplyBpfProfile save the BPF profile to the cache, and update it to the kernel for the existing BPF profile
func (enforcer *BpfEnforcer) SaveAndApplyBpfProfile(profileName string, bpfContent varmor.BpfContent) error {
	enforcer.pretreatment(&bpfContent)

	// save/update the BPF profile to the cache
	if profile, ok := enforcer.bpfProfileCache[profileName]; ok {
		if reflect.DeepEqual(bpfContent, profile.bpfContent) {
			// nothing need to update
			enforcer.log.V(3).Info("the BPF profile is not changed, nothing need to update", "profile", profileName, "old", profile.bpfContent)
			return nil
		}
		enforcer.log.V(3).Info("update the BPF profile", "profile", profileName, "new", bpfContent)
		profile.bpfContent = bpfContent
		enforcer.bpfProfileCache[profileName] = profile
	} else {
		enforcer.log.V(3).Info("save the BPF profile", "profile", profileName, "new", bpfContent)
		profile := bpfProfile{
			bpfContent:     bpfContent,
			containerCache: make(map[string]enforceID),
		}
		enforcer.bpfProfileCache[profileName] = profile
	}

	// apply the BPF profile to the kernel for the existing containers
	profile := enforcer.bpfProfileCache[profileName]
	for _, enforceID := range profile.containerCache {
		enforcer.log.V(3).Info("apply the BPF profile", "profile", profileName, "new", profile.bpfContent)
		err := enforcer.applyProfile(enforceID.mntNsID, profile.bpfContent)
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteBpfProfile unload the BPF profile from kernel, then delete it from the cache
func (enforcer *BpfEnforcer) DeleteBpfProfile(profileName string) error {
	if profile, ok := enforcer.bpfProfileCache[profileName]; ok {
		for containerID, enforceID := range profile.containerCache {
			// unload the BPF profile from the kernel
			enforcer.deleteProfile(enforceID.mntNsID)

			// delete the container from the global cache
			delete(enforcer.containerCache, containerID)
		}
		// delete the profile from the bpfProfileCache
		delete(enforcer.bpfProfileCache, profileName)
	}
	return nil
}

func (enforcer *BpfEnforcer) IsBpfProfileExist(profileName string) bool {
	_, ok := enforcer.bpfProfileCache[profileName]
	return ok
}
