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
	"errors"
	"fmt"
	"net"

	ebpf "github.com/cilium/ebpf"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

// newEnforceID retrieve the mnt ns id with PID from the procfs, then create an enforceID object with it
func (enforcer *BpfEnforcer) newEnforceID(pid uint32) (enforceID, error) {
	mntNsID, err := varmorutils.ReadMntNsID(pid)
	if err != nil {
		return enforceID{}, err
	}

	id := enforceID{
		pid:     pid,
		mntNsID: mntNsID,
	}
	return id, nil
}

func (enforcer *BpfEnforcer) applyCapabilityRule(nsID uint32, caps uint64) error {
	if caps != 0 {
		err := enforcer.objs.V_capable.Put(&nsID, &caps)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_capable.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_capable.Delete()")
		}
	}
	return nil
}

func (enforcer *BpfEnforcer) applyFileRules(nsID uint32, files []varmor.FileContent) error {
	if len(files) != 0 {
		mapName := fmt.Sprintf("v_file_inner_%d", nsID)
		innerMapSpec := ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4*2 + uint32(varmortypes.MaxFilePathPatternLength)*2,
			MaxEntries: uint32(varmortypes.MaxBpfFileRuleCount),
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, file := range files {
			var prefix, suffix [varmortypes.MaxFilePathPatternLength]byte
			copy(prefix[:], file.Pattern.Prefix)
			copy(suffix[:], file.Pattern.Suffix)

			var rule bpfPathRule
			rule.Permissions = file.Permissions
			rule.Pattern.Flags = file.Pattern.Flags
			rule.Pattern.Prefix = prefix
			rule.Pattern.Suffix = suffix
			var index uint32 = uint32(i)
			err = innerMap.Put(&index, &rule)
			if err != nil {
				return err
			}
		}
		err = enforcer.objs.V_fileOuter.Put(&nsID, innerMap)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_fileOuter.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_fileOuter.Delete()")
		}
	}

	return nil
}

func (enforcer *BpfEnforcer) applyProcessRules(nsID uint32, processes []varmor.FileContent) error {
	if len(processes) != 0 {
		mapName := fmt.Sprintf("v_bprm_inner_%d", nsID)
		innerMapSpec := ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4*2 + uint32(varmortypes.MaxFilePathPatternLength)*2,
			MaxEntries: uint32(varmortypes.MaxBpfBprmRuleCount),
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, file := range processes {
			var prefix, suffix [varmortypes.MaxFilePathPatternLength]byte
			copy(prefix[:], file.Pattern.Prefix)
			copy(suffix[:], file.Pattern.Suffix)

			var rule bpfPathRule
			rule.Permissions = file.Permissions
			rule.Pattern.Flags = file.Pattern.Flags
			rule.Pattern.Prefix = prefix
			rule.Pattern.Suffix = suffix
			var index uint32 = uint32(i)
			err = innerMap.Put(&index, &rule)
			if err != nil {
				return err
			}
		}
		err = enforcer.objs.V_bprmOuter.Put(&nsID, innerMap)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_bprmOuter.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_bprmOuter.Delete()")
		}
	}

	return nil
}

func (enforcer *BpfEnforcer) applyNetworkRules(nsID uint32, networks []varmor.NetworkContent) error {
	if len(networks) != 0 {
		mapName := fmt.Sprintf("v_net_inner_%d", nsID)
		innerMapSpec := ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4*2 + 16*2,
			MaxEntries: uint32(varmortypes.MaxBpfNetworkRuleCount),
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, network := range networks {
			var rule bpfNetworkRule

			rule.Flags = network.Flags
			rule.Port = network.Port
			ip := net.ParseIP(network.Address)
			if ip.To4() != nil {
				copy(rule.Address[:], ip.To4())
			} else {
				copy(rule.Address[:], ip.To16())
			}

			if network.CIDR != "" {
				_, ipNet, err := net.ParseCIDR(network.CIDR)
				if err != nil {
					return err
				}
				copy(rule.Mask[:], ipNet.Mask)
			}

			var index uint32 = uint32(i)
			err = innerMap.Put(&index, &rule)
			if err != nil {
				return err
			}
		}
		err = enforcer.objs.V_netOuter.Put(&nsID, innerMap)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_netOuter.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_netOuter.Delete()")
		}
	}

	return nil
}

func (enforcer *BpfEnforcer) applyPtraceRule(nsID uint32, ptrace varmor.PtraceContent) error {
	if ptrace.Permissions != 0 && ptrace.Flags != 0 {
		rule := uint64(ptrace.Permissions)<<32 + uint64(ptrace.Flags)
		err := enforcer.objs.V_ptrace.Put(&nsID, &rule)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_ptrace.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_ptrace.Delete()")
		}
	}
	return nil
}

func (enforcer *BpfEnforcer) applyMountRules(nsID uint32, mounts []varmor.MountContent) error {
	if len(mounts) != 0 {
		mapName := fmt.Sprintf("v_mount_inner_%d", nsID)
		innerMapSpec := ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4*3 + uint32(varmortypes.MaxFileSystemTypeLength) + uint32(varmortypes.MaxFilePathPatternLength)*2,
			MaxEntries: uint32(varmortypes.MaxBpfMountRuleCount),
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, mount := range mounts {
			var fstype [varmortypes.MaxFileSystemTypeLength]byte
			var prefix, suffix [varmortypes.MaxFilePathPatternLength]byte
			copy(fstype[:], mount.Fstype)
			copy(prefix[:], mount.Pattern.Prefix)
			copy(suffix[:], mount.Pattern.Suffix)

			var rule bpfMountRule
			rule.MountFlags = mount.MountFlags
			rule.ReverseMountFlags = mount.ReverseMountflags
			rule.Fstype = fstype
			rule.Pattern.Flags = mount.Pattern.Flags
			rule.Pattern.Prefix = prefix
			rule.Pattern.Suffix = suffix
			var index uint32 = uint32(i)
			err = innerMap.Put(&index, &rule)
			if err != nil {
				return err
			}
		}
		err = enforcer.objs.V_mountOuter.Put(&nsID, innerMap)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_mountOuter.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_mountOuter.Delete()")
		}
	}

	return nil
}

func (enforcer *BpfEnforcer) applyProfile(nsID uint32, bpfContent varmor.BpfContent) (err error) {
	err = enforcer.applyCapabilityRule(nsID, bpfContent.Capabilities)
	if err != nil {
		return err
	}

	err = enforcer.applyFileRules(nsID, bpfContent.Files)
	if err != nil {
		return err
	}

	err = enforcer.applyProcessRules(nsID, bpfContent.Processes)
	if err != nil {
		return err
	}

	err = enforcer.applyNetworkRules(nsID, bpfContent.Networks)
	if err != nil {
		return err
	}

	err = enforcer.applyPtraceRule(nsID, bpfContent.Ptrace)
	if err != nil {
		return err
	}

	err = enforcer.applyMountRules(nsID, bpfContent.Mounts)
	if err != nil {
		return err
	}

	return nil
}

func (enforcer *BpfEnforcer) deleteProfile(nsID uint32) {
	// capability rule
	err := enforcer.objs.V_capable.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_capable.Delete()")
	}

	// file rules
	err = enforcer.objs.V_fileOuter.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_fileOuter.Delete()")
	}

	// process rules
	err = enforcer.objs.V_bprmOuter.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_bprmOuter.Delete()")
	}

	// network rules
	err = enforcer.objs.V_netOuter.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_netOuter.Delete()")
	}

	// ptrace rule
	err = enforcer.objs.V_ptrace.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_ptrace.Delete()")
	}

	// mount rules
	err = enforcer.objs.V_mountOuter.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_mountOuter.Delete()")
	}
}
