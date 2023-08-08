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
)

// newEnforceID retrieve the mnt ns id with PID from the procfs, then create an enforceID object with it
func (enforcer *BpfEnforcer) newEnforceID(pid uint32) (enforceID, error) {
	mntNsID, err := readMntNsID(pid)
	if err != nil {
		return enforceID{}, err
	}

	id := enforceID{
		pid:     pid,
		mntNsID: mntNsID,
	}
	return id, nil
}

func (enforcer *BpfEnforcer) applyProfile(nsID uint32, bpfContent varmor.BpfContent) error {
	// capability rules
	if bpfContent.Capabilities != 0 {
		err := enforcer.objs.V_capable.Put(&nsID, &bpfContent.Capabilities)
		if err != nil {
			return err
		}
	} else {
		err := enforcer.objs.V_capable.Delete(&nsID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			enforcer.log.Error(err, "V_capable.Delete()")
		}
	}

	// file rules
	if len(bpfContent.Files) != 0 {
		mapName := fmt.Sprintf("v_file_inner_%d", nsID)
		innerMapSpec := ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4*2 + 64*2,
			MaxEntries: uint32(varmortypes.MaxBpfFileRuleCount),
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, file := range bpfContent.Files {
			var prefix, suffix [varmortypes.MaxFilePathPatternLength]byte
			copy(prefix[:], file.Prefix)
			copy(suffix[:], file.Suffix)

			var rule bpfPathRule
			rule.Flags = file.Flags
			rule.Permissions = file.Permissions
			rule.Prefix = prefix
			rule.Suffix = suffix
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

	// process rules
	if len(bpfContent.Processes) != 0 {
		mapName := fmt.Sprintf("v_bprm_inner_%d", nsID)
		innerMapSpec := ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4*2 + 64*2,
			MaxEntries: uint32(varmortypes.MaxBpfBprmRuleCount),
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, file := range bpfContent.Processes {
			var prefix, suffix [varmortypes.MaxFilePathPatternLength]byte
			copy(prefix[:], file.Prefix)
			copy(suffix[:], file.Suffix)

			var rule bpfPathRule
			rule.Flags = file.Flags
			rule.Permissions = file.Permissions
			rule.Prefix = prefix
			rule.Suffix = suffix
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

	// network rules
	if len(bpfContent.Networks) != 0 {
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

		for i, network := range bpfContent.Networks {
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

func (enforcer *BpfEnforcer) deleteProfile(nsID uint32) {
	// capability rules
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
}
