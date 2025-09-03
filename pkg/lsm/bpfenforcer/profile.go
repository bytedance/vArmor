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
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

// newEnforceID retrieve the mnt ns id with PID from the procfs, then create an enforceID object with it
func (enforcer *BpfEnforcer) newEnforceID(pid uint32, ips []string) (enforceID, error) {
	mntNsID, err := varmorutils.ReadMntNsID(pid)
	if err != nil {
		return enforceID{}, err
	}

	id := enforceID{
		pid:     pid,
		mntNsID: mntNsID,
		ips:     ips,
	}
	return id, nil
}

func (enforcer *BpfEnforcer) SetProfileMode(mntNsID uint32, profileMode uint32) error {
	return enforcer.objs.V_profileMode.Put(&mntNsID, profileMode)
}

func (enforcer *BpfEnforcer) applyCapabilityRule(nsID uint32, capabilities *varmor.CapabilitiesContent) error {
	if capabilities != nil {
		rule := bpfCapabilityRule{
			Mode: capabilities.Mode,
			Caps: capabilities.Capabilities,
		}
		err := enforcer.objs.V_capable.Put(&nsID, &rule)
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
			ValueSize:  PathRuleSize,
			MaxEntries: MaxBpfFileRuleCount,
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, file := range files {
			var prefix, suffix [MaxFilePathPatternLength]byte
			copy(prefix[:], file.Pattern.Prefix)
			copy(suffix[:], file.Pattern.Suffix)

			rule := bpfPathRule{
				Mode:        file.Mode,
				Permissions: file.Permissions,
				Pattern: pathPattern{
					Flags:  file.Pattern.Flags,
					Prefix: prefix,
					Suffix: suffix,
				},
			}
			index := uint32(i)
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
			ValueSize:  PathRuleSize,
			MaxEntries: MaxBpfBprmRuleCount,
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, file := range processes {
			var prefix, suffix [MaxFilePathPatternLength]byte
			copy(prefix[:], file.Pattern.Prefix)
			copy(suffix[:], file.Pattern.Suffix)

			rule := bpfPathRule{
				Mode:        file.Mode,
				Permissions: file.Permissions,
				Pattern: pathPattern{
					Flags:  file.Pattern.Flags,
					Prefix: prefix,
					Suffix: suffix,
				},
			}
			index := uint32(i)
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
			ValueSize:  NetRuleSize,
			MaxEntries: MaxBpfNetworkRuleCount,
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, network := range networks {
			rule := bpfNetworkRule{
				Mode:  network.Mode,
				Flags: network.Flags,
			}

			if network.Address != nil {
				// Socket Connect
				rule.Port = network.Address.Port
				rule.EndPort = network.Address.EndPort
				if len(network.Address.Ports) > 16 {
					return fmt.Errorf("too many ports in a single network rule, max is 16")
				} else {
					copy(rule.Ports[:], network.Address.Ports)
				}

				switch network.Address.IP {
				case "", varmor.PodSelfIP, varmor.Unspecified:
					break
				default:
					ip := net.ParseIP(network.Address.IP)
					if ip.To4() != nil {
						copy(rule.Address[:], ip.To4())
					} else {
						copy(rule.Address[:], ip.To16())
					}
				}

				if network.Address.CIDR != "" {
					_, ipNet, err := net.ParseCIDR(network.Address.CIDR)
					if err != nil {
						return err
					}
					copy(rule.Mask[:], ipNet.Mask)
				}
			} else if network.Socket != nil {
				// Socket Create
				rule.Domains = network.Socket.Domains
				rule.Types = network.Socket.Types
				rule.Protocols = network.Socket.Protocols
			} else {
				continue
			}

			index := uint32(i)
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

func (enforcer *BpfEnforcer) applyPtraceRule(nsID uint32, ptrace *varmor.PtraceContent) error {
	if ptrace != nil {
		rule := bpfPtraceRule{
			Mode:        ptrace.Mode,
			Permissions: ptrace.Permissions,
			Flags:       ptrace.Flags,
		}
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
			ValueSize:  MountRuleSize,
			MaxEntries: MaxBpfMountRuleCount,
		}
		innerMap, err := ebpf.NewMap(&innerMapSpec)
		if err != nil {
			return err
		}
		defer innerMap.Close()

		for i, mount := range mounts {
			var fstype [MaxFileSystemTypeLength]byte
			var prefix, suffix [MaxFilePathPatternLength]byte
			copy(fstype[:], mount.Fstype)
			copy(prefix[:], mount.Pattern.Prefix)
			copy(suffix[:], mount.Pattern.Suffix)

			var rule bpfMountRule
			rule.Mode = mount.Mode
			rule.MountFlags = mount.MountFlags
			rule.ReverseMountFlags = mount.ReverseMountflags
			rule.Fstype = fstype
			rule.Pattern.Flags = mount.Pattern.Flags
			rule.Pattern.Prefix = prefix
			rule.Pattern.Suffix = suffix
			index := uint32(i)
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

func (enforcer *BpfEnforcer) applyProfile(nsID uint32, mode varmor.ProfileMode, bpfContent varmor.BpfContent) (err error) {

	switch mode {
	case varmor.ProfileModeEnforce:
		err = enforcer.SetProfileMode(nsID, EnforceMode)
		if err != nil {
			return err
		}
	case varmor.ProfileModeComplain:
		err = enforcer.SetProfileMode(nsID, ComplainMode)
		if err != nil {
			return err
		}
	}

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
	// profile mode
	err := enforcer.objs.V_profileMode.Delete(&nsID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		enforcer.log.Error(err, "V_profileMode.Delete()")
	}

	// capability rule
	err = enforcer.objs.V_capable.Delete(&nsID)
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
