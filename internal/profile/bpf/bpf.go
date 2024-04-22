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

package bpf

import (
	"fmt"
	"net"
	"strings"

	"github.com/dlclark/regexp2"
	"golang.org/x/sys/unix"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

const (
	PreciseMatch  = 0x00000001
	GreedyMatch   = 0x00000002
	PrefixMatch   = 0x00000004
	SuffixMatch   = 0x00000008
	CidrMatch     = 0x00000020
	Ipv4Match     = 0x00000040
	Ipv6Match     = 0x00000080
	PortMatch     = 0x00000100
	AaMayExec     = 0x00000001
	AaMayWrite    = 0x00000002
	AaMayRead     = 0x00000004
	AaMayAppend   = 0x00000008
	AaPtraceTrace = 0x00000002
	AaPtraceRead  = 0x00000004
	AaMayBeTraced = 0x00000008
	AaMayBeRead   = 0x00000010
	AaMayUmount   = 0x00000200
)

func reverseString(s string) string {
	bytes := []byte(s)
	len := len(bytes)

	for i := 0; i < len/2; i++ {
		bytes[i], bytes[len-i-1] = bytes[len-i-1], bytes[i]
	}

	return string(bytes)
}

func regexp2FindAllString(re *regexp2.Regexp, s string) []string {
	var matches []string
	m, _ := re.FindStringMatch(s)
	for m != nil {
		matches = append(matches, m.String())
		m, _ = re.FindNextMatch(m)
	}
	return matches
}

func GenerateRuntimeDefaultProfile(bpfContent *varmor.BpfContent) error {
	var err error

	fileContent, err := newBpfPathRule("/proc/sysrq-trigger", AaMayRead|AaMayWrite|AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule("/proc/**/mem", AaMayRead|AaMayWrite|AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule("/proc/kmem", AaMayRead|AaMayWrite|AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule("/proc/kcore", AaMayRead|AaMayWrite|AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule("/sys/firmware/**", AaMayRead|AaMayWrite|AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule("/sys/kernel/security/**", AaMayRead|AaMayWrite|AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	mountContent, err := newBpfMountRule("**", "*", 0xFFFFFFFF&^AaMayUmount, 0xFFFFFFFF)
	if err != nil {
		return err
	}
	bpfContent.Mounts = append(bpfContent.Mounts, *mountContent)

	if bpfContent.Ptrace == nil {
		bpfContent.Ptrace = &varmor.PtraceContent{}
	}
	bpfContent.Ptrace.Permissions = AaPtraceTrace | AaPtraceRead
	bpfContent.Ptrace.Flags = PreciseMatch

	return nil
}

func newBpfPathRule(pattern string, permissions uint32) (*varmor.FileContent, error) {
	// Pre-check
	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, pattern))

	if starWildcardLen > 0 && strings.Contains(pattern, "**") {
		return nil, fmt.Errorf("the globbing * and ** in the pattern '%s' cannot be used at the same time", pattern)
	}

	if starWildcardLen > 1 || strings.Count(pattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern '%s' can only be used once", pattern)
	}

	// Create bpfPathRule
	var pathRule varmor.FileContent
	var flags uint32

	if starWildcardLen > 0 {
		if strings.Contains(pattern, "/") {
			return nil, fmt.Errorf("the pattern '%s' with globbing * is not supported", pattern)
		}

		stringList := strings.Split(pattern, "*")

		if len(stringList[0]) > 0 {
			pathRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			pathRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else if strings.Contains(pattern, "**") {
		flags |= GreedyMatch

		stringList := strings.Split(pattern, "**")

		if len(stringList[0]) > 0 {
			pathRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			pathRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else {
		pathRule.Pattern.Prefix = pattern
		flags |= PreciseMatch | PrefixMatch
	}

	if len(pathRule.Pattern.Prefix) >= varmortypes.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of prefix '%s' should be less than the maximum (%d)", pathRule.Pattern.Prefix, varmortypes.MaxFilePathPatternLength)
	}

	if len(pathRule.Pattern.Suffix) >= varmortypes.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of suffix '%s' should be less than the maximum (%d)", pathRule.Pattern.Suffix, varmortypes.MaxFilePathPatternLength)
	}

	pathRule.Pattern.Flags = flags
	pathRule.Permissions = permissions

	return &pathRule, nil
}

func newBpfNetworkRule(cidr string, ipAddress string, port uint32) (*varmor.NetworkContent, error) {
	// Pre-check
	if cidr == "" && ipAddress == "" && port == 0 {
		return nil, fmt.Errorf("cidr, ipAddress and port cannot be empty at the same time")
	}

	if cidr != "" && ipAddress != "" {
		return nil, fmt.Errorf("cannot set CIRD and IP address at the same time")
	}

	if port > 65535 {
		return nil, fmt.Errorf("invalid network port")
	}

	var networkRule varmor.NetworkContent

	if cidr != "" {
		networkRule.Flags |= CidrMatch

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		networkRule.Address = ipNet.IP.String()
		networkRule.CIDR = ipNet.String()
		if ipNet.IP.To4() != nil {
			networkRule.Flags |= Ipv4Match
		} else {
			networkRule.Flags |= Ipv6Match
		}
	}

	if ipAddress != "" {
		networkRule.Flags |= PreciseMatch

		ip := net.ParseIP(ipAddress)
		if ip == nil {
			return nil, fmt.Errorf("the address is not a valid textual representation of an IP address")
		}

		networkRule.Address = ip.String()
		if ip.To4() != nil {
			networkRule.Flags |= Ipv4Match
		} else {
			networkRule.Flags |= Ipv6Match
		}
	}

	if port != 0 {
		networkRule.Flags |= PortMatch
		networkRule.Port = port
	}

	return &networkRule, nil
}

func newBpfMountRule(sourcePattern string, fstype string, mountFlags uint32, reverseMountFlags uint32) (*varmor.MountContent, error) {
	// Pre-check
	if len(fstype) >= varmortypes.MaxFileSystemTypeLength {
		return nil, fmt.Errorf("the length of fstype '%s' should be less than the maximum (%d)", fstype, varmortypes.MaxFileSystemTypeLength)
	}

	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, sourcePattern))

	if starWildcardLen > 0 && strings.Contains(sourcePattern, "**") {
		return nil, fmt.Errorf("the globbing * and ** in the pattern '%s' cannot be used at the same time", sourcePattern)
	}

	if starWildcardLen > 1 || strings.Count(sourcePattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern '%s' can only be used once", sourcePattern)
	}

	// Create bpfMountRule
	var mountRule varmor.MountContent
	var flags uint32

	if starWildcardLen > 0 {
		if strings.Contains(sourcePattern, "/") {
			return nil, fmt.Errorf("the pattern '%s' with globbing * is not supported", sourcePattern)
		}

		stringList := strings.Split(sourcePattern, "*")

		if len(stringList[0]) > 0 {
			mountRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			mountRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else if strings.Contains(sourcePattern, "**") {
		flags |= GreedyMatch

		stringList := strings.Split(sourcePattern, "**")

		if len(stringList[0]) > 0 {
			mountRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			mountRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else {
		mountRule.Pattern.Prefix = sourcePattern
		flags |= PreciseMatch | PrefixMatch
	}

	if len(mountRule.Pattern.Prefix) >= varmortypes.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of prefix '%s' should be less than the maximum (%d)", mountRule.Pattern.Prefix, varmortypes.MaxFilePathPatternLength)
	}

	if len(mountRule.Pattern.Suffix) >= varmortypes.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of suffix '%s' should be less than the maximum (%d)", mountRule.Pattern.Suffix, varmortypes.MaxFilePathPatternLength)
	}

	mountRule.Pattern.Flags = flags
	mountRule.MountFlags = mountFlags
	mountRule.ReverseMountflags = reverseMountFlags
	mountRule.Fstype = fstype

	return &mountRule, nil
}

func generateHardeningRules(rule string, content *varmor.BpfContent, privileged bool) error {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 1. Blocking escape vectors from privileged container
	// disallow write core_pattern
	case "disallow-write-core-pattern":
		fileContent, err := newBpfPathRule("/proc/sys/kernel/core_pattern", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	// disallow mount securityfs
	case "disallow-mount-securityfs":
		if privileged {
			// By default, the target container is configured to prohibit mounting.
			// We will enforce the rule only if `.spec.policy.enhanceProtect.privileged` is set to true.

			// mount new
			flags := 0xFFFFFFFF &^ unix.MS_REMOUNT &^ unix.MS_BIND &^ unix.MS_SHARED &^
				unix.MS_PRIVATE &^ unix.MS_SLAVE &^ unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ AaMayUmount
			mountContent, err := newBpfMountRule("**", "securityfs", uint32(flags), 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
	// disallow mount procfs
	case "disallow-mount-procfs":
		if privileged {
			// By default, the target container is configured to prohibit mounting.
			// We will enforce the rule only if `.spec.policy.enhanceProtect.privileged` is set to true.

			// mount new
			flags := 0xFFFFFFFF &^ unix.MS_REMOUNT &^ unix.MS_BIND &^ unix.MS_SHARED &^
				unix.MS_PRIVATE &^ unix.MS_SLAVE &^ unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ AaMayUmount
			mountContent, err := newBpfMountRule("**", "proc", uint32(flags), 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
		// bind, rbind, remount, move, umount
		flags := unix.MS_BIND | unix.MS_REC | unix.MS_REMOUNT | unix.MS_MOVE | AaMayUmount
		mountContent, err := newBpfMountRule("/proc**", "none", uint32(flags), 0)
		if err != nil {
			return err
		}
		content.Mounts = append(content.Mounts, *mountContent)
	// disallow write release_agent
	case "disallow-write-release-agent":
		fileContent, err := newBpfPathRule("/sys/fs/cgroup/**/release_agent", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	// disallow mount cgroupfs
	case "disallow-mount-cgroupfs":
		if privileged {
			// By default, the target container is configured to prohibit mounting.
			// We will enforce the rule only if `.spec.policy.enhanceProtect.privileged` is set to true.

			// mount new
			flags := 0xFFFFFFFF &^ unix.MS_REMOUNT &^ unix.MS_BIND &^ unix.MS_SHARED &^
				unix.MS_PRIVATE &^ unix.MS_SLAVE &^ unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ AaMayUmount
			mountContent, err := newBpfMountRule("**", "cgroup", uint32(flags), 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
		// bind, rbind, remount, move, umount
		flags := unix.MS_BIND | unix.MS_REC | unix.MS_REMOUNT | unix.MS_MOVE | AaMayUmount
		mountContent, err := newBpfMountRule("/sys**", "none", uint32(flags), 0)
		if err != nil {
			return err
		}
		content.Mounts = append(content.Mounts, *mountContent)
	// disallow debug disk devices
	case "disallow-debug-disk-device":
		fileContent, err := newBpfPathRule("{{.DiskDevices}}", AaMayRead|AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	// disallow mount disk devices
	case "disallow-mount-disk-device":
		if privileged {
			// By default, the target container is configured to prohibit mounting.
			// We will enforce the rule only if `.spec.policy.enhanceProtect.privileged` is set to true.

			// mount new
			mountContent, err := newBpfMountRule("{{.DiskDevices}}", "*", 0xFFFFFFFF&^AaMayUmount, 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
	// disable mount operations
	case "disallow-mount":
		if privileged {
			// By default, the target container is configured to prohibit mounting.
			// We will enforce the rule only if `.spec.policy.enhanceProtect.privileged` is set to true.

			// mount new
			mountContent, err := newBpfMountRule("**", "*", 0xFFFFFFFF&^AaMayUmount, 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
	// disable umount operations
	case "disallow-umount":
		mountContent, err := newBpfMountRule("**", "none", AaMayUmount, 0)
		if err != nil {
			return err
		}
		content.Mounts = append(content.Mounts, *mountContent)
	// disallow insmond
	case "disallow-insmod":
		content.Capabilities |= 1 << unix.CAP_SYS_MODULE
	// disallow load ebpf program
	case "disallow-load-ebpf":
		content.Capabilities |= (1 << unix.CAP_SYS_ADMIN) | (1 << unix.CAP_BPF)
	// disallow access to the root of the task through procfs
	case "disallow-access-procfs-root":
		if content.Ptrace == nil {
			content.Ptrace = &varmor.PtraceContent{}
		}
		content.Ptrace.Permissions |= AaPtraceRead
		content.Ptrace.Flags |= PreciseMatch
	// disallow access /proc/kallsyms
	case "disallow-access-kallsyms":
		fileContent, err := newBpfPathRule("/proc/kallsyms", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	//// 2. Disable capabilities
	// disable all capabilities
	case "disable-cap-all":
		content.Capabilities = (1 << (unix.CAP_LAST_CAP + 1)) - 1
	// disable privileged capabilities
	case "disable-cap-privileged":
		content.Capabilities |= ((1 << unix.CAP_DAC_READ_SEARCH) |
			(1 << unix.CAP_LINUX_IMMUTABLE) |
			(1 << unix.CAP_NET_BROADCAST) |
			(1 << unix.CAP_NET_ADMIN) |
			(1 << unix.CAP_IPC_LOCK) |
			(1 << unix.CAP_IPC_OWNER) |
			(1 << unix.CAP_SYS_MODULE) |
			(1 << unix.CAP_SYS_RAWIO) |
			(1 << unix.CAP_SYS_PTRACE) |
			(1 << unix.CAP_SYS_PACCT) |
			(1 << unix.CAP_SYS_ADMIN) |
			(1 << unix.CAP_SYS_BOOT) |
			(1 << unix.CAP_SYS_NICE) |
			(1 << unix.CAP_SYS_RESOURCE) |
			(1 << unix.CAP_SYS_TIME) |
			(1 << unix.CAP_SYS_TTY_CONFIG) |
			(1 << unix.CAP_LEASE) |
			(1 << unix.CAP_AUDIT_CONTROL) |
			(1 << unix.CAP_MAC_OVERRIDE) |
			(1 << unix.CAP_MAC_ADMIN) |
			(1 << unix.CAP_SYSLOG) |
			(1 << unix.CAP_WAKE_ALARM) |
			(1 << unix.CAP_BLOCK_SUSPEND) |
			(1 << unix.CAP_AUDIT_READ) |
			(1 << unix.CAP_PERFMON) |
			(1 << unix.CAP_BPF) |
			(1 << unix.CAP_CHECKPOINT_RESTORE))
	// disable the specified capability
	case "disable-cap-chown":
		content.Capabilities |= 1 << unix.CAP_CHOWN
	case "disable-cap-dac-override":
		content.Capabilities |= 1 << unix.CAP_DAC_OVERRIDE
	case "disable-cap-dac-read-search":
		content.Capabilities |= 1 << unix.CAP_DAC_READ_SEARCH
	case "disable-cap-fowner":
		content.Capabilities |= 1 << unix.CAP_FOWNER
	case "disable-cap-fsetid":
		content.Capabilities |= 1 << unix.CAP_FSETID
	case "disable-cap-kill":
		content.Capabilities |= 1 << unix.CAP_KILL
	case "disable-cap-setgid":
		content.Capabilities |= 1 << unix.CAP_SETGID
	case "disable-cap-setuid":
		content.Capabilities |= 1 << unix.CAP_SETUID
	case "disable-cap-setpcap":
		content.Capabilities |= 1 << unix.CAP_SETPCAP
	case "disable-cap-linux-immutable":
		content.Capabilities |= 1 << unix.CAP_LINUX_IMMUTABLE
	case "disable-cap-net-bind-service":
		content.Capabilities |= 1 << unix.CAP_NET_BIND_SERVICE
	case "disable-cap-net-broadcast":
		content.Capabilities |= 1 << unix.CAP_NET_BROADCAST
	case "disable-cap-net-admin":
		content.Capabilities |= 1 << unix.CAP_NET_ADMIN
	case "disable-cap-net-raw":
		content.Capabilities |= 1 << unix.CAP_NET_RAW
	case "disable-cap-ipc-lock":
		content.Capabilities |= 1 << unix.CAP_IPC_LOCK
	case "disable-cap-ipc-owner":
		content.Capabilities |= 1 << unix.CAP_IPC_OWNER
	case "disable-cap-sys-module":
		content.Capabilities |= 1 << unix.CAP_SYS_MODULE
	case "disable-cap-sys-rawio":
		content.Capabilities |= 1 << unix.CAP_SYS_RAWIO
	case "disable-cap-sys-chroot":
		content.Capabilities |= 1 << unix.CAP_SYS_CHROOT
	case "disable-cap-sys-ptrace":
		content.Capabilities |= 1 << unix.CAP_SYS_PTRACE
	case "disable-cap-sys-pacct":
		content.Capabilities |= 1 << unix.CAP_SYS_PACCT
	case "disable-cap-sys-admin":
		content.Capabilities |= 1 << unix.CAP_SYS_ADMIN
	case "disable-cap-sys-boot":
		content.Capabilities |= 1 << unix.CAP_SYS_BOOT
	case "disable-cap-sys-nice":
		content.Capabilities |= 1 << unix.CAP_SYS_NICE
	case "disable-cap-sys-resource":
		content.Capabilities |= 1 << unix.CAP_SYS_RESOURCE
	case "disable-cap-sys-time":
		content.Capabilities |= 1 << unix.CAP_SYS_TIME
	case "disable-cap-sys-tty-config":
		content.Capabilities |= 1 << unix.CAP_SYS_TTY_CONFIG
	case "disable-cap-mknod":
		content.Capabilities |= 1 << unix.CAP_MKNOD
	case "disable-cap-lease":
		content.Capabilities |= 1 << unix.CAP_LEASE
	case "disable-cap-audit-write":
		content.Capabilities |= 1 << unix.CAP_AUDIT_WRITE
	case "disable-cap-audit-control":
		content.Capabilities |= 1 << unix.CAP_AUDIT_CONTROL
	case "disable-cap-setfcap":
		content.Capabilities |= 1 << unix.CAP_SETFCAP
	case "disable-cap-mac-override":
		content.Capabilities |= 1 << unix.CAP_MAC_OVERRIDE
	case "disable-cap-mac-admin":
		content.Capabilities |= 1 << unix.CAP_MAC_ADMIN
	case "disable-cap-syslog":
		content.Capabilities |= 1 << unix.CAP_SYSLOG
	case "disable-cap-wake-alarm":
		content.Capabilities |= 1 << unix.CAP_WAKE_ALARM
	case "disable-cap-block-suspend":
		content.Capabilities |= 1 << unix.CAP_BLOCK_SUSPEND
	case "disable-cap-audit-read":
		content.Capabilities |= 1 << unix.CAP_AUDIT_READ
	case "disable-cap-perfmon":
		content.Capabilities |= 1 << unix.CAP_PERFMON
	case "disable-cap-bpf":
		content.Capabilities |= 1 << unix.CAP_BPF
	case "disable-cap-checkpoint-restore":
		content.Capabilities |= 1 << unix.CAP_CHECKPOINT_RESTORE

	//// 3. Kernel vulnerability mitigation
	// diallow create user namespace
	case "disallow-create-user-ns":
		// TODO: add support for userns_create hook point (Linux v6.1+)
	// diallow abuse user namespace
	case "disallow-abuse-user-ns":
		content.Capabilities |= 1 << unix.CAP_SYS_ADMIN
	}
	return nil
}

func generateVulMitigationRules(rule string, content *varmor.BpfContent) error {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "cgroups-lxcfs-escape-mitigation":
		fileContent, err := newBpfPathRule("/**/release_agent", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("/**/devices.allow", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("/**/cgroup.procs", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("/**/devices/tasks", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "runc-override-mitigation":
		fileContent, err := newBpfPathRule("/**/runc", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	}
	return nil
}

func generateAttackProtectionRules(rule string, content *varmor.BpfContent) error {
	var fileContent *varmor.FileContent
	var networkContent *varmor.NetworkContent
	var err error

	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 4. Mitigate container information leakage
	case "mitigate-sa-leak":
		fileContent, err = newBpfPathRule("/run/secrets/kubernetes.io/serviceaccount/**", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("/var/run/secrets/kubernetes.io/serviceaccount/**", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "mitigate-disk-device-number-leak":
		fileContent, err = newBpfPathRule("/proc/partitions", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("/proc/**/mountinfo", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "mitigate-overlayfs-leak":
		fileContent, err = newBpfPathRule("/proc/**/mounts", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("/proc/**/mountinfo", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "mitigate-host-ip-leak":
		fileContent, err = newBpfPathRule("/proc/**/net/arp", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "disallow-metadata-service":
		// For Aliyun, Volc Engine, etc.
		networkContent, err = newBpfNetworkRule("", "100.96.0.96", 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)

		// For AWS, GCP, Azure, etc.
		networkContent, err = newBpfNetworkRule("", "169.254.169.254", 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disallow-access-k8s-sensitive-files":
		fileContent, err = newBpfPathRule("**/etc/kubernetes", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("**/.kube/config", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule("**/volumes/kubernetes.io~secret", AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	//// 5. Restrict the sensitive operations inside the container
	case "disable-write-etc":
		fileContent, err = newBpfPathRule("/etc/**", AaMayWrite|AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	case "disable-busybox":
		fileContent, err = newBpfPathRule("/**/busybox", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

	case "disable-shell":
		fileContent, err = newBpfPathRule("/**/sh", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

		fileContent, err = newBpfPathRule("/**/bash", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

		fileContent, err = newBpfPathRule("/**/dash", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-wget":
		fileContent, err = newBpfPathRule("/**/wget", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-curl":
		fileContent, err = newBpfPathRule("/**/curl", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-chmod":
		fileContent, err = newBpfPathRule("/**/chmod", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-su-sudo":
		fileContent, err = newBpfPathRule("/**/su", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

		fileContent, err = newBpfPathRule("/**/sudo", AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	}
	return nil
}

func generateRawFileRules(rule varmor.FileRule, bpfContent *varmor.BpfContent) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "read", "r":
			permissions |= AaMayRead
		case "write", "w":
			permissions |= AaMayWrite
			permissions |= AaMayAppend
		case "append", "a":
			permissions |= AaMayAppend
		}
	}

	if permissions == 0 {
		return nil
	}

	fileContent, err := newBpfPathRule(rule.Pattern, permissions)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	return nil
}

func generateRawProcessRules(rule varmor.FileRule, bpfContent *varmor.BpfContent) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "exec", "x":
			permissions |= AaMayExec
		}
	}

	if permissions == 0 {
		return nil
	}

	fileContent, err := newBpfPathRule(rule.Pattern, permissions)
	if err != nil {
		return err
	}
	bpfContent.Processes = append(bpfContent.Processes, *fileContent)

	return nil
}

func generateRawNetworkRules(rule varmor.NetworkEgressRule, bpfContent *varmor.BpfContent) error {
	networkContent, err := newBpfNetworkRule(rule.IPBlock, rule.IP, uint32(rule.Port))
	if err != nil {
		return err
	}
	bpfContent.Networks = append(bpfContent.Networks, *networkContent)

	return nil
}

func generateRawPtraceRule(rule varmor.PtraceRule, bpfContent *varmor.BpfContent) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "trace":
			permissions |= AaPtraceTrace
		case "read":
			permissions |= AaPtraceRead
		case "traceby":
			permissions |= AaMayBeTraced
		case "readby":
			permissions |= AaMayBeRead
		}
	}

	if permissions != 0 {
		if bpfContent.Ptrace == nil {
			bpfContent.Ptrace = &varmor.PtraceContent{}
		}

		bpfContent.Ptrace.Permissions = permissions
		if rule.StrictMode {
			bpfContent.Ptrace.Flags = GreedyMatch
		} else {
			bpfContent.Ptrace.Flags = PreciseMatch
		}
	}

	return nil
}

func generateRawMountRule(rule varmor.MountRule, bpfContent *varmor.BpfContent) error {
	var mountFlags, reverseMountFlags uint32

	for _, flag := range rule.Flags {
		switch strings.ToLower(flag) {
		// All Flags:
		case "all":
			mountFlags = 0xFFFFFFFF
			reverseMountFlags = 0xFFFFFFFF
		// Command Flags
		case "remount":
			mountFlags |= unix.MS_REMOUNT
		case "bind", "B":
			mountFlags |= unix.MS_BIND
		case "move", "M":
			mountFlags |= unix.MS_MOVE
		case "rbind", "R":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
		case "make-unbindable":
			mountFlags |= unix.MS_UNBINDABLE
		case "make-private":
			mountFlags |= unix.MS_PRIVATE
		case "make-slave":
			mountFlags |= unix.MS_SLAVE
		case "make-shared":
			mountFlags |= unix.MS_SHARED
		case "make-runbindable":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_UNBINDABLE
		case "make-rprivate":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_PRIVATE
		case "make-rslave":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_SLAVE
		case "make-rshared":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_SHARED
		// Generic Flags
		case "ro", "r", "read-only":
			mountFlags |= unix.MS_RDONLY
		case "nosuid":
			mountFlags |= unix.MS_NOSUID
		case "nodev":
			mountFlags |= unix.MS_NODEV
		case "noexec":
			mountFlags |= unix.MS_NOEXEC
		case "sync":
			mountFlags |= unix.MS_SYNCHRONOUS
		case "mand":
			mountFlags |= unix.MS_MANDLOCK
		case "dirsync":
			mountFlags |= unix.MS_DIRSYNC
		case "noatime":
			mountFlags |= unix.MS_NOATIME
		case "nodiratime":
			mountFlags |= unix.MS_NODIRATIME
		case "silent":
			mountFlags |= unix.MS_SILENT
		case "relatime":
			mountFlags |= unix.MS_RELATIME
		case "iversion":
			mountFlags |= unix.MS_I_VERSION
		case "strictatime":
			mountFlags |= unix.MS_STRICTATIME
		case "rw", "w":
			reverseMountFlags |= unix.MS_RDONLY
		case "suid":
			reverseMountFlags |= unix.MS_NOSUID
		case "dev":
			reverseMountFlags |= unix.MS_NODEV
		case "exec":
			reverseMountFlags |= unix.MS_NOEXEC
		case "async":
			reverseMountFlags |= unix.MS_SYNCHRONOUS
		case "nomand":
			reverseMountFlags |= unix.MS_MANDLOCK
		case "atime":
			reverseMountFlags |= unix.MS_NOATIME
		case "diratime":
			reverseMountFlags |= unix.MS_NODIRATIME
		case "loud":
			reverseMountFlags |= unix.MS_SILENT
		case "norelatime":
			reverseMountFlags |= unix.MS_RELATIME
		case "noiversion":
			reverseMountFlags |= unix.MS_I_VERSION
		case "nostrictatime":
			reverseMountFlags |= unix.MS_STRICTATIME
		// Custom Flags
		case "umount":
			mountFlags |= AaMayUmount
		}
	}

	mountContent, err := newBpfMountRule(rule.SourcePattern, rule.Fstype, mountFlags, reverseMountFlags)
	if err != nil {
		return err
	}
	bpfContent.Mounts = append(bpfContent.Mounts, *mountContent)

	return nil
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, bpfContent *varmor.BpfContent) error {
	var err error

	// Add default rules for unprivileged containers (securityContext.privileged:true) based on the rules of the RuntimeDefault mode
	if !enhanceProtect.Privileged {
		err = GenerateRuntimeDefaultProfile(bpfContent)
		if err != nil {
			return err
		}
	}

	// Hardening
	for _, rule := range enhanceProtect.HardeningRules {
		err = generateHardeningRules(rule, bpfContent, enhanceProtect.Privileged)
		if err != nil {
			return err
		}
	}

	// Vulnerability Mitigation
	for _, rule := range enhanceProtect.VulMitigationRules {
		err = generateVulMitigationRules(rule, bpfContent)
		if err != nil {
			return err
		}
	}

	// Attack Protection
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				err = generateAttackProtectionRules(rule, bpfContent)
				if err != nil {
					return err
				}
			}
		}
	}

	// Custom
	for _, rule := range enhanceProtect.BpfRawRules.Files {
		err := generateRawFileRules(rule, bpfContent)
		if err != nil {
			return err
		}

		err = generateRawProcessRules(rule, bpfContent)
		if err != nil {
			return err
		}
	}

	for _, rule := range enhanceProtect.BpfRawRules.Processes {
		err := generateRawFileRules(rule, bpfContent)
		if err != nil {
			return err
		}

		err = generateRawProcessRules(rule, bpfContent)
		if err != nil {
			return err
		}
	}

	for _, egressRule := range enhanceProtect.BpfRawRules.Network.Egresses {
		err := generateRawNetworkRules(egressRule, bpfContent)
		if err != nil {
			return err
		}
	}

	if len(enhanceProtect.BpfRawRules.Ptrace.Permissions) != 0 {
		err = generateRawPtraceRule(enhanceProtect.BpfRawRules.Ptrace, bpfContent)
		if err != nil {
			return err
		}
	}

	if enhanceProtect.Privileged {
		for _, rule := range enhanceProtect.BpfRawRules.Mounts {
			err := generateRawMountRule(rule, bpfContent)
			if err != nil {
				return err
			}
		}
	}

	if len(bpfContent.Files) > varmortypes.MaxBpfFileRuleCount {
		return fmt.Errorf("the maximum number of BPF file rules exceeded(Max Count: %d)", varmortypes.MaxBpfFileRuleCount)
	}

	if len(bpfContent.Processes) > varmortypes.MaxBpfBprmRuleCount {
		return fmt.Errorf("the maximum number of BPF bprm rules exceeded(Max Count: %d)", varmortypes.MaxBpfBprmRuleCount)
	}

	if len(bpfContent.Networks) > varmortypes.MaxBpfNetworkRuleCount {
		return fmt.Errorf("the maximum number of BPF network rules exceeded(Max Count: %d)", varmortypes.MaxBpfNetworkRuleCount)
	}

	if len(bpfContent.Mounts) > varmortypes.MaxBpfMountRuleCount {
		return fmt.Errorf("the maximum number of BPF mount rules exceeded(Max Count: %d)", varmortypes.MaxBpfMountRuleCount)
	}

	return nil
}
