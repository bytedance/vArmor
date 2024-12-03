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
	"strings"

	"golang.org/x/sys/unix"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func GenerateRuntimeDefaultProfile(bpfContent *varmor.BpfContent, mode uint32) error {
	var err error

	fileContent, err := newBpfPathRule(mode, "/proc/sysrq-trigger", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule(mode, "/proc/**/mem", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule(mode, "/proc/kmem", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule(mode, "/proc/kcore", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule(mode, "/sys/firmware/**", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule(mode, "/sys/devices/virtual/powercap/**", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	fileContent, err = newBpfPathRule(mode, "/sys/kernel/security/**", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	mountContent, err := newBpfMountRule(mode, "**", "*", 0xFFFFFFFF&^bpfenforcer.AaMayUmount, 0xFFFFFFFF)
	if err != nil {
		return err
	}
	bpfContent.Mounts = append(bpfContent.Mounts, *mountContent)

	setBpfPtraceRule(bpfContent, mode, bpfenforcer.AaPtraceTrace|bpfenforcer.AaPtraceRead, bpfenforcer.PreciseMatch)

	return nil
}

func generateHardeningRules(content *varmor.BpfContent, mode uint32, privileged bool, rule string) error {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 1. Blocking escape vectors from privileged container
	// disallow write core_pattern
	case "disallow-write-core-pattern":
		fileContent, err := newBpfPathRule(mode, "/proc/sys/kernel/core_pattern", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
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
				unix.MS_PRIVATE &^ unix.MS_SLAVE &^ unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ bpfenforcer.AaMayUmount
			mountContent, err := newBpfMountRule(mode, "**", "securityfs", uint32(flags), 0xFFFFFFFF)
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
				unix.MS_PRIVATE &^ unix.MS_SLAVE &^ unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ bpfenforcer.AaMayUmount
			mountContent, err := newBpfMountRule(mode, "**", "proc", uint32(flags), 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
		// bind, rbind, remount, move, umount
		flags := unix.MS_BIND | unix.MS_REC | unix.MS_REMOUNT | unix.MS_MOVE | bpfenforcer.AaMayUmount
		mountContent, err := newBpfMountRule(mode, "/proc**", "none", uint32(flags), 0)
		if err != nil {
			return err
		}
		content.Mounts = append(content.Mounts, *mountContent)
	// disallow write release_agent
	case "disallow-write-release-agent":
		fileContent, err := newBpfPathRule(mode, "/sys/fs/cgroup/**/release_agent", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
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
				unix.MS_PRIVATE &^ unix.MS_SLAVE &^ unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ bpfenforcer.AaMayUmount
			mountContent, err := newBpfMountRule(mode, "**", "cgroup", uint32(flags), 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
		// bind, rbind, remount, move, umount
		flags := unix.MS_BIND | unix.MS_REC | unix.MS_REMOUNT | unix.MS_MOVE | bpfenforcer.AaMayUmount
		mountContent, err := newBpfMountRule(mode, "/sys**", "none", uint32(flags), 0)
		if err != nil {
			return err
		}
		content.Mounts = append(content.Mounts, *mountContent)
	// disallow debug disk devices
	case "disallow-debug-disk-device":
		fileContent, err := newBpfPathRule(mode, "{{.DiskDevices}}", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
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
			mountContent, err := newBpfMountRule(mode, "{{.DiskDevices}}", "*", 0xFFFFFFFF&^bpfenforcer.AaMayUmount, 0xFFFFFFFF)
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
			mountContent, err := newBpfMountRule(mode, "**", "*", 0xFFFFFFFF&^bpfenforcer.AaMayUmount, 0xFFFFFFFF)
			if err != nil {
				return err
			}
			content.Mounts = append(content.Mounts, *mountContent)
		}
	// disable umount operations
	case "disallow-umount":
		mountContent, err := newBpfMountRule(mode, "**", "none", bpfenforcer.AaMayUmount, 0)
		if err != nil {
			return err
		}
		content.Mounts = append(content.Mounts, *mountContent)
	// disallow insmond
	case "disallow-insmod":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_MODULE)
	// disallow load ebpf program
	case "disallow-load-ebpf":
		setBpfCapabilityRule(content, mode, (1<<unix.CAP_SYS_ADMIN)|(1<<unix.CAP_BPF))
	// disallow access to the root of the task through procfs
	case "disallow-access-procfs-root":
		setBpfPtraceRule(content, mode, bpfenforcer.AaPtraceRead, bpfenforcer.PreciseMatch)
	// disallow access /proc/kallsyms
	case "disallow-access-kallsyms":
		fileContent, err := newBpfPathRule(mode, "/proc/kallsyms", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	//// 2. Disable capabilities
	// disable all capabilities
	case "disable-cap-all":
		setBpfCapabilityRule(content, mode, (1<<(unix.CAP_LAST_CAP+1))-1)
	// disable all capabilities except for net_bind_service
	case "disable-cap-all-except-net-bind-service":
		setBpfCapabilityRule(content, mode, ((1<<(unix.CAP_LAST_CAP+1))-1)-(1<<unix.CAP_NET_BIND_SERVICE))
	// disable privileged capabilities
	case "disable-cap-privileged":
		setBpfCapabilityRule(content, mode, (1<<unix.CAP_DAC_READ_SEARCH)|
			(1<<unix.CAP_LINUX_IMMUTABLE)|
			(1<<unix.CAP_NET_BROADCAST)|
			(1<<unix.CAP_NET_ADMIN)|
			(1<<unix.CAP_IPC_LOCK)|
			(1<<unix.CAP_IPC_OWNER)|
			(1<<unix.CAP_SYS_MODULE)|
			(1<<unix.CAP_SYS_RAWIO)|
			(1<<unix.CAP_SYS_PTRACE)|
			(1<<unix.CAP_SYS_PACCT)|
			(1<<unix.CAP_SYS_ADMIN)|
			(1<<unix.CAP_SYS_BOOT)|
			(1<<unix.CAP_SYS_NICE)|
			(1<<unix.CAP_SYS_RESOURCE)|
			(1<<unix.CAP_SYS_TIME)|
			(1<<unix.CAP_SYS_TTY_CONFIG)|
			(1<<unix.CAP_LEASE)|
			(1<<unix.CAP_AUDIT_CONTROL)|
			(1<<unix.CAP_MAC_OVERRIDE)|
			(1<<unix.CAP_MAC_ADMIN)|
			(1<<unix.CAP_SYSLOG)|
			(1<<unix.CAP_WAKE_ALARM)|
			(1<<unix.CAP_BLOCK_SUSPEND)|
			(1<<unix.CAP_AUDIT_READ)|
			(1<<unix.CAP_PERFMON)|
			(1<<unix.CAP_BPF)|
			(1<<unix.CAP_CHECKPOINT_RESTORE))
	// disable the specified capability
	case "disable-cap-chown":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_CHOWN)
	case "disable-cap-dac-override":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_DAC_OVERRIDE)
	case "disable-cap-dac-read-search":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_DAC_READ_SEARCH)
	case "disable-cap-fowner":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_FOWNER)
	case "disable-cap-fsetid":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_FSETID)
	case "disable-cap-kill":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_KILL)
	case "disable-cap-setgid":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SETGID)
	case "disable-cap-setuid":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SETUID)
	case "disable-cap-setpcap":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SETPCAP)
	case "disable-cap-linux-immutable":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_LINUX_IMMUTABLE)
	case "disable-cap-net-bind-service":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_NET_BIND_SERVICE)
	case "disable-cap-net-broadcast":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_NET_BROADCAST)
	case "disable-cap-net-admin":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_NET_ADMIN)
	case "disable-cap-net-raw":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_NET_RAW)
	case "disable-cap-ipc-lock":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_IPC_LOCK)
	case "disable-cap-ipc-owner":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_IPC_OWNER)
	case "disable-cap-sys-module":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_MODULE)
	case "disable-cap-sys-rawio":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_RAWIO)
	case "disable-cap-sys-chroot":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_CHROOT)
	case "disable-cap-sys-ptrace":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_PTRACE)
	case "disable-cap-sys-pacct":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_PACCT)
	case "disable-cap-sys-admin":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_ADMIN)
	case "disable-cap-sys-boot":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_BOOT)
	case "disable-cap-sys-nice":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_NICE)
	case "disable-cap-sys-resource":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_RESOURCE)
	case "disable-cap-sys-time":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_TIME)
	case "disable-cap-sys-tty-config":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_TTY_CONFIG)
	case "disable-cap-mknod":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_MKNOD)
	case "disable-cap-lease":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_LEASE)
	case "disable-cap-audit-write":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_AUDIT_WRITE)
	case "disable-cap-audit-control":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_AUDIT_CONTROL)
	case "disable-cap-setfcap":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SETFCAP)
	case "disable-cap-mac-override":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_MAC_OVERRIDE)
	case "disable-cap-mac-admin":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_MAC_ADMIN)
	case "disable-cap-syslog":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYSLOG)
	case "disable-cap-wake-alarm":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_WAKE_ALARM)
	case "disable-cap-block-suspend":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_BLOCK_SUSPEND)
	case "disable-cap-audit-read":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_AUDIT_READ)
	case "disable-cap-perfmon":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_PERFMON)
	case "disable-cap-bpf":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_BPF)
	case "disable-cap-checkpoint-restore":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_CHECKPOINT_RESTORE)

	//// 3. Kernel vulnerability mitigation
	// diallow create user namespace
	case "disallow-create-user-ns":
		// TODO: add support for userns_create hook point (Linux v6.1+)
	// diallow abuse user namespace
	case "disallow-abuse-user-ns":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_ADMIN)
	}
	return nil
}

func generateVulMitigationRules(content *varmor.BpfContent, mode uint32, rule string) error {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "cgroups-lxcfs-escape-mitigation":
		fileContent, err := newBpfPathRule(mode, "/**/release_agent", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/devices.allow", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/cgroup.procs", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/devices/tasks", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "runc-override-mitigation":
		fileContent, err := newBpfPathRule(mode, "/**/runc", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	}
	return nil
}

func generateAttackProtectionRules(content *varmor.BpfContent, mode uint32, rule string) error {
	var fileContent *varmor.FileContent
	var networkContent *varmor.NetworkContent
	var err error

	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 4. Mitigate container information leakage
	case "mitigate-sa-leak":
		fileContent, err = newBpfPathRule(mode, "/run/secrets/kubernetes.io/serviceaccount/**", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/var/run/secrets/kubernetes.io/serviceaccount/**", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "mitigate-disk-device-number-leak":
		fileContent, err = newBpfPathRule(mode, "/proc/partitions", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/proc/**/mountinfo", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "mitigate-overlayfs-leak":
		fileContent, err = newBpfPathRule(mode, "/proc/**/mounts", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/proc/**/mountinfo", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "mitigate-host-ip-leak":
		fileContent, err = newBpfPathRule(mode, "/proc/**/net/arp", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	case "disallow-metadata-service":
		// For Aliyun, Volc Engine, etc.
		networkContent, err = newBpfNetworkConnectRule(mode, "", "100.96.0.96", 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)

		// For AWS, GCP, Azure, etc.
		networkContent, err = newBpfNetworkConnectRule(mode, "", "169.254.169.254", 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disallow-access-k8s-sensitive-files":
		fileContent, err = newBpfPathRule(mode, "**/etc/kubernetes", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "**/.kube/config", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "**/volumes/kubernetes.io~secret", bpfenforcer.AaMayRead)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	//// 5. Restrict the sensitive operations inside the container
	case "disable-write-etc":
		fileContent, err = newBpfPathRule(mode, "/etc/**", bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

	case "disable-busybox":
		fileContent, err = newBpfPathRule(mode, "/**/busybox", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

	case "disable-shell":
		fileContent, err = newBpfPathRule(mode, "/**/sh", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/bash", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/dash", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-wget":
		fileContent, err = newBpfPathRule(mode, "/**/wget", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-curl":
		fileContent, err = newBpfPathRule(mode, "/**/curl", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-chmod":
		fileContent, err = newBpfPathRule(mode, "/**/chmod", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	case "disable-su-sudo":
		fileContent, err = newBpfPathRule(mode, "/**/su", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/sudo", bpfenforcer.AaMayExec)
		if err != nil {
			return err
		}
		content.Processes = append(content.Processes, *fileContent)
	//// 6. Others
	case "disable-network":
		networkContent, err = newBpfNetworkCreateRule(mode, 1<<unix.AF_MAX-1, 0, 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disable-ipv4", "disable-inet":
		networkContent, err = newBpfNetworkCreateRule(mode, 1<<unix.AF_INET, 0, 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disable-ipv6", "disable-inet6":
		networkContent, err = newBpfNetworkCreateRule(mode, 1<<unix.AF_INET6, 0, 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disable-unix-domain-socket":
		networkContent, err = newBpfNetworkCreateRule(mode, 1<<unix.AF_UNIX, 0, 0)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disable-icmp":
		networkContent, err = newBpfNetworkCreateRule(mode, 0, 0, 1<<unix.IPPROTO_ICMP|1<<unix.IPPROTO_ICMPV6)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disable-tcp":
		networkContent, err = newBpfNetworkCreateRule(mode, 0, 0, 1<<unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "disable-udp":
		networkContent, err = newBpfNetworkCreateRule(mode, 0, 0, 1<<unix.IPPROTO_UDP)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	}
	return nil
}

func generateRawFileRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.FileRule) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "all", "*":
			permissions |= bpfenforcer.AaMayRead | bpfenforcer.AaMayWrite | bpfenforcer.AaMayAppend
		case "read", "r":
			permissions |= bpfenforcer.AaMayRead
		case "write", "w":
			permissions |= bpfenforcer.AaMayWrite
			permissions |= bpfenforcer.AaMayAppend
		case "append", "a":
			permissions |= bpfenforcer.AaMayAppend
		}
	}

	if permissions == 0 {
		return nil
	}

	fileContent, err := newBpfPathRule(mode, rule.Pattern, permissions)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	return nil
}

func generateRawProcessRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.FileRule) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "all", "*":
			permissions |= bpfenforcer.AaMayExec
		case "exec", "x":
			permissions |= bpfenforcer.AaMayExec
		}
	}

	if permissions == 0 {
		return nil
	}

	fileContent, err := newBpfPathRule(mode, rule.Pattern, permissions)
	if err != nil {
		return err
	}
	bpfContent.Processes = append(bpfContent.Processes, *fileContent)

	return nil
}

func generateRawNetworkSocketRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.NetworkSocketRule) error {
	var domains, types, protocols uint64

	for _, domain := range rule.Domains {
		switch strings.ToLower(domain) {
		case "all", "*":
			domains = 1<<unix.AF_UNIX | 1<<unix.AF_INET | 1<<unix.AF_AX25 | 1<<unix.AF_IPX |
				1<<unix.AF_APPLETALK | 1<<unix.AF_NETROM | 1<<unix.AF_BRIDGE | 1<<unix.AF_ATMPVC |
				1<<unix.AF_X25 | 1<<unix.AF_INET6 | 1<<unix.AF_ROSE | 1<<unix.AF_NETBEUI |
				1<<unix.AF_SECURITY | 1<<unix.AF_KEY | 1<<unix.AF_NETLINK | 1<<unix.AF_PACKET |
				1<<unix.AF_ASH | 1<<unix.AF_ECONET | 1<<unix.AF_ATMSVC | 1<<unix.AF_RDS |
				1<<unix.AF_SNA | 1<<unix.AF_IRDA | 1<<unix.AF_PPPOX | 1<<unix.AF_WANPIPE |
				1<<unix.AF_LLC | 1<<unix.AF_IB | 1<<unix.AF_MPLS | 1<<unix.AF_CAN |
				1<<unix.AF_TIPC | 1<<unix.AF_BLUETOOTH | 1<<unix.AF_IUCV | 1<<unix.AF_RXRPC |
				1<<unix.AF_ISDN | 1<<unix.AF_PHONET | 1<<unix.AF_IEEE802154 | 1<<unix.AF_CAIF |
				1<<unix.AF_ALG | 1<<unix.AF_NFC | 1<<unix.AF_VSOCK | 1<<unix.AF_KCM |
				1<<unix.AF_QIPCRTR | 1<<unix.AF_SMC | 1<<unix.AF_XDP | 1<<unix.AF_MCTP
		case "unix":
			domains |= 1 << unix.AF_UNIX
		case "inet":
			domains |= 1 << unix.AF_INET
		case "ax25":
			domains |= 1 << unix.AF_AX25
		case "ipx":
			domains |= 1 << unix.AF_IPX
		case "appletalk":
			domains |= 1 << unix.AF_APPLETALK
		case "netrom":
			domains |= 1 << unix.AF_NETROM
		case "bridge":
			domains |= 1 << unix.AF_BRIDGE
		case "atmpvc":
			domains |= 1 << unix.AF_ATMPVC
		case "x25":
			domains |= 1 << unix.AF_X25
		case "inet6":
			domains |= 1 << unix.AF_INET6
		case "rose":
			domains |= 1 << unix.AF_ROSE
		case "netbeui":
			domains |= 1 << unix.AF_NETBEUI
		case "security":
			domains |= 1 << unix.AF_SECURITY
		case "key":
			domains |= 1 << unix.AF_KEY
		case "netlink":
			domains |= 1 << unix.AF_NETLINK
		case "packet":
			domains |= 1 << unix.AF_PACKET
		case "ash":
			domains |= 1 << unix.AF_ASH
		case "econet":
			domains |= 1 << unix.AF_ECONET
		case "atmsvc":
			domains |= 1 << unix.AF_ATMSVC
		case "rds":
			domains |= 1 << unix.AF_RDS
		case "sna":
			domains |= 1 << unix.AF_SNA
		case "irda":
			domains |= 1 << unix.AF_IRDA
		case "pppox":
			domains |= 1 << unix.AF_PPPOX
		case "wanpipe":
			domains |= 1 << unix.AF_WANPIPE
		case "llc":
			domains |= 1 << unix.AF_LLC
		case "ib":
			domains |= 1 << unix.AF_IB
		case "mpls":
			domains |= 1 << unix.AF_MPLS
		case "can":
			domains |= 1 << unix.AF_CAN
		case "tipc":
			domains |= 1 << unix.AF_TIPC
		case "bluetooth":
			domains |= 1 << unix.AF_BLUETOOTH
		case "iucv":
			domains |= 1 << unix.AF_IUCV
		case "rxrpc":
			domains |= 1 << unix.AF_RXRPC
		case "isdn":
			domains |= 1 << unix.AF_ISDN
		case "phonet":
			domains |= 1 << unix.AF_PHONET
		case "ieee802154":
			domains |= 1 << unix.AF_IEEE802154
		case "caif":
			domains |= 1 << unix.AF_CAIF
		case "alg":
			domains |= 1 << unix.AF_ALG
		case "nfc":
			domains |= 1 << unix.AF_NFC
		case "vsock":
			domains |= 1 << unix.AF_VSOCK
		case "kcm":
			domains |= 1 << unix.AF_KCM
		case "qipcrtr":
			domains |= 1 << unix.AF_QIPCRTR
		case "smc":
			domains |= 1 << unix.AF_SMC
		case "xdp":
			domains |= 1 << unix.AF_XDP
		case "mctp":
			domains |= 1 << unix.AF_MCTP
		default:
			return fmt.Errorf("policy contains an illegal NetworkSocketRule rule, found unknown or unsupported socket domain (%s)", domain)
		}
	}

	for _, t := range rule.Types {
		switch strings.ToLower(t) {
		case "all", "*":
			types = 1<<unix.SOCK_STREAM | 1<<unix.SOCK_DGRAM | 1<<unix.SOCK_RAW |
				1<<unix.SOCK_RDM | 1<<unix.SOCK_SEQPACKET | 1<<unix.SOCK_DCCP | 1<<unix.SOCK_PACKET
		case "stream":
			types |= 1 << unix.SOCK_STREAM
		case "dgram":
			types |= 1 << unix.SOCK_DGRAM
		case "raw":
			types |= 1 << unix.SOCK_RAW
		case "rdm":
			types |= 1 << unix.SOCK_RDM
		case "seqpacket":
			types |= 1 << unix.SOCK_SEQPACKET
		case "dccp":
			types |= 1 << unix.SOCK_DCCP
		case "packet":
			types |= 1 << unix.SOCK_PACKET
		default:
			return fmt.Errorf("policy contains an illegal NetworkSocketRule rule, found unknown or unsupported socket type (%s)", t)
		}
	}

	for _, protocol := range rule.Protocols {
		switch strings.ToLower(protocol) {
		case "all", "*":
			protocols = 1<<unix.IPPROTO_ICMP | 1<<unix.IPPROTO_ICMPV6 | 1<<unix.IPPROTO_TCP | 1<<unix.IPPROTO_UDP
		case "icmp":
			protocols |= 1<<unix.IPPROTO_ICMP | 1<<unix.IPPROTO_ICMPV6
		case "tcp":
			protocols |= 1 << unix.IPPROTO_TCP
		case "udp":
			protocols |= 1 << unix.IPPROTO_UDP
		default:
			return fmt.Errorf("policy contains an illegal NetworkSocketRule rule, found unknown or unsupported socket protocol (%s)", protocol)
		}
	}

	networkContent, err := newBpfNetworkCreateRule(mode, domains, types, protocols)
	if err != nil {
		return err
	}
	bpfContent.Networks = append(bpfContent.Networks, *networkContent)

	return nil
}

func generateRawNetworkEgressRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.NetworkEgressRule) error {
	networkContent, err := newBpfNetworkConnectRule(mode, rule.IPBlock, rule.IP, uint32(rule.Port))
	if err != nil {
		return err
	}
	bpfContent.Networks = append(bpfContent.Networks, *networkContent)

	return nil
}

func generateRawPtraceRule(bpfContent *varmor.BpfContent, mode uint32, rule *varmor.PtraceRule) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "all", "*":
			permissions |= bpfenforcer.AaPtraceTrace | bpfenforcer.AaPtraceRead | bpfenforcer.AaMayBeTraced | bpfenforcer.AaMayBeRead
		case "trace":
			permissions |= bpfenforcer.AaPtraceTrace
		case "read":
			permissions |= bpfenforcer.AaPtraceRead
		case "traceby":
			permissions |= bpfenforcer.AaMayBeTraced
		case "readby":
			permissions |= bpfenforcer.AaMayBeRead
		}
	}

	if permissions != 0 {
		if rule.StrictMode {
			setBpfPtraceRule(bpfContent, mode, permissions, bpfenforcer.GreedyMatch)
		} else {
			setBpfPtraceRule(bpfContent, mode, permissions, bpfenforcer.PreciseMatch)
		}
	}

	return nil
}

func generateRawMountRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.MountRule) error {
	var mountFlags, reverseMountFlags uint32

	for _, flag := range rule.Flags {
		switch strings.ToLower(flag) {
		// All Flags:
		case "all", "*":
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
			mountFlags |= bpfenforcer.AaMayUmount
		}
	}

	mountContent, err := newBpfMountRule(mode, rule.SourcePattern, rule.Fstype, mountFlags, reverseMountFlags)
	if err != nil {
		return err
	}
	bpfContent.Mounts = append(bpfContent.Mounts, *mountContent)

	return nil
}

func generateCustomRules(enhanceProtect *varmor.EnhanceProtect, bpfContent *varmor.BpfContent, mode uint32) error {
	for _, rule := range enhanceProtect.BpfRawRules.Files {
		err := generateRawFileRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}

		err = generateRawProcessRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}
	}

	for _, rule := range enhanceProtect.BpfRawRules.Processes {
		err := generateRawFileRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}

		err = generateRawProcessRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}
	}

	if enhanceProtect.BpfRawRules.Network != nil {
		for _, socketRule := range enhanceProtect.BpfRawRules.Network.Sockets {
			err := generateRawNetworkSocketRule(bpfContent, mode, socketRule)
			if err != nil {
				return err
			}
		}
		for _, egressRule := range enhanceProtect.BpfRawRules.Network.Egresses {
			err := generateRawNetworkEgressRule(bpfContent, mode, egressRule)
			if err != nil {
				return err
			}
		}
	}

	if enhanceProtect.BpfRawRules.Ptrace != nil {
		err := generateRawPtraceRule(bpfContent, mode, enhanceProtect.BpfRawRules.Ptrace)
		if err != nil {
			return err
		}
	}

	if enhanceProtect.Privileged {
		for _, rule := range enhanceProtect.BpfRawRules.Mounts {
			err := generateRawMountRule(bpfContent, mode, rule)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, bpfContent *varmor.BpfContent) error {
	var err error
	var mode uint32

	if enhanceProtect.AuditViolations {
		mode = bpfenforcer.AuditMode
	} else {
		mode = bpfenforcer.EnforceMode
	}

	// Add default rules for unprivileged containers (securityContext.privileged:true) based on the rules of the RuntimeDefault mode
	if !enhanceProtect.Privileged {
		err = GenerateRuntimeDefaultProfile(bpfContent, mode)
		if err != nil {
			return err
		}
	}

	// Hardening
	for _, rule := range enhanceProtect.HardeningRules {
		err = generateHardeningRules(bpfContent, mode, enhanceProtect.Privileged, rule)
		if err != nil {
			return err
		}
	}

	// Vulnerability Mitigation
	for _, rule := range enhanceProtect.VulMitigationRules {
		err = generateVulMitigationRules(bpfContent, mode, rule)
		if err != nil {
			return err
		}
	}

	// Attack Protection
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				err = generateAttackProtectionRules(bpfContent, mode, rule)
				if err != nil {
					return err
				}
			}
		}
	}

	// Custom
	if enhanceProtect.BpfRawRules != nil {
		err := generateCustomRules(enhanceProtect, bpfContent, mode)
		if err != nil {
			return err
		}
	}

	if len(bpfContent.Files) > bpfenforcer.MaxBpfFileRuleCount {
		return fmt.Errorf("the maximum number of BPF file rules exceeded(Max Count: %d)", bpfenforcer.MaxBpfFileRuleCount)
	}

	if len(bpfContent.Processes) > bpfenforcer.MaxBpfBprmRuleCount {
		return fmt.Errorf("the maximum number of BPF bprm rules exceeded(Max Count: %d)", bpfenforcer.MaxBpfBprmRuleCount)
	}

	if len(bpfContent.Networks) > bpfenforcer.MaxBpfNetworkRuleCount {
		return fmt.Errorf("the maximum number of BPF network rules exceeded(Max Count: %d)", bpfenforcer.MaxBpfNetworkRuleCount)
	}

	if len(bpfContent.Mounts) > bpfenforcer.MaxBpfMountRuleCount {
		return fmt.Errorf("the maximum number of BPF mount rules exceeded(Max Count: %d)", bpfenforcer.MaxBpfMountRuleCount)
	}

	return nil
}
