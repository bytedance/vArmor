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

// Package bpf generates the BPF profile
package bpf

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/client-go/kubernetes"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
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

func modeToQualifiers(mode uint32) []string {
	var qualifiers []string
	if mode&bpfenforcer.AuditMode != 0 {
		qualifiers = append(qualifiers, "audit")
	}
	if mode&bpfenforcer.DenyMode != 0 {
		qualifiers = append(qualifiers, "deny")
	}
	return qualifiers
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
	// disallow loading ebpf programs, except for those of the BPF_PROG_TYPE_SOCKET_FILTER and BPF_PROG_TYPE_CGROUP_SKB types
	case "disallow-load-bpf-prog", "disallow-load-ebpf":
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
		// TODO: add support for userns_create hook point (Since Linux v6.1)
	// diallow abuse user namespace
	case "disallow-abuse-user-ns":
		setBpfCapabilityRule(content, mode, 1<<unix.CAP_SYS_ADMIN)
	case "disallow-load-all-bpf-prog":
		// TODO: add support for bpf hook point (Since Linux v4.15)
	case "disallow-load-bpf-via-setsockopt":
		// TODO: add support for setsockopt hook point security_socket_setsockopt
	}
	return nil
}

func generateVulMitigationRules(
	kubeClient *kubernetes.Clientset,
	content *varmor.BpfContent,
	mode uint32,
	rule string,
	enableServiceEgressControl bool,
	enablePodEgressControl bool,
	egressInfo *varmortypes.EgressInfo) error {

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
	case "ingress-nightmare-mitigation":
		if enableServiceEgressControl {
			service, err := generateRawNetworkEgressRuleForServices(kubeClient, content, varmor.Service{
				Qualifiers: modeToQualifiers(mode),
				Namespace:  "ingress-nginx",
				Name:       "ingress-nginx-controller-admission",
			})
			if err != nil {
				return fmt.Errorf("failed to generate network egress rule for blocking access to the ingress-nginx/ingress-nginx-controller-admission service. error: %w", err)
			}
			if service != nil {
				egressInfo.ToServices = append(egressInfo.ToServices, *service)
			}
			service, err = generateRawNetworkEgressRuleForServices(kubeClient, content, varmor.Service{
				Qualifiers: modeToQualifiers(mode),
				Namespace:  "kube-system",
				Name:       "ingress-nginx-controller-admission",
			})
			if err != nil {
				return fmt.Errorf("failed to generate network egress rule for blocking access to the kube-system/ingress-nginx-controller-admission service. error: %w", err)
			}
			if service != nil {
				egressInfo.ToServices = append(egressInfo.ToServices, *service)
			}
		}
	}
	return nil
}

func generateAttackProtectionRules(
	kubeClient *kubernetes.Clientset,
	content *varmor.BpfContent,
	mode uint32,
	rule string,
	enableServiceEgressControl bool,
	enablePodEgressControl bool,
	egressInfo *varmortypes.EgressInfo) error {

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
	case "block-access-to-metadata-service", "disallow-metadata-service":
		// AWS, GCP, Azure, OpenStack, etc.
		networkContent, err = newBpfNetworkConnectRule(mode, "", "169.254.169.254", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)

		// AWS IPv6-only EC2 instance
		networkContent, err = newBpfNetworkConnectRule(mode, "", "fd00:ec2::254", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)

		// Volc Engine, BytePlus (backward compatibility)
		networkContent, err = newBpfNetworkConnectRule(mode, "", "100.96.0.96", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "block-access-to-volc-metadata-service":
		// Volc Engine, BytePlus
		networkContent, err = newBpfNetworkConnectRule(mode, "", "100.96.0.96", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "block-access-to-alibaba-metadata-service":
		// Alibaba Cloud
		networkContent, err = newBpfNetworkConnectRule(mode, "", "100.100.100.200", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "block-access-to-aws-metadata-service":
		// AWS, GCP, Azure, OpenStack, etc.
		networkContent, err = newBpfNetworkConnectRule(mode, "", "169.254.169.254", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)

		// AWS IPv6-only EC2 instance
		networkContent, err = newBpfNetworkConnectRule(mode, "", "fd00:ec2::254", 0, 0, nil)
		if err != nil {
			return err
		}
		content.Networks = append(content.Networks, *networkContent)
	case "block-access-to-oci-metadata-service":
		// Oracle Cloud Infrastructure
		networkContent, err = newBpfNetworkConnectRule(mode, "", "192.0.0.192", 0, 0, nil)
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
	case "block-access-to-kube-apiserver":
		if enableServiceEgressControl {
			service, err := generateRawNetworkEgressRuleForServices(kubeClient, content, varmor.Service{
				Qualifiers: modeToQualifiers(mode),
				Namespace:  "default",
				Name:       "kubernetes",
			})
			if err != nil {
				return fmt.Errorf("failed to generate network egress rule for blocking access to the kube-apiserver. error: %w", err)
			}
			if service != nil {
				egressInfo.ToServices = append(egressInfo.ToServices, *service)
			}
		}
	case "block-access-to-container-runtime":
		fileContent, err = newBpfPathRule(mode, "/**/containerd.sock", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/docker.sock", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)

		fileContent, err = newBpfPathRule(mode, "/**/crio.sock", bpfenforcer.AaMayRead|bpfenforcer.AaMayWrite|bpfenforcer.AaMayAppend)
		if err != nil {
			return err
		}
		content.Files = append(content.Files, *fileContent)
	}
	return nil
}

func GenerateEnhanceProtectProfile(
	kubeClient *kubernetes.Clientset,
	enhanceProtect *varmor.EnhanceProtect,
	bpfContent *varmor.BpfContent,
	enableServiceEgressControl bool,
	enablePodEgressControl bool,
	egressInfo *varmortypes.EgressInfo) error {

	var err error
	var mode uint32

	if enhanceProtect.AuditViolations {
		mode |= bpfenforcer.AuditMode
	}

	if !enhanceProtect.AllowViolations {
		mode |= bpfenforcer.DenyMode
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
		err = generateVulMitigationRules(kubeClient, bpfContent, mode, rule, enableServiceEgressControl, enablePodEgressControl, egressInfo)
		if err != nil {
			return err
		}
	}

	// Attack Protection
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				err = generateAttackProtectionRules(kubeClient, bpfContent, mode, rule, enableServiceEgressControl, enablePodEgressControl, egressInfo)
				if err != nil {
					return err
				}
			}
		}
	}

	// Custom
	if enhanceProtect.BpfRawRules != nil {
		err = generateCustomRules(kubeClient, enhanceProtect, bpfContent, enableServiceEgressControl, enablePodEgressControl, egressInfo)
		if err != nil {
			return err
		}
	}

	if len(bpfContent.Files) > bpfenforcer.MaxBpfFileRuleCount {
		return fmt.Errorf("the maximum number of BPF file rules exceeded (max: %d, expected: %d)",
			bpfenforcer.MaxBpfFileRuleCount, len(bpfContent.Files))
	}

	if len(bpfContent.Processes) > bpfenforcer.MaxBpfBprmRuleCount {
		return fmt.Errorf("the maximum number of BPF bprm rules exceeded (max: %d, expected: %d)",
			bpfenforcer.MaxBpfBprmRuleCount, len(bpfContent.Processes))
	}

	if len(bpfContent.Networks) > bpfenforcer.MaxBpfNetworkRuleCount {
		return fmt.Errorf("the maximum number of BPF network rules exceeded (max: %d, expected: %d)",
			bpfenforcer.MaxBpfNetworkRuleCount, len(bpfContent.Networks))
	}

	if len(bpfContent.Mounts) > bpfenforcer.MaxBpfMountRuleCount {
		return fmt.Errorf("the maximum number of BPF mount rules exceeded (max: %d, expected: %d)",
			bpfenforcer.MaxBpfMountRuleCount, len(bpfContent.Mounts))
	}

	return nil
}
