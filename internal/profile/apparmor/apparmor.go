// Copyright 2021-2023 vArmor Authors
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

package apparmor

import (
	"encoding/base64"
	"fmt"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func GenerateAlwaysAllowProfile(profileName string) string {
	c := []byte(fmt.Sprintf(alwaysAllowTemplate, profileName, ""))
	return base64.StdEncoding.EncodeToString(c)
}

func GenerateRuntimeDefaultProfile(profileName string) string {
	c := []byte(fmt.Sprintf(runtimeDefaultTemplate, profileName, profileName, profileName, ""))
	return base64.StdEncoding.EncodeToString(c)
}

func generateHardeningRules(rule, qualifier string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 1. Blocking escape vectors from privileged container
	// disallow write core_pattern
	case "disallow-write-core-pattern":
		rules += qualifier + "deny /proc/sys/kernel/core_pattern w,\n"
	// disallow mount securityfs
	case "disallow-mount-securityfs":
		// mount new
		rules += qualifier + "deny mount fstype=securityfs,\n"
	// disallow mount procfs
	case "disallow-mount-procfs":
		// mount new
		rules += qualifier + "deny mount fstype=proc,\n"
		// bind, rbind, move
		rules += qualifier + "deny mount options in (bind,rbind,move) /proc** -> /**,\n"
		// remount
		rules += qualifier + "deny mount options in (remount,bind,rbind) -> /proc**,\n"
	// disallow write release_agent
	case "disallow-write-release-agent":
		rules += qualifier + "deny /sys/fs/cgroup/**/release_agent w,\n"
	// disallow mount cgroupfs
	case "disallow-mount-cgroupfs":
		// mount new
		rules += qualifier + "deny mount fstype=cgroup,\n"
		// bind, rbind, move
		rules += qualifier + "deny mount options in (bind,rbind,move) /sys/fs/cgroup** -> /**,\n"
		rules += qualifier + "deny mount options in (rbind) /sys** -> /**,\n"
		// remount
		rules += qualifier + "deny mount options in (remount,bind,rbind) -> /sys/fs/cgroup**,\n"
	// disallow debug disk devices
	case "disallow-debug-disk-device":
		rules += "{{range $value := .DiskDevices}}"
		rules += qualifier + "deny /dev/{{$value}} rw,\n"
		rules += "{{end}}"
	// disallow mount disk devices
	case "disallow-mount-disk-device":
		rules += "{{range $value := .DiskDevices}}"
		rules += qualifier + "deny mount /dev/{{$value}},\n"
		rules += "{{end}}"
	// disallow mount
	case "disallow-mount":
		rules += qualifier + "deny mount,\n"
	// disallow umount
	case "disallow-umount":
		rules += qualifier + "deny umount,\n"
	// disallow insmond
	case "disallow-insmod":
		rules += qualifier + "deny capability sys_module,\n"
	// disallow load ebpf program
	case "disallow-load-ebpf":
		rules += qualifier + "deny capability sys_admin,\n"
		rules += qualifier + "deny capability bpf,\n"
	// disallow access to the root of the task through procfs
	case "disallow-access-procfs-root":
		rules += qualifier + "deny ptrace read,\n"
	// disallow access /proc/kallsyms
	case "disallow-access-kallsyms":
		rules += qualifier + "deny /proc/kallsyms r,\n"

	//// 2. Disable capabilities
	// disable all capabilities
	case "disable-cap-all":
		rules += qualifier + "deny capability,\n"
	// disable all capabilities except for net_bind_service
	case "disable-cap-all-except-net-bind-service":
		rules += qualifier + "deny capability chown,\n"
		rules += qualifier + "deny capability dac_override,\n"
		rules += qualifier + "deny capability dac_read_search,\n"
		rules += qualifier + "deny capability fowner,\n"
		rules += qualifier + "deny capability fsetid,\n"
		rules += qualifier + "deny capability kill,\n"
		rules += qualifier + "deny capability setgid,\n"
		rules += qualifier + "deny capability setuid,\n"
		rules += qualifier + "deny capability setpcap,\n"
		rules += qualifier + "deny capability linux_immutable,\n"
		rules += qualifier + "deny capability net_broadcast,\n"
		rules += qualifier + "deny capability net_admin,\n"
		rules += qualifier + "deny capability net_raw,\n"
		rules += qualifier + "deny capability ipc_lock,\n"
		rules += qualifier + "deny capability ipc_owner,\n"
		rules += qualifier + "deny capability sys_module,\n"
		rules += qualifier + "deny capability sys_rawio,\n"
		rules += qualifier + "deny capability sys_chroot,\n"
		rules += qualifier + "deny capability sys_ptrace,\n"
		rules += qualifier + "deny capability sys_pacct,\n"
		rules += qualifier + "deny capability sys_admin,\n"
		rules += qualifier + "deny capability sys_boot,\n"
		rules += qualifier + "deny capability sys_nice,\n"
		rules += qualifier + "deny capability sys_resource,\n"
		rules += qualifier + "deny capability sys_time,\n"
		rules += qualifier + "deny capability sys_tty_config,\n"
		rules += qualifier + "deny capability mknod,\n"
		rules += qualifier + "deny capability lease,\n"
		rules += qualifier + "deny capability audit_write,\n"
		rules += qualifier + "deny capability audit_control,\n"
		rules += qualifier + "deny capability setfcap,\n"
		rules += qualifier + "deny capability mac_override,\n"
		rules += qualifier + "deny capability mac_admin,\n"
		rules += qualifier + "deny capability syslog,\n"
		rules += qualifier + "deny capability wake_alarm,\n"
		rules += qualifier + "deny capability block_suspend,\n"
		rules += qualifier + "deny capability audit_read,\n"
		rules += qualifier + "deny capability perfmon,\n"
		rules += qualifier + "deny capability bpf,\n"
		rules += qualifier + "deny capability checkpoint_restore,\n"

	// disable privileged capabilities
	case "disable-cap-privileged":
		rules += qualifier + "deny capability dac_read_search,\n"
		rules += qualifier + "deny capability linux_immutable,\n"
		rules += qualifier + "deny capability net_broadcast,\n"
		rules += qualifier + "deny capability net_admin,\n"
		rules += qualifier + "deny capability ipc_lock,\n"
		rules += qualifier + "deny capability ipc_owner,\n"
		rules += qualifier + "deny capability sys_module,\n"
		rules += qualifier + "deny capability sys_rawio,\n"
		rules += qualifier + "deny capability sys_ptrace,\n"
		rules += qualifier + "deny capability sys_pacct,\n"
		rules += qualifier + "deny capability sys_admin,\n"
		rules += qualifier + "deny capability sys_boot,\n"
		rules += qualifier + "deny capability sys_nice,\n"
		rules += qualifier + "deny capability sys_resource,\n"
		rules += qualifier + "deny capability sys_time,\n"
		rules += qualifier + "deny capability sys_tty_config,\n"
		rules += qualifier + "deny capability lease,\n"
		rules += qualifier + "deny capability audit_control,\n"
		rules += qualifier + "deny capability mac_override,\n"
		rules += qualifier + "deny capability mac_admin,\n"
		rules += qualifier + "deny capability syslog,\n"
		rules += qualifier + "deny capability wake_alarm,\n"
		rules += qualifier + "deny capability block_suspend,\n"
		rules += qualifier + "deny capability audit_read,\n"
		rules += qualifier + "deny capability perfmon,\n"
		rules += qualifier + "deny capability bpf,\n"
		rules += qualifier + "deny capability checkpoint_restore,\n"

	// disable the specified capability
	case "disable-cap-chown":
		rules += qualifier + "deny capability chown,\n"
	case "disable-cap-dac-override":
		rules += qualifier + "deny capability dac_override,\n"
	case "disable-cap-dac-read-search":
		rules += qualifier + "deny capability dac_read_search,\n"
	case "disable-cap-fowner":
		rules += qualifier + "deny capability fowner,\n"
	case "disable-cap-fsetid":
		rules += qualifier + "deny capability fsetid,\n"
	case "disable-cap-kill":
		rules += qualifier + "deny capability kill,\n"
	case "disable-cap-setgid":
		rules += qualifier + "deny capability setgid,\n"
	case "disable-cap-setuid":
		rules += qualifier + "deny capability setuid,\n"
	case "disable-cap-setpcap":
		rules += qualifier + "deny capability setpcap,\n"
	case "disable-cap-linux-immutable":
		rules += qualifier + "deny capability linux_immutable,\n"
	case "disable-cap-net-bind-service":
		rules += qualifier + "deny capability net_bind_service,\n"
	case "disable-cap-net-broadcast":
		rules += qualifier + "deny capability net_broadcast,\n"
	case "disable-cap-net-admin":
		rules += qualifier + "deny capability net_admin,\n"
	case "disable-cap-net-raw":
		rules += qualifier + "deny capability net_raw,\n"
	case "disable-cap-ipc-lock":
		rules += qualifier + "deny capability ipc_lock,\n"
	case "disable-cap-ipc-owner":
		rules += qualifier + "deny capability ipc_owner,\n"
	case "disable-cap-sys-module":
		rules += qualifier + "deny capability sys_module,\n"
	case "disable-cap-sys-rawio":
		rules += qualifier + "deny capability sys_rawio,\n"
	case "disable-cap-sys-chroot":
		rules += qualifier + "deny capability sys_chroot,\n"
	case "disable-cap-sys-ptrace":
		rules += qualifier + "deny capability sys_ptrace,\n"
	case "disable-cap-sys-pacct":
		rules += qualifier + "deny capability sys_pacct,\n"
	case "disable-cap-sys-admin":
		rules += qualifier + "deny capability sys_admin,\n"
	case "disable-cap-sys-boot":
		rules += qualifier + "deny capability sys_boot,\n"
	case "disable-cap-sys-nice":
		rules += qualifier + "deny capability sys_nice,\n"
	case "disable-cap-sys-resource":
		rules += qualifier + "deny capability sys_resource,\n"
	case "disable-cap-sys-time":
		rules += qualifier + "deny capability sys_time,\n"
	case "disable-cap-sys-tty-config":
		rules += qualifier + "deny capability sys_tty_config,\n"
	case "disable-cap-mknod":
		rules += qualifier + "deny capability mknod,\n"
	case "disable-cap-lease":
		rules += qualifier + "deny capability lease,\n"
	case "disable-cap-audit-write":
		rules += qualifier + "deny capability audit_write,\n"
	case "disable-cap-audit-control":
		rules += qualifier + "deny capability audit_control,\n"
	case "disable-cap-setfcap":
		rules += qualifier + "deny capability setfcap,\n"
	case "disable-cap-mac-override":
		rules += qualifier + "deny capability mac_override,\n"
	case "disable-cap-mac-admin":
		rules += qualifier + "deny capability mac_admin,\n"
	case "disable-cap-syslog":
		rules += qualifier + "deny capability syslog,\n"
	case "disable-cap-wake-alarm":
		rules += qualifier + "deny capability wake_alarm,\n"
	case "disable-cap-block-suspend":
		rules += qualifier + "deny capability block_suspend,\n"
	case "disable-cap-audit-read":
		rules += qualifier + "deny capability audit_read,\n"
	case "disable-cap-perfmon":
		rules += qualifier + "deny capability perfmon,\n"
	case "disable-cap-bpf":
		rules += qualifier + "deny capability bpf,\n"
	case "disable-cap-checkpoint-restore":
		rules += qualifier + "deny capability checkpoint_restore,\n"

	//// 3. Kernel vulnerability mitigation
	// forward-compatible
	case "disallow-create-user-ns":
		// TODO: add support for userns_create with AppArmor LSM (Linux v6.7+)
	// diallow abuse user namespace
	case "disallow-abuse-user-ns":
		rules += qualifier + "deny capability sys_admin,\n"
	}
	return rules
}

func generateAttackProtectionRules(rule, qualifier string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 4. Mitigate container information leakage
	case "mitigate-sa-leak":
		rules += qualifier + "deny /run/secrets/kubernetes.io/serviceaccount/** r,\n"
		rules += qualifier + "deny /var/run/secrets/kubernetes.io/serviceaccount/** r,\n"
	case "mitigate-disk-device-number-leak":
		rules += qualifier + "deny /proc/partitions r,\n"
		rules += qualifier + "deny /proc/**/mountinfo r,\n"
	case "mitigate-overlayfs-leak":
		rules += qualifier + "deny /proc/**/mounts r,\n"
		rules += qualifier + "deny /proc/**/mountinfo r,\n"
	case "mitigate-host-ip-leak":
		rules += qualifier + "deny /proc/**/net/arp r,\n"
	//// 5. Restrict the execution of sensitive commands inside the container
	case "disable-write-etc":
		rules += qualifier + "deny /etc/** wl,\n"
	case "disable-busybox":
		rules += qualifier + "deny /**/busybox rx,\n"
	case "disable-shell":
		rules += qualifier + "deny /**/sh rx,\n"
		rules += qualifier + "deny /**/bash rx,\n"
		rules += qualifier + "deny /**/dash rx,\n"
	case "disable-wget":
		rules += qualifier + "deny /**/wget rx,\n"
	case "disable-curl":
		rules += qualifier + "deny /**/curl rx,\n"
	case "disable-chmod":
		rules += qualifier + "deny /**/chmod rx,\n"
	case "disable-su-sudo":
		rules += qualifier + "deny /**/su rx,\n"
		rules += qualifier + "deny /**/sudo rx,\n"
	}
	return rules
}

func generateVulMitigationRules(rule, qualifier string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "cgroups-lxcfs-escape-mitigation":
		rules += qualifier + "deny /**/release_agent w,\n"
		rules += qualifier + "deny /**/devices/devices.allow w,\n"
		rules += qualifier + "deny /**/devices/**/devices.allow w,\n"
		rules += qualifier + "deny /**/devices/cgroup.procs w,\n"
		rules += qualifier + "deny /**/devices/**/cgroup.procs w,\n"
		rules += qualifier + "deny /**/devices/tasks w,\n"
		rules += qualifier + "deny /**/devices/**/tasks w,\n"
	case "runc-override-mitigation":
		rules += qualifier + "deny /**/runc w,\n"
	}
	return rules
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, profileName string) string {
	var baseRules, qualifier string

	if enhanceProtect.AuditViolations {
		qualifier = "  audit "
	} else {
		qualifier = "  "
	}

	// Hardening
	for _, rule := range enhanceProtect.HardeningRules {
		baseRules += generateHardeningRules(rule, qualifier)
	}

	// Vulnerability Mitigation
	for _, rule := range enhanceProtect.VulMitigationRules {
		baseRules += generateVulMitigationRules(rule, qualifier)
	}

	// Custom
	for _, rule := range enhanceProtect.AppArmorRawRules {
		if strings.HasSuffix(rule, ",") {
			baseRules += qualifier + rule + "\n"
		}
	}

	// Attack Protection
	index := 0
	parentBaseRules := baseRules
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				baseRules += generateAttackProtectionRules(rule, qualifier)
			}
		} else {
			// build a child profile for certain binaries
			childProfileName := fmt.Sprintf("child_%d", index)
			childProfilePath := fmt.Sprintf("%s//%s", profileName, childProfileName)
			childProfileRules := parentBaseRules
			index += 1

			for _, rule := range attackProtectionRule.Rules {
				childProfileRules += generateAttackProtectionRules(rule, qualifier)
			}

			targetsCx := ""
			for _, target := range attackProtectionRule.Targets {
				targetsCx += fmt.Sprintf("%s cx -> %s,\n", target, childProfileName)
			}

			targetsRix := ""
			for _, target := range attackProtectionRule.Targets {
				targetsRix += fmt.Sprintf("%s rix,\n", target)
			}

			if enhanceProtect.Privileged {
				baseRules += fmt.Sprintf(alwaysAllowChildTemplate,
					targetsCx,
					childProfileName,
					targetsRix,
					childProfileRules)
			} else {
				baseRules += fmt.Sprintf(runtimeDefaultChildTemplate,
					childProfilePath, // parent may send signal to child
					childProfilePath, // parent may ptrace child
					targetsCx,
					childProfileName,
					targetsRix,
					profileName, childProfilePath, // signal
					profileName, childProfilePath, // ptrace
					childProfileRules)
			}
		}
	}

	if enhanceProtect.Privileged {
		// Create profile for privileged container based on the AlwaysAllow template
		p := fmt.Sprintf(alwaysAllowTemplate, profileName, baseRules)
		return base64.StdEncoding.EncodeToString([]byte(p))
	} else {
		// Create profile for unprivileged container based on the RuntimeDefault template
		p := fmt.Sprintf(runtimeDefaultTemplate, profileName, profileName, profileName, baseRules)
		return base64.StdEncoding.EncodeToString([]byte(p))
	}
}

func GenerateBehaviorModelingProfile(profileName string) string {
	c := []byte(fmt.Sprintf(behaviorModelingTemplate, profileName))
	return base64.StdEncoding.EncodeToString(c)
}
