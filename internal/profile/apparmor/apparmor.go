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

func generateHardeningRules(rule string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 1. Blocking escape vectors from privileged container
	// disallow write core_pattern
	case "disallow-write-core-pattern":
		rules += "  deny /proc/sys/kernel/core_pattern w,\n"
	// disallow mount securityfs
	case "disallow-mount-securityfs":
		// mount new
		rules += "  deny mount fstype=securityfs,\n"
	// disallow mount procfs
	case "disallow-mount-procfs":
		// mount new
		rules += "  deny mount fstype=proc,\n"
		// bind, rbind, move
		rules += "  deny mount options in (bind,rbind,move) /proc** -> /**,\n"
		// remount
		rules += "  deny mount options in (remount,bind,rbind) -> /proc**,\n"
	// disallow write release_agent
	case "disallow-write-release-agent":
		rules += "  deny /sys/fs/cgroup/**/release_agent w,\n"
	// disallow mount cgroupfs
	case "disallow-mount-cgroupfs":
		// mount new
		rules += "  deny mount fstype=cgroup,\n"
		// bind, rbind, move
		rules += "  deny mount options in (bind,rbind,move) /sys/fs/cgroup** -> /**,\n"
		rules += "  deny mount options in (rbind) /sys** -> /**,\n"
		// remount
		rules += "  deny mount options in (remount,bind,rbind) -> /sys/fs/cgroup**,\n"
	// disallow debug disk devices
	case "disallow-debug-disk-device":
		rules += "{{range $value := .DiskDevices}}"
		rules += "  deny /dev/{{$value}} rw,\n"
		rules += "{{end}}"
	// disallow mount disk devices
	case "disallow-mount-disk-device":
		rules += "{{range $value := .DiskDevices}}"
		rules += "  deny mount /dev/{{$value}},\n"
		rules += "{{end}}"
	// disallow mount
	case "disallow-mount":
		rules += "  deny mount,\n"
	// disallow umount
	case "disallow-umount":
		rules += "  deny umount,\n"
	// disallow insmond
	case "disallow-insmod":
		rules += "  deny capability sys_module,\n"
	// disallow load ebpf program
	case "disallow-load-ebpf":
		rules += "  deny capability sys_admin,\n"
		rules += "  deny capability bpf,\n"
	// disallow access to the root of the task through procfs
	case "disallow-access-procfs-root":
		rules += "  deny ptrace read,\n"

	//// 2. Disable capabilities
	// disable all capabilities
	case "disable-cap-all":
		rules += "  deny capability,\n"
	// disable privileged capabilities
	case "disable-cap-privileged":
		rules += `  deny capability dac_read_search,
  deny capability linux_immutable,
  deny capability net_broadcast,
  deny capability net_admin,
  deny capability ipc_lock,
  deny capability ipc_owner,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_ptrace,
  deny capability sys_pacct,
  deny capability sys_admin,
  deny capability sys_boot,
  deny capability sys_nice,
  deny capability sys_resource,
  deny capability sys_time,
  deny capability sys_tty_config,
  deny capability lease,
  deny capability audit_control,
  deny capability mac_override,
  deny capability mac_admin,
  deny capability syslog,
  deny capability wake_alarm,
  deny capability block_suspend,
  deny capability audit_read,
	deny capability perfmon,
	deny capability bpf,
	deny capability checkpoint_restore,	
`
	// disable the specified capability
	case "disable-cap-chown":
		rules += "  deny capability chown,\n"
	case "disable-cap-dac-override":
		rules += "  deny capability dac_override,\n"
	case "disable-cap-dac-read-search":
		rules += "  deny capability dac_read_search,\n"
	case "disable-cap-fowner":
		rules += "  deny capability fowner,\n"
	case "disable-cap-fsetid":
		rules += "  deny capability fsetid,\n"
	case "disable-cap-kill":
		rules += "  deny capability kill,\n"
	case "disable-cap-setgid":
		rules += "  deny capability setgid,\n"
	case "disable-cap-setuid":
		rules += "  deny capability setuid,\n"
	case "disable-cap-setpcap":
		rules += "  deny capability setpcap,\n"
	case "disable-cap-linux-immutable":
		rules += "  deny capability linux_immutable,\n"
	case "disable-cap-net-bind-service":
		rules += "  deny capability net_bind_service,\n"
	case "disable-cap-net-broadcast":
		rules += "  deny capability net_broadcast,\n"
	case "disable-cap-net-admin":
		rules += "  deny capability net_admin,\n"
	case "disable-cap-net-raw":
		rules += "  deny capability net_raw,\n"
	case "disable-cap-ipc-lock":
		rules += "  deny capability ipc_lock,\n"
	case "disable-cap-ipc-owner":
		rules += "  deny capability ipc_owner,\n"
	case "disable-cap-sys-module":
		rules += "  deny capability sys_module,\n"
	case "disable-cap-sys-rawio":
		rules += "  deny capability sys_rawio,\n"
	case "disable-cap-sys-chroot":
		rules += "  deny capability sys_chroot,\n"
	case "disable-cap-sys-ptrace":
		rules += "  deny capability sys_ptrace,\n"
	case "disable-cap-sys-pacct":
		rules += "  deny capability sys_pacct,\n"
	case "disable-cap-sys-admin":
		rules += "  deny capability sys_admin,\n"
	case "disable-cap-sys-boot":
		rules += "  deny capability sys_boot,\n"
	case "disable-cap-sys-nice":
		rules += "  deny capability sys_nice,\n"
	case "disable-cap-sys-resource":
		rules += "  deny capability sys_resource,\n"
	case "disable-cap-sys-time":
		rules += "  deny capability sys_time,\n"
	case "disable-cap-sys-tty-config":
		rules += "  deny capability sys_tty_config,\n"
	case "disable-cap-mknod":
		rules += "  deny capability mknod,\n"
	case "disable-cap-lease":
		rules += "  deny capability lease,\n"
	case "disable-cap-audit-write":
		rules += "  deny capability audit_write,\n"
	case "disable-cap-audit-control":
		rules += "  deny capability audit_control,\n"
	case "disable-cap-setfcap":
		rules += "  deny capability setfcap,\n"
	case "disable-cap-mac-override":
		rules += "  deny capability mac_override,\n"
	case "disable-cap-mac-admin":
		rules += "  deny capability mac_admin,\n"
	case "disable-cap-syslog":
		rules += "  deny capability syslog,\n"
	case "disable-cap-wake-alarm":
		rules += "  deny capability wake_alarm,\n"
	case "disable-cap-block-suspend":
		rules += "  deny capability block_suspend,\n"
	case "disable-cap-audit-read":
		rules += "  deny capability audit_read,\n"
	case "disable-cap-perfmon":
		rules += "  deny capability perfmon,\n"
	case "disable-cap-bpf":
		rules += "  deny capability bpf,\n"
	case "disable-cap-checkpoint-restore":
		rules += "  deny capability checkpoint_restore,\n"

	//// 3. Kernel vulnerability mitigation
	// forward-compatible
	case "disallow-create-user-ns":
		fallthrough
	// diallow abuse user namespace
	case "disallow-abuse-user-ns":
		rules += "  deny capability sys_admin,\n"
	}
	return rules
}

func generateAttackProtectionRules(rule string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 4. Mitigate container information leakage
	case "mitigate-sa-leak":
		rules += "  deny /run/secrets/kubernetes.io/serviceaccount/** r,\n"
		rules += "  deny /var/run/secrets/kubernetes.io/serviceaccount/** r,\n"
	case "mitigate-disk-device-number-leak":
		rules += "  deny /proc/partitions r,\n"
		rules += "  deny /proc/**/mountinfo r,\n"
	case "mitigate-overlayfs-leak":
		rules += "  deny /proc/**/mounts r,\n"
		rules += "  deny /proc/**/mountinfo r,\n"
	case "mitigate-host-ip-leak":
		rules += "  deny /proc/**/net/arp r,\n"
	//// 5. Restrict the execution of sensitive commands inside the container
	case "disable-write-etc":
		rules += "  deny /etc/** wl,\n"
	case "disable-busybox":
		rules += "  deny /**/busybox rx,\n"
	case "disable-shell":
		rules += "  deny /**/sh rx,\n"
		rules += "  deny /**/bash rx,\n"
		rules += "  deny /**/dash rx,\n"
	case "disable-wget":
		rules += "  deny /**/wget rx,\n"
	case "disable-curl":
		rules += "  deny /**/curl rx,\n"
	case "disable-chmod":
		rules += "  deny /**/chmod rx,\n"
	case "disable-su-sudo":
		rules += "  deny /**/su rx,\n"
		rules += "  deny /**/sudo rx,\n"
	}
	return rules
}

func generateVulMitigationRules(rule string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "cgroups-lxcfs-escape-mitigation":
		rules += "  deny /**/release_agent w,\n"
		rules += "  deny /**/devices/devices.allow w,\n"
		rules += "  deny /**/devices/**/devices.allow w,\n"
		rules += "  deny /**/devices/cgroup.procs w,\n"
		rules += "  deny /**/devices/**/cgroup.procs w,\n"
		rules += "  deny /**/devices/tasks w,\n"
		rules += "  deny /**/devices/**/tasks w,\n"
	}
	return rules
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, profileName string) string {
	var baseRules string

	// Hardening
	for _, rule := range enhanceProtect.HardeningRules {
		baseRules += generateHardeningRules(rule)
	}

	// Vulnerability Mitigation
	for _, rule := range enhanceProtect.VulMitigationRules {
		baseRules += generateVulMitigationRules(rule)
	}

	// Custom
	for _, rule := range enhanceProtect.AppArmorRawRules {
		if strings.HasSuffix(rule, ",") {
			baseRules += "  " + rule + "\n"
		}
	}

	// Attack Protection
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				baseRules += generateAttackProtectionRules(rule)
			}
		}
	}

	// childName(target): childRules
	childRulesMap := make(map[string]string)
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) != 0 {
			var childRules string

			for _, childName := range attackProtectionRule.Targets {
				if _, ok := childRulesMap[childName]; !ok {
					childRules = baseRules
				} else {
					childRules = childRulesMap[childName]
				}

				for _, rule := range attackProtectionRule.Rules {
					childRules += generateAttackProtectionRules(rule)
					childRulesMap[childName] = childRules
				}
			}
		}
	}

	for childName, childRules := range childRulesMap {
		if enhanceProtect.Privileged {
			// Create the child profile for privileged container based on the AlwaysAllow child template
			baseRules += fmt.Sprintf(alwaysAllowChildTemplate, childName, childName, childName, childRules)
		} else {
			// Create the child profile for unprivileged container based on the RuntimeDefault child template
			childProfileName := fmt.Sprintf("%s//%s", profileName, childName)
			baseRules += fmt.Sprintf(runtimeDefaultChildTemplate,
				childProfileName,                // signal
				childName, childName, childName, // target
				profileName, childProfileName, // signal
				profileName, childProfileName, // ptrace
				childRules)
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
