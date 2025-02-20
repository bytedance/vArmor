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
	"reflect"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// appArmorRules caches the AppArmor rules for specific executable files
type appArmorRules struct {
	// Rules cache the list of attack protection rules to be used.
	Rules []string `json:"rules"`
	// RawRules cache the custom rules to be used.
	RawRules []string `json:"rawRules"`
	// Targets specify the executable files for which the rules and rawRules apply.
	// They must be specified as full paths to the executable files.
	Targets []string `json:"targets"`
}

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
		rules += qualifier + "/proc/sys/kernel/core_pattern w,\n"
	// disallow mount securityfs
	case "disallow-mount-securityfs":
		// mount new
		rules += qualifier + "mount fstype=securityfs,\n"
	// disallow mount procfs
	case "disallow-mount-procfs":
		// mount new
		rules += qualifier + "mount fstype=proc,\n"
		// bind, rbind, move
		rules += qualifier + "mount options in (bind,rbind,move) /proc** -> /**,\n"
		// remount
		rules += qualifier + "mount options in (remount,bind,rbind) -> /proc**,\n"
	// disallow write release_agent
	case "disallow-write-release-agent":
		rules += qualifier + "/sys/fs/cgroup/**/release_agent w,\n"
	// disallow mount cgroupfs
	case "disallow-mount-cgroupfs":
		// mount new
		rules += qualifier + "mount fstype=cgroup,\n"
		// bind, rbind, move
		rules += qualifier + "mount options in (bind,rbind,move) /sys/fs/cgroup** -> /**,\n"
		rules += qualifier + "mount options in (rbind) /sys** -> /**,\n"
		// remount
		rules += qualifier + "mount options in (remount,bind,rbind) -> /sys/fs/cgroup**,\n"
	// disallow debug disk devices
	case "disallow-debug-disk-device":
		rules += "{{range $value := .DiskDevices}}"
		rules += qualifier + "/dev/{{$value}} rw,\n"
		rules += "{{end}}"
	// disallow mount disk devices
	case "disallow-mount-disk-device":
		rules += "{{range $value := .DiskDevices}}"
		rules += qualifier + "mount /dev/{{$value}},\n"
		rules += "{{end}}"
	// disallow mount
	case "disallow-mount":
		rules += qualifier + "mount,\n"
	// disallow umount
	case "disallow-umount":
		rules += qualifier + "umount,\n"
	// disallow insmond
	case "disallow-insmod":
		rules += qualifier + "capability sys_module,\n"
	// disallow loading ebpf programs, except for those of the BPF_PROG_TYPE_SOCKET_FILTER and BPF_PROG_TYPE_CGROUP_SKB types
	case "disallow-load-bpf-prog", "disallow-load-ebpf":
		rules += qualifier + "capability sys_admin,\n"
		rules += qualifier + "capability bpf,\n"
	// disallow access to the root of the task through procfs
	case "disallow-access-procfs-root":
		rules += qualifier + "ptrace read,\n"
	// disallow access /proc/kallsyms
	case "disallow-access-kallsyms":
		rules += qualifier + "/proc/kallsyms r,\n"

	//// 2. Disable capabilities
	// disable all capabilities
	case "disable-cap-all":
		rules += qualifier + "capability,\n"
	// disable all capabilities except for net_bind_service
	case "disable-cap-all-except-net-bind-service":
		rules += qualifier + "capability chown,\n"
		rules += qualifier + "capability dac_override,\n"
		rules += qualifier + "capability dac_read_search,\n"
		rules += qualifier + "capability fowner,\n"
		rules += qualifier + "capability fsetid,\n"
		rules += qualifier + "capability kill,\n"
		rules += qualifier + "capability setgid,\n"
		rules += qualifier + "capability setuid,\n"
		rules += qualifier + "capability setpcap,\n"
		rules += qualifier + "capability linux_immutable,\n"
		rules += qualifier + "capability net_broadcast,\n"
		rules += qualifier + "capability net_admin,\n"
		rules += qualifier + "capability net_raw,\n"
		rules += qualifier + "capability ipc_lock,\n"
		rules += qualifier + "capability ipc_owner,\n"
		rules += qualifier + "capability sys_module,\n"
		rules += qualifier + "capability sys_rawio,\n"
		rules += qualifier + "capability sys_chroot,\n"
		rules += qualifier + "capability sys_ptrace,\n"
		rules += qualifier + "capability sys_pacct,\n"
		rules += qualifier + "capability sys_admin,\n"
		rules += qualifier + "capability sys_boot,\n"
		rules += qualifier + "capability sys_nice,\n"
		rules += qualifier + "capability sys_resource,\n"
		rules += qualifier + "capability sys_time,\n"
		rules += qualifier + "capability sys_tty_config,\n"
		rules += qualifier + "capability mknod,\n"
		rules += qualifier + "capability lease,\n"
		rules += qualifier + "capability audit_write,\n"
		rules += qualifier + "capability audit_control,\n"
		rules += qualifier + "capability setfcap,\n"
		rules += qualifier + "capability mac_override,\n"
		rules += qualifier + "capability mac_admin,\n"
		rules += qualifier + "capability syslog,\n"
		rules += qualifier + "capability wake_alarm,\n"
		rules += qualifier + "capability block_suspend,\n"
		rules += qualifier + "capability audit_read,\n"
		rules += qualifier + "capability perfmon,\n"
		rules += qualifier + "capability bpf,\n"
		rules += qualifier + "capability checkpoint_restore,\n"

	// disable privileged capabilities
	case "disable-cap-privileged":
		rules += qualifier + "capability dac_read_search,\n"
		rules += qualifier + "capability linux_immutable,\n"
		rules += qualifier + "capability net_broadcast,\n"
		rules += qualifier + "capability net_admin,\n"
		rules += qualifier + "capability ipc_lock,\n"
		rules += qualifier + "capability ipc_owner,\n"
		rules += qualifier + "capability sys_module,\n"
		rules += qualifier + "capability sys_rawio,\n"
		rules += qualifier + "capability sys_ptrace,\n"
		rules += qualifier + "capability sys_pacct,\n"
		rules += qualifier + "capability sys_admin,\n"
		rules += qualifier + "capability sys_boot,\n"
		rules += qualifier + "capability sys_nice,\n"
		rules += qualifier + "capability sys_resource,\n"
		rules += qualifier + "capability sys_time,\n"
		rules += qualifier + "capability sys_tty_config,\n"
		rules += qualifier + "capability lease,\n"
		rules += qualifier + "capability audit_control,\n"
		rules += qualifier + "capability mac_override,\n"
		rules += qualifier + "capability mac_admin,\n"
		rules += qualifier + "capability syslog,\n"
		rules += qualifier + "capability wake_alarm,\n"
		rules += qualifier + "capability block_suspend,\n"
		rules += qualifier + "capability audit_read,\n"
		rules += qualifier + "capability perfmon,\n"
		rules += qualifier + "capability bpf,\n"
		rules += qualifier + "capability checkpoint_restore,\n"

	// disable the specified capability
	case "disable-cap-chown":
		rules += qualifier + "capability chown,\n"
	case "disable-cap-dac-override":
		rules += qualifier + "capability dac_override,\n"
	case "disable-cap-dac-read-search":
		rules += qualifier + "capability dac_read_search,\n"
	case "disable-cap-fowner":
		rules += qualifier + "capability fowner,\n"
	case "disable-cap-fsetid":
		rules += qualifier + "capability fsetid,\n"
	case "disable-cap-kill":
		rules += qualifier + "capability kill,\n"
	case "disable-cap-setgid":
		rules += qualifier + "capability setgid,\n"
	case "disable-cap-setuid":
		rules += qualifier + "capability setuid,\n"
	case "disable-cap-setpcap":
		rules += qualifier + "capability setpcap,\n"
	case "disable-cap-linux-immutable":
		rules += qualifier + "capability linux_immutable,\n"
	case "disable-cap-net-bind-service":
		rules += qualifier + "capability net_bind_service,\n"
	case "disable-cap-net-broadcast":
		rules += qualifier + "capability net_broadcast,\n"
	case "disable-cap-net-admin":
		rules += qualifier + "capability net_admin,\n"
	case "disable-cap-net-raw":
		rules += qualifier + "capability net_raw,\n"
	case "disable-cap-ipc-lock":
		rules += qualifier + "capability ipc_lock,\n"
	case "disable-cap-ipc-owner":
		rules += qualifier + "capability ipc_owner,\n"
	case "disable-cap-sys-module":
		rules += qualifier + "capability sys_module,\n"
	case "disable-cap-sys-rawio":
		rules += qualifier + "capability sys_rawio,\n"
	case "disable-cap-sys-chroot":
		rules += qualifier + "capability sys_chroot,\n"
	case "disable-cap-sys-ptrace":
		rules += qualifier + "capability sys_ptrace,\n"
	case "disable-cap-sys-pacct":
		rules += qualifier + "capability sys_pacct,\n"
	case "disable-cap-sys-admin":
		rules += qualifier + "capability sys_admin,\n"
	case "disable-cap-sys-boot":
		rules += qualifier + "capability sys_boot,\n"
	case "disable-cap-sys-nice":
		rules += qualifier + "capability sys_nice,\n"
	case "disable-cap-sys-resource":
		rules += qualifier + "capability sys_resource,\n"
	case "disable-cap-sys-time":
		rules += qualifier + "capability sys_time,\n"
	case "disable-cap-sys-tty-config":
		rules += qualifier + "capability sys_tty_config,\n"
	case "disable-cap-mknod":
		rules += qualifier + "capability mknod,\n"
	case "disable-cap-lease":
		rules += qualifier + "capability lease,\n"
	case "disable-cap-audit-write":
		rules += qualifier + "capability audit_write,\n"
	case "disable-cap-audit-control":
		rules += qualifier + "capability audit_control,\n"
	case "disable-cap-setfcap":
		rules += qualifier + "capability setfcap,\n"
	case "disable-cap-mac-override":
		rules += qualifier + "capability mac_override,\n"
	case "disable-cap-mac-admin":
		rules += qualifier + "capability mac_admin,\n"
	case "disable-cap-syslog":
		rules += qualifier + "capability syslog,\n"
	case "disable-cap-wake-alarm":
		rules += qualifier + "capability wake_alarm,\n"
	case "disable-cap-block-suspend":
		rules += qualifier + "capability block_suspend,\n"
	case "disable-cap-audit-read":
		rules += qualifier + "capability audit_read,\n"
	case "disable-cap-perfmon":
		rules += qualifier + "capability perfmon,\n"
	case "disable-cap-bpf":
		rules += qualifier + "capability bpf,\n"
	case "disable-cap-checkpoint-restore":
		rules += qualifier + "capability checkpoint_restore,\n"

	//// 3. Kernel vulnerability mitigation
	// forward-compatible
	case "disallow-create-user-ns":
		// TODO: add support for userns_create with AppArmor LSM (Linux v6.7+)
	// diallow abuse user namespace
	case "disallow-abuse-user-ns":
		rules += qualifier + "capability sys_admin,\n"
	}
	return rules
}

func generateAttackProtectionRules(rule, qualifier string, allowViolations bool) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 4. Mitigate container information leakage
	case "mitigate-sa-leak":
		rules += qualifier + "/run/secrets/kubernetes.io/serviceaccount/** r,\n"
		rules += qualifier + "/var/run/secrets/kubernetes.io/serviceaccount/** r,\n"
	case "mitigate-disk-device-number-leak":
		rules += qualifier + "/proc/partitions r,\n"
		rules += qualifier + "/proc/**/mountinfo r,\n"
	case "mitigate-overlayfs-leak":
		rules += qualifier + "/proc/**/mounts r,\n"
		rules += qualifier + "/proc/**/mountinfo r,\n"
	case "mitigate-host-ip-leak":
		rules += qualifier + "/proc/**/net/arp r,\n"
	//// 5. Restrict the sensitive operations inside the container
	case "disable-write-etc":
		rules += qualifier + "/etc/** wl,\n"
	case "disable-busybox":
		if allowViolations {
			rules += qualifier + "/**/busybox rix,\n"
		} else {
			rules += qualifier + "/**/busybox rx,\n"
		}
	case "disable-shell":
		if allowViolations {
			rules += qualifier + "/**/sh rix,\n"
			rules += qualifier + "/**/bash rix,\n"
			rules += qualifier + "/**/dash rix,\n"
		} else {
			rules += qualifier + "/**/sh rx,\n"
			rules += qualifier + "/**/bash rx,\n"
			rules += qualifier + "/**/dash rx,\n"
		}
	case "disable-wget":
		if allowViolations {
			rules += qualifier + "/**/wget rix,\n"
		} else {
			rules += qualifier + "/**/wget rx,\n"
		}
	case "disable-curl":
		if allowViolations {
			rules += qualifier + "/**/curl rix,\n"
		} else {
			rules += qualifier + "/**/curl rx,\n"
		}
	case "disable-chmod":
		if allowViolations {
			rules += qualifier + "/**/chmod rix,\n"
		} else {
			rules += qualifier + "/**/chmod rx,\n"
		}
	case "disable-su-sudo":
		if allowViolations {
			rules += qualifier + "/**/su rix,\n"
			rules += qualifier + "/**/sudo rix,\n"
		} else {
			rules += qualifier + "/**/su rx,\n"
			rules += qualifier + "/**/sudo rx,\n"
		}
	//// 6. Others
	case "disable-network":
		rules += qualifier + "network,\n"
	case "disable-ipv4", "disable-inet":
		rules += qualifier + "network inet,\n"
	case "disable-ipv6", "disable-inet6":
		rules += qualifier + "network inet6,\n"
	case "disable-unix-domain-socket":
		rules += qualifier + "network unix,\n"
	case "disable-icmp":
		rules += qualifier + "network icmp,\n"
	case "disable-tcp":
		rules += qualifier + "network tcp,\n"
	case "disable-udp":
		rules += qualifier + "network udp,\n"
	}
	return rules
}

func generateVulMitigationRules(rule, qualifier string) (rules string) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "cgroups-lxcfs-escape-mitigation":
		rules += qualifier + "/**/release_agent w,\n"
		rules += qualifier + "/**/devices/devices.allow w,\n"
		rules += qualifier + "/**/devices/**/devices.allow w,\n"
		rules += qualifier + "/**/devices/cgroup.procs w,\n"
		rules += qualifier + "/**/devices/**/cgroup.procs w,\n"
		rules += qualifier + "/**/devices/tasks w,\n"
		rules += qualifier + "/**/devices/**/tasks w,\n"
	case "runc-override-mitigation":
		rules += qualifier + "/**/runc w,\n"
	}
	return rules
}

func mergeRulesForSameTarget(tempRules []appArmorRules) []appArmorRules {
	var finalRules []appArmorRules

	for _, tempRule := range tempRules {
		merged := false
		for index, finalRule := range finalRules {
			if reflect.DeepEqual(finalRule.Targets, tempRule.Targets) {
				finalRules[index].Rules = append(finalRules[index].Rules, tempRule.Rules...)
				finalRules[index].RawRules = append(finalRules[index].RawRules, tempRule.RawRules...)
				merged = true
			}
		}

		if !merged {
			finalRules = append(finalRules, appArmorRules{
				Rules:    tempRule.Rules,
				RawRules: tempRule.RawRules,
				Targets:  tempRule.Targets,
			})
		}
	}

	return finalRules
}

func mergeTargetForSameRules(tempRules []appArmorRules) []appArmorRules {
	var finalRules []appArmorRules

	for _, tempRule := range tempRules {
		merged := false
		for index, finalRule := range finalRules {
			if reflect.DeepEqual(finalRule.Rules, tempRule.Rules) &&
				reflect.DeepEqual(finalRule.RawRules, tempRule.RawRules) {
				finalRules[index].Targets = append(finalRules[index].Targets, tempRule.Targets...)
				merged = true
			}
		}

		if !merged {
			finalRules = append(finalRules, appArmorRules{
				Rules:    tempRule.Rules,
				RawRules: tempRule.RawRules,
				Targets:  tempRule.Targets,
			})
		}
	}

	return finalRules
}

func preprocessAttackProtectionAndCustomRulesForTargets(enhanceProtect *varmor.EnhanceProtect) []appArmorRules {
	var tempRules []appArmorRules

	// Break down the rules at the granularity of the AttackProtectionRules' target
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			continue
		}

		for _, target := range attackProtectionRule.Targets {
			tempRules = append(tempRules, appArmorRules{
				Rules:   attackProtectionRule.Rules,
				Targets: []string{target},
			})
		}
	}

	// Break down the rules at the granularity of the AppArmorRawRules' target
	for _, appArmorRawRules := range enhanceProtect.AppArmorRawRules {
		if len(appArmorRawRules.Targets) == 0 {
			continue
		}

		for _, target := range appArmorRawRules.Targets {
			tempRules = append(tempRules, appArmorRules{
				RawRules: []string{appArmorRawRules.Rules},
				Targets:  []string{target},
			})
		}
	}

	// Merge rules which have same target
	tempRules = mergeRulesForSameTarget(tempRules)

	// Merge targets which have same rules
	tempRules = mergeTargetForSameRules(tempRules)

	// Return the final rules for specific executable files
	return tempRules
}

func generateRulesForTargets(enhanceProtect *varmor.EnhanceProtect, profileName, baseRules, qualifier string) string {
	parentBaseRules := baseRules
	aarules := preprocessAttackProtectionAndCustomRulesForTargets(enhanceProtect)

	for index, aarule := range aarules {
		// Building a child profile for certain binaries
		childProfileName := fmt.Sprintf("child_%d", index)
		childProfilePath := fmt.Sprintf("%s//%s", profileName, childProfileName)
		childProfileRules := parentBaseRules
		index += 1

		// Generate attack protection rules for targets
		childProfileRules += "\n  # Attack Protection Rules For Child Profile\n"
		for _, rule := range aarule.Rules {
			childProfileRules += generateAttackProtectionRules(rule, qualifier, enhanceProtect.AllowViolations)
		}

		// Merge custom rules for targets
		childProfileRules += "\n  # Custom Rules For Child Profile\n"
		for _, rule := range aarule.RawRules {
			childProfileRules += rule + "\n"
		}

		// Setup targets to run in the child profile
		targetsCx := ""
		for _, target := range aarule.Targets {
			targetsCx += fmt.Sprintf("%s cx -> %s,\n", target, childProfileName)
		}

		targetsRix := ""
		for _, target := range aarule.Targets {
			targetsRix += fmt.Sprintf("%s rix,\n", target)
		}

		// Generate the final child profile for targets
		baseRules += "\n## Child Profile ##\n"
		if enhanceProtect.Privileged {
			baseRules += fmt.Sprintf(alwaysAllowChildTemplate,
				targetsCx,
				childProfileName,
				targetsRix,
				childProfileRules)
		} else {
			templ := runtimeDefaultChildTemplateForEnhanceProtectMode
			if enhanceProtect.AllowViolations {
				// Note:
				// 		'x' must be preceded by exec qualifier 'i', 'p', 'c', or 'u' if there is no deny qualifier
				templ = strings.ReplaceAll(templ, "wklx,", "wklix,")
			}

			baseRules += fmt.Sprintf(templ,
				childProfilePath, // parent may send signal to child
				childProfilePath, // parent may ptrace child
				targetsCx,
				childProfileName,
				targetsRix,
				profileName, childProfilePath, // allow receiving the signal from the parent
				profileName, childProfilePath, // allow be traced by the parent
				childProfileRules)
		}
	}

	return baseRules
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, profileName string) string {
	var baseRules string
	qualifier := "  "

	if enhanceProtect.AuditViolations {
		qualifier += "audit "
	}

	if !enhanceProtect.AllowViolations {
		qualifier += "deny "
	}

	// Hardening Rules
	baseRules += "  # Hardening Rules\n"
	for _, rule := range enhanceProtect.HardeningRules {
		baseRules += generateHardeningRules(rule, qualifier)
	}

	// Attack Protection Rules
	baseRules += "\n  # Attack Protection Rules\n"
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		// Only process the global rules now
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				baseRules += generateAttackProtectionRules(rule, qualifier, enhanceProtect.AllowViolations)
			}
		}
	}

	// Vulnerability Mitigation Rules
	baseRules += "\n  # Vulnerability Mitigation Rules\n"
	for _, rule := range enhanceProtect.VulMitigationRules {
		baseRules += generateVulMitigationRules(rule, qualifier)
	}

	// Custom Rules
	baseRules += "\n  # Custom Rules\n"
	for _, rule := range enhanceProtect.AppArmorRawRules {
		// Only process the global rules now
		if len(rule.Targets) == 0 {
			baseRules += rule.Rules + "\n"
		}
	}

	// Attack protection rules and custom rules for restricting specific executable
	baseRules = generateRulesForTargets(enhanceProtect, profileName, baseRules, qualifier)

	// Generate the final profile
	if enhanceProtect.Privileged {
		// Create profile for privileged container based on the AlwaysAllow template
		p := fmt.Sprintf(alwaysAllowTemplate, profileName, baseRules)
		p = strings.ReplaceAll(p, "  QUALIFIER ", qualifier)
		return base64.StdEncoding.EncodeToString([]byte(p))
	} else {
		// Create profile for unprivileged container based on the RuntimeDefault template
		templ := runtimeDefaultTemplateForEnhanceProtectMode
		if enhanceProtect.AllowViolations {
			// Note:
			//		'x' must be preceded by exec qualifier 'i', 'p', 'c', or 'u' if there is no deny qualifier
			templ = strings.ReplaceAll(templ, "wklx,", "wklix,")
		}

		p := fmt.Sprintf(templ, profileName, profileName, profileName, baseRules)
		p = strings.ReplaceAll(p, "  QUALIFIER ", qualifier)
		return base64.StdEncoding.EncodeToString([]byte(p))
	}
}

func GenerateBehaviorModelingProfile(profileName string) string {
	c := []byte(fmt.Sprintf(behaviorModelingTemplate, profileName))
	return base64.StdEncoding.EncodeToString(c)
}
