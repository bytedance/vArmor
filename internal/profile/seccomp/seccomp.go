// Copyright 2024 vArmor Authors
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

// Package seccomp generates the Seccomp profile
package seccomp

import (
	"encoding/json"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	defaultSyscall = specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names: []string{
			"open",
			"openat",
			"openat2",
			"close",
			"read",
			"write",
		},
	}
)

func GenerateAlwaysAllowProfile() string {
	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
	}

	p, _ := json.Marshal(profile)
	return string(p)
}

func GenerateBehaviorModelingProfile() string {
	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActLog,
		Syscalls:      []specs.LinuxSyscall{defaultSyscall},
	}

	p, _ := json.Marshal(profile)
	return string(p)
}

func GenerateProfileWithBehaviorModel(seccomp *varmor.Seccomp) (string, error) {
	if len(seccomp.Syscalls) == 0 {
		return "", nil
	}

	syscall := specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names:  seccomp.Syscalls,
	}

	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{defaultSyscall, syscall},
	}

	p, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	return string(p), nil
}

func generateHardeningRules(rule string, syscalls map[string]specs.LinuxSyscall, action specs.LinuxSeccompAction) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	//// 3. Kernel vulnerability mitigation
	case "disallow-create-user-ns":
		// Note: We should append the arguments after initializing the LinuxSyscall
		// object when we want to add new built-in rules for unshare().
		if _, ok := syscalls["unshare"]; !ok {
			syscalls["unshare"] = specs.LinuxSyscall{
				Names:  []string{"unshare"},
				Action: action,
				Args: []specs.LinuxSeccompArg{
					{
						Index:    0,
						Value:    unix.CLONE_NEWUSER,
						ValueTwo: unix.CLONE_NEWUSER,
						Op:       specs.OpMaskedEqual,
					},
				},
			}
		}
	case "disallow-load-all-bpf-prog":
		// Note: We should append the arguments after initializing the LinuxSyscall
		// object when we want to add new built-in rules for bpf().
		if _, ok := syscalls["bpf"]; !ok {
			syscalls["bpf"] = specs.LinuxSyscall{
				Names:  []string{"bpf"},
				Action: action,
				Args: []specs.LinuxSeccompArg{
					{
						Index: 0,
						Value: unix.BPF_PROG_LOAD,
						Op:    specs.OpEqualTo,
					},
				},
			}
		}
	case "disallow-load-bpf-via-setsockopt":
		syscalls["setsockopt_so_attach_filter"] = specs.LinuxSyscall{
			Names:  []string{"setsockopt"},
			Action: action,
			Args: []specs.LinuxSeccompArg{
				{
					Index: 1,
					Value: unix.SOL_SOCKET,
					Op:    specs.OpEqualTo,
				},
				{
					Index: 2,
					Value: unix.SO_ATTACH_FILTER,
					Op:    specs.OpEqualTo,
				},
			},
		}

		syscalls["setsockopt_so_attach_reuseport_cbpf"] = specs.LinuxSyscall{
			Names:  []string{"setsockopt"},
			Action: action,
			Args: []specs.LinuxSeccompArg{
				{
					Index: 1,
					Value: unix.SOL_SOCKET,
					Op:    specs.OpEqualTo,
				},
				{
					Index: 2,
					Value: unix.SO_ATTACH_REUSEPORT_CBPF,
					Op:    specs.OpEqualTo,
				},
			},
		}

	case "disallow-userfaultfd-creation":
		if _, ok := syscalls["userfaultfd"]; !ok {
			syscalls["userfaultfd"] = specs.LinuxSyscall{
				Names:  []string{"userfaultfd"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
	}
}

func generateVulMitigationRules(rule string, syscalls map[string]specs.LinuxSyscall, action specs.LinuxSeccompAction) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "dirty-pipe-mitigation":
		if _, ok := syscalls["splice"]; !ok {
			syscalls["splice"] = specs.LinuxSyscall{
				Names:  []string{"splice"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
	}
}

func generateAttackProtectionRules(rule string, syscalls map[string]specs.LinuxSyscall, action specs.LinuxSeccompAction) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "disable-chmod-x-bit":
		// Append the arguments for chmod
		if _, ok := syscalls["chmod"]; !ok {
			syscalls["chmod"] = specs.LinuxSyscall{
				Names:  []string{"chmod"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		chmod := syscalls["chmod"]
		chmod.Args = append(chmod.Args, []specs.LinuxSeccompArg{
			{
				Index:    1,
				Value:    unix.S_IXUSR,
				ValueTwo: unix.S_IXUSR,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    1,
				Value:    unix.S_IXGRP,
				ValueTwo: unix.S_IXGRP,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    1,
				Value:    unix.S_IXOTH,
				ValueTwo: unix.S_IXOTH,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["chmod"] = chmod

		// Append the arguments for fchmod
		if _, ok := syscalls["fchmod"]; !ok {
			syscalls["fchmod"] = specs.LinuxSyscall{
				Names:  []string{"fchmod"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		fchmod := syscalls["fchmod"]
		fchmod.Args = append(fchmod.Args, []specs.LinuxSeccompArg{
			{
				Index:    1,
				Value:    unix.S_IXUSR,
				ValueTwo: unix.S_IXUSR,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    1,
				Value:    unix.S_IXGRP,
				ValueTwo: unix.S_IXGRP,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    1,
				Value:    unix.S_IXOTH,
				ValueTwo: unix.S_IXOTH,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["fchmod"] = fchmod

		// Append the arguments for fchmodat
		if _, ok := syscalls["fchmodat"]; !ok {
			syscalls["fchmodat"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		fchmodat := syscalls["fchmodat"]
		fchmodat.Args = append(fchmodat.Args, []specs.LinuxSeccompArg{
			{
				Index:    2,
				Value:    unix.S_IXUSR,
				ValueTwo: unix.S_IXUSR,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    2,
				Value:    unix.S_IXGRP,
				ValueTwo: unix.S_IXGRP,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    2,
				Value:    unix.S_IXOTH,
				ValueTwo: unix.S_IXOTH,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["fchmodat"] = fchmodat

		// Append the arguments for fchmodat2
		if _, ok := syscalls["fchmodat2"]; !ok {
			syscalls["fchmodat2"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat2"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		fchmodat2 := syscalls["fchmodat2"]
		fchmodat2.Args = append(fchmodat2.Args, []specs.LinuxSeccompArg{
			{
				Index:    2,
				Value:    unix.S_IXUSR,
				ValueTwo: unix.S_IXUSR,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    2,
				Value:    unix.S_IXGRP,
				ValueTwo: unix.S_IXGRP,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    2,
				Value:    unix.S_IXOTH,
				ValueTwo: unix.S_IXOTH,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["fchmodat2"] = fchmodat2

	case "disable-chmod-s-bit":
		// Append arguments for chmod
		if _, ok := syscalls["chmod"]; !ok {
			syscalls["chmod"] = specs.LinuxSyscall{
				Names:  []string{"chmod"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		chmod := syscalls["chmod"]
		chmod.Args = append(chmod.Args, []specs.LinuxSeccompArg{
			{
				Index:    1,
				Value:    unix.S_ISUID,
				ValueTwo: unix.S_ISUID,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    1,
				Value:    unix.S_ISGID,
				ValueTwo: unix.S_ISGID,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["chmod"] = chmod

		// Append arguments for fchmod
		if _, ok := syscalls["fchmod"]; !ok {
			syscalls["fchmod"] = specs.LinuxSyscall{
				Names:  []string{"fchmod"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		fchmod := syscalls["fchmod"]
		fchmod.Args = append(fchmod.Args, []specs.LinuxSeccompArg{
			{
				Index:    1,
				Value:    unix.S_ISUID,
				ValueTwo: unix.S_ISUID,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    1,
				Value:    unix.S_ISGID,
				ValueTwo: unix.S_ISGID,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["fchmod"] = fchmod

		// Append arguments for fchmodat
		if _, ok := syscalls["fchmodat"]; !ok {
			syscalls["fchmodat"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		fchmodat := syscalls["fchmodat"]
		fchmodat.Args = append(fchmodat.Args, []specs.LinuxSeccompArg{
			{
				Index:    2,
				Value:    unix.S_ISUID,
				ValueTwo: unix.S_ISUID,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    2,
				Value:    unix.S_ISGID,
				ValueTwo: unix.S_ISGID,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["fchmodat"] = fchmodat

		// Append arguments for fchmodat2
		if _, ok := syscalls["fchmodat2"]; !ok {
			syscalls["fchmodat2"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat2"},
				Action: action,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
		fchmodat2 := syscalls["fchmodat2"]
		fchmodat2.Args = append(fchmodat2.Args, []specs.LinuxSeccompArg{
			{
				Index:    2,
				Value:    unix.S_ISUID,
				ValueTwo: unix.S_ISUID,
				Op:       specs.OpMaskedEqual,
			},
			{
				Index:    2,
				Value:    unix.S_ISGID,
				ValueTwo: unix.S_ISGID,
				Op:       specs.OpMaskedEqual,
			},
		}...)
		syscalls["fchmodat2"] = fchmodat2
	}
}

func InLinuxSeccompArgArray(c specs.LinuxSeccompArg, array []specs.LinuxSeccompArg) bool {
	for _, v := range array {
		if reflect.DeepEqual(c, v) {
			return true
		}
	}
	return false
}

func mergeSyscallArgs(syscallName string, rawRule specs.LinuxSyscall, syscalls map[string]specs.LinuxSyscall) bool {
	if syscall, ok := syscalls[syscallName]; ok {
		if syscall.Action == rawRule.Action && reflect.DeepEqual(syscall.ErrnoRet, rawRule.ErrnoRet) {
			if len(rawRule.Args) == 0 && len(syscall.Args) != 0 {
				// Make the raw rule override the built-in rule
				return false
			} else if len(rawRule.Args) != 0 && len(syscall.Args) == 0 {
				// Ignore the raw rule because the built-in rule disables the syscall
				return true
			}

			for _, rawArg := range rawRule.Args {
				if !InLinuxSeccompArgArray(rawArg, syscall.Args) {
					// Merge the arguments of raw rule into the selected built-in rule
					syscall.Args = append(syscall.Args, rawArg)
					syscalls[syscallName] = syscall
				}
			}
			return true
		}
	}
	return false
}

func generateRawRules(rawRules []specs.LinuxSyscall, syscalls map[string]specs.LinuxSyscall, profile *specs.LinuxSeccomp) {
	for _, rawRule := range rawRules {
		for _, name := range rawRule.Names {
			// Merge the arguments of raw rule into the selected built-in rules.
			if mergeSyscallArgs(name, rawRule, syscalls) {
				continue
			}

			// Add new syscall rule to profile
			s := specs.LinuxSyscall{
				Names:    []string{name},
				Action:   rawRule.Action,
				ErrnoRet: rawRule.ErrnoRet,
				Args:     rawRule.Args,
			}
			profile.Syscalls = append(profile.Syscalls, s)
		}
	}
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, profileName string) (string, error) {
	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls:      []specs.LinuxSyscall{},
	}

	syscalls := make(map[string]specs.LinuxSyscall)

	var action specs.LinuxSeccompAction
	if enhanceProtect.AllowViolations && enhanceProtect.AuditViolations {
		// alarm-only without interception mode (observation mode)
		action = specs.ActLog
	} else {
		// intercept mode
		action = specs.ActErrno
	}

	// Hardening
	for _, rule := range enhanceProtect.HardeningRules {
		generateHardeningRules(rule, syscalls, action)
	}

	// Vulnerability Mitigation
	for _, rule := range enhanceProtect.VulMitigationRules {
		generateVulMitigationRules(rule, syscalls, action)
	}

	// Attack Protection
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				generateAttackProtectionRules(rule, syscalls, action)
			}
		}
	}

	// Custom
	generateRawRules(enhanceProtect.SyscallRawRules, syscalls, &profile)

	// Add all selected built-in rules to profile.
	for _, syscall := range syscalls {
		profile.Syscalls = append(profile.Syscalls, syscall)
	}

	p, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	return string(p), nil
}

func GenerateDefenseInDepthProfile(defenseInDepth *varmor.DefenseInDepth, profile string) (string, error) {
	finalProfile := specs.LinuxSeccomp{}
	err := json.Unmarshal([]byte(profile), &finalProfile)
	if err != nil {
		return "", err
	}

	if defenseInDepth.AllowViolations {
		finalProfile.DefaultAction = specs.ActLog
	} else {
		finalProfile.DefaultAction = specs.ActErrno
	}

	finalProfile.Syscalls = append(finalProfile.Syscalls, defenseInDepth.Seccomp.SyscallRawRules...)

	p, err := json.Marshal(finalProfile)
	if err != nil {
		return "", err
	}
	return string(p), nil
}
