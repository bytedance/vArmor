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

package seccomp

import (
	"encoding/base64"
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

func GenerateBehaviorModelingProfile() string {
	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActLog,
		Syscalls:      []specs.LinuxSyscall{defaultSyscall},
	}

	p, _ := json.Marshal(profile)
	return base64.StdEncoding.EncodeToString(p)
}

func GenerateProfileWithBehaviorModel(dynamicResult *varmor.DynamicResult) (string, error) {
	if len(dynamicResult.Seccomp.Syscall) == 0 {
		return "", nil
	}

	syscall := specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names:  dynamicResult.Seccomp.Syscall,
	}

	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{defaultSyscall, syscall},
	}

	p, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

func generateHardeningRules(rule string, syscalls map[string]specs.LinuxSyscall) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "disallow-create-user-ns":
		if _, ok := syscalls["unshare"]; !ok {
			syscalls["unshare"] = specs.LinuxSyscall{
				Names:  []string{"unshare"},
				Action: specs.ActErrno,
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
	}
}

func generateVulMitigationRules(rule string, syscalls map[string]specs.LinuxSyscall) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "dirty-pipe-mitigation":
		if _, ok := syscalls["splice"]; !ok {
			syscalls["splice"] = specs.LinuxSyscall{
				Names:  []string{"splice"},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{},
			}
		}
	}
}

func generateAttackProtectionRules(rule string, syscalls map[string]specs.LinuxSyscall) {
	rule = strings.ToLower(rule)
	rule = strings.ReplaceAll(rule, "_", "-")

	switch rule {
	case "disable-chmod-x-bit":
		if _, ok := syscalls["chmod"]; !ok {
			syscalls["chmod"] = specs.LinuxSyscall{
				Names:  []string{"chmod"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

		if _, ok := syscalls["fchmod"]; !ok {
			syscalls["fchmod"] = specs.LinuxSyscall{
				Names:  []string{"fchmod"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

		if _, ok := syscalls["fchmodat"]; !ok {
			syscalls["fchmodat"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

		if _, ok := syscalls["fchmodat2"]; !ok {
			syscalls["fchmodat2"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat2"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

	case "disable-chmod-s-bit":
		if _, ok := syscalls["chmod"]; !ok {
			syscalls["chmod"] = specs.LinuxSyscall{
				Names:  []string{"chmod"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

		if _, ok := syscalls["fchmod"]; !ok {
			syscalls["fchmod"] = specs.LinuxSyscall{
				Names:  []string{"fchmod"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

		if _, ok := syscalls["fchmodat"]; !ok {
			syscalls["fchmodat"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}

		if _, ok := syscalls["fchmodat2"]; !ok {
			syscalls["fchmodat2"] = specs.LinuxSyscall{
				Names:  []string{"fchmodat2"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
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
				},
			}
		}
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

	// Hardening
	for _, rule := range enhanceProtect.HardeningRules {
		generateHardeningRules(rule, syscalls)
	}

	// Vulnerability Mitigation
	for _, rule := range enhanceProtect.VulMitigationRules {
		generateVulMitigationRules(rule, syscalls)
	}

	// Attack Protection
	for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
		if len(attackProtectionRule.Targets) == 0 {
			for _, rule := range attackProtectionRule.Rules {
				generateAttackProtectionRules(rule, syscalls)
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
	return base64.StdEncoding.EncodeToString(p), nil
}
