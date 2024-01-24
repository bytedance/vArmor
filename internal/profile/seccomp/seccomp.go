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

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, profileName string) (string, error) {
	if enhanceProtect.Privileged {
		return "", nil
	}

	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls:      []specs.LinuxSyscall{},
	}

	// Custom
	profile.Syscalls = append(profile.Syscalls, enhanceProtect.SyscallRawRules...)

	p, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}
