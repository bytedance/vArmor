/*
Copyright The vArmor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

type SeccompProfile struct {
	// profileType indicates which kind of Seccomp profile will be applied. Valid options are:
	// BehaviorModel - a profile generated via the BehaviorModeling mode will be used.
	// Custom - a custom profile defined in the customProfile field will be used.
	ProfileType ProfileType `json:"profileType"`
	// customProfile holds the user-defined Seccomp profile content. It must be a valid profile that
	// adheres to Seccomp syntax.
	// See https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp
	// +optional
	CustomProfile string `json:"customProfile,omitempty"`
	// syscallRawRules specifies custom Seccomp rules. These rules will be added to the end of the
	// Seccomp profile that you specified.
	// +optional
	SyscallRawRules []specs.LinuxSyscall `json:"syscallRawRules,omitempty"`
}
