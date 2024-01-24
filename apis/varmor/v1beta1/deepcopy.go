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

package v1beta1

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

func linuxSyscallDeepCopyInto(in *[]specs.LinuxSyscall, out *[]specs.LinuxSyscall) {
	for i := range *in {
		(*out)[i].Names = make([]string, len((*in)[i].Names))
		copy((*out)[i].Names, (*in)[i].Names)
		(*out)[i].Action = (*in)[i].Action
		if (*in)[i].ErrnoRet != nil {
			ret := *((*in)[i].ErrnoRet)
			(*out)[i].ErrnoRet = &ret
		}
		(*out)[i].Args = make([]specs.LinuxSeccompArg, len((*in)[i].Args))
		copy((*out)[i].Args, (*in)[i].Args)
	}
}
