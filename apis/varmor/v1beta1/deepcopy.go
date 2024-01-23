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
