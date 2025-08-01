// Package common provides common functions for the status service
package common

import (
	"reflect"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func MergeAppArmorResult(apm *varmor.ArmorProfileModel, appArmor *varmor.AppArmor) {
	if appArmor == nil {
		return
	}

	if apm.Data.DynamicResult.AppArmor == nil {
		apm.Data.DynamicResult.AppArmor = &varmor.AppArmor{}
	}

	for _, newProfile := range appArmor.Profiles {
		find := false
		for _, profile := range apm.Data.DynamicResult.AppArmor.Profiles {
			if newProfile == profile {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Profiles = append(apm.Data.DynamicResult.AppArmor.Profiles, newProfile)
		}
	}

	for _, newExe := range appArmor.Executions {
		find := false
		for _, execution := range apm.Data.DynamicResult.AppArmor.Executions {
			if newExe == execution {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Executions = append(apm.Data.DynamicResult.AppArmor.Executions, newExe)
		}
	}

	for _, newFile := range appArmor.Files {
		findFile := false
		for index, file := range apm.Data.DynamicResult.AppArmor.Files {
			if newFile.Path == file.Path && newFile.Owner == file.Owner {
				findFile = true

				for _, newPerm := range newFile.Permissions {
					findPerm := false
					for _, perm := range file.Permissions {
						if newPerm == perm {
							findPerm = true
							break
						}
					}
					if !findPerm {
						apm.Data.DynamicResult.AppArmor.Files[index].Permissions = append(apm.Data.DynamicResult.AppArmor.Files[index].Permissions, newPerm)
					}
				}

				if file.OldPath == "" && newFile.OldPath != "" {
					apm.Data.DynamicResult.AppArmor.Files[index].OldPath = newFile.OldPath
				}
				break
			}
		}
		if !findFile {
			apm.Data.DynamicResult.AppArmor.Files = append(apm.Data.DynamicResult.AppArmor.Files, newFile)
		}
	}

	for _, newCap := range appArmor.Capabilities {
		find := false
		for _, cap := range apm.Data.DynamicResult.AppArmor.Capabilities {
			if newCap == cap {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Capabilities = append(apm.Data.DynamicResult.AppArmor.Capabilities, newCap)
		}
	}

	for _, newNet := range appArmor.Networks {
		find := false
		for _, net := range apm.Data.DynamicResult.AppArmor.Networks {
			if reflect.DeepEqual(newNet, net) {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Networks = append(apm.Data.DynamicResult.AppArmor.Networks, newNet)
		}
	}

	for _, newPtrace := range appArmor.Ptraces {
		find := false
		for index, ptrace := range apm.Data.DynamicResult.AppArmor.Ptraces {
			if newPtrace.Peer == ptrace.Peer {
				find = true

				for _, newPerm := range newPtrace.Permissions {
					findPerm := false
					for _, perm := range ptrace.Permissions {
						if newPerm == perm {
							findPerm = true
							break
						}
					}
					if !findPerm {
						apm.Data.DynamicResult.AppArmor.Ptraces[index].Permissions = append(apm.Data.DynamicResult.AppArmor.Ptraces[index].Permissions, newPerm)
					}
				}

				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Ptraces = append(apm.Data.DynamicResult.AppArmor.Ptraces, newPtrace)
		}
	}

	for _, newSignal := range appArmor.Signals {
		find := false
		for index, signal := range apm.Data.DynamicResult.AppArmor.Signals {
			if newSignal.Peer == signal.Peer {
				find = true

				for _, newPerm := range newSignal.Permissions {
					findPerm := false
					for _, perm := range signal.Permissions {
						if newPerm == perm {
							findPerm = true
							break
						}
					}
					if !findPerm {
						apm.Data.DynamicResult.AppArmor.Signals[index].Permissions = append(apm.Data.DynamicResult.AppArmor.Signals[index].Permissions, newPerm)
					}
				}

				for _, newSig := range newSignal.Signals {
					findSig := false
					for _, sig := range signal.Signals {
						if newSig == sig {
							findSig = true
							break
						}
					}
					if !findSig {
						apm.Data.DynamicResult.AppArmor.Signals[index].Signals = append(apm.Data.DynamicResult.AppArmor.Signals[index].Signals, newSig)
					}
				}

				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Signals = append(apm.Data.DynamicResult.AppArmor.Signals, newSignal)
		}
	}

	for _, newUnhandled := range appArmor.Unhandled {
		find := false
		for _, unhandled := range apm.Data.DynamicResult.AppArmor.Unhandled {
			if newUnhandled == unhandled {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Unhandled = append(apm.Data.DynamicResult.AppArmor.Unhandled, newUnhandled)
		}
	}
}

func MergeSeccompResult(apm *varmor.ArmorProfileModel, seccomp *varmor.Seccomp) {
	if seccomp == nil {
		return
	}

	if apm.Data.DynamicResult.Seccomp == nil {
		apm.Data.DynamicResult.Seccomp = &varmor.Seccomp{}
	}

	for _, newSyscall := range seccomp.Syscalls {
		find := false
		for _, syscall := range apm.Data.DynamicResult.Seccomp.Syscalls {
			if newSyscall == syscall {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.Seccomp.Syscalls = append(apm.Data.DynamicResult.Seccomp.Syscalls, newSyscall)
		}
	}
}
