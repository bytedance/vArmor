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
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"gotest.tools/assert"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func Test_generateRawRules(t *testing.T) {
	eperm1 := uint(1)
	eperm2 := uint(1)
	ebusy := uint(0x10)

	testCases := []struct {
		name             string
		syscallRawRules  []specs.LinuxSyscall
		syscalls         map[string]specs.LinuxSyscall
		expectedSyscalls map[string]specs.LinuxSyscall
		expectedProfile  specs.LinuxSeccomp
	}{
		{
			name: "ignoreRawRulesTest",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:    []string{"chmod", "fchmod"},
					Action:   specs.ActErrno,
					ErrnoRet: &eperm1,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"chmod": {
					Names:    []string{"chmod"},
					Action:   specs.ActErrno,
					ErrnoRet: &eperm2,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				"fchmod": {
					Names:    []string{"fchmod"},
					Action:   specs.ActErrno,
					ErrnoRet: &eperm2,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"chmod": {
					Names:    []string{"chmod"},
					Action:   specs.ActErrno,
					ErrnoRet: &eperm2,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				"fchmod": {
					Names:    []string{"fchmod"},
					Action:   specs.ActErrno,
					ErrnoRet: &eperm2,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls:      []specs.LinuxSyscall{},
			},
		},
		{
			name: "quadratureNamesTest",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"chmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"chmod"},
						Action: specs.ActErrno,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    1,
								Value:    unix.S_ISUID,
								ValueTwo: unix.S_ISUID,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
				},
			},
		},
		{
			name: "quadratureActionTest",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"fchmod"},
					Action: specs.ActKill,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"fchmod"},
						Action: specs.ActKill,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    1,
								Value:    unix.S_ISUID,
								ValueTwo: unix.S_ISUID,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
				},
			},
		},
		{
			name: "quadratureErrnoRetTest",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:    []string{"fchmod"},
					Action:   specs.ActErrno,
					ErrnoRet: &ebusy,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:    []string{"fchmod"},
						Action:   specs.ActErrno,
						ErrnoRet: &ebusy,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    1,
								Value:    unix.S_ISUID,
								ValueTwo: unix.S_ISUID,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
				},
			},
		},
		{
			name: "mergePartialRawRulesTest1",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"fchmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_IREAD,
							ValueTwo: unix.S_IREAD,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				{
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
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
						{
							Index:    1,
							Value:    unix.S_IREAD,
							ValueTwo: unix.S_IREAD,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
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
					},
				},
			},
		},
		{
			name: "mergePartialRawRulesTest2",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"fchmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_IREAD,
							ValueTwo: unix.S_IREAD,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				{
					Names:  []string{"fchmod"},
					Action: specs.ActKill,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    2,
							Value:    unix.S_IRWXU,
							ValueTwo: unix.S_IRWXU,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
						{
							Index:    1,
							Value:    unix.S_IREAD,
							ValueTwo: unix.S_IREAD,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"fchmod"},
						Action: specs.ActKill,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    2,
								Value:    unix.S_IRWXU,
								ValueTwo: unix.S_IRWXU,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
				},
			},
		},
		{
			name: "mergePartialRawRulesTest3",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"chmod", "fchmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_IREAD,
							ValueTwo: unix.S_IREAD,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				{
					Names:  []string{"fchmod"},
					Action: specs.ActKill,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    2,
							Value:    unix.S_IRWXU,
							ValueTwo: unix.S_IRWXU,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
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
						{
							Index:    1,
							Value:    unix.S_IREAD,
							ValueTwo: unix.S_IREAD,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"chmod"},
						Action: specs.ActErrno,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    1,
								Value:    unix.S_IREAD,
								ValueTwo: unix.S_IREAD,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
					{
						Names:  []string{"fchmod"},
						Action: specs.ActKill,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    2,
								Value:    unix.S_IRWXU,
								ValueTwo: unix.S_IRWXU,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
				},
			},
		},
		{
			name: "rawRulesWithEmptyArgsTest",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"chmod", "fchmod"},
					Action: specs.ActErrno,
					Args:   []specs.LinuxSeccompArg{},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"chmod": {
					Names:  []string{"chmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				"fchmod": {
					Names:  []string{"fchmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"chmod": {
					Names:  []string{"chmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
				"fchmod": {
					Names:  []string{"fchmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"chmod"},
						Action: specs.ActErrno,
						Args:   []specs.LinuxSeccompArg{},
					},
					{
						Names:  []string{"fchmod"},
						Action: specs.ActErrno,
						Args:   []specs.LinuxSeccompArg{},
					},
				},
			},
		},
		{
			name: "builtinRulesWithEmptyArgsTest",
			syscallRawRules: []specs.LinuxSyscall{
				{
					Names:  []string{"chmod", "fchmod"},
					Action: specs.ActErrno,
					Args: []specs.LinuxSeccompArg{
						{
							Index:    1,
							Value:    unix.S_ISUID,
							ValueTwo: unix.S_ISUID,
							Op:       specs.OpMaskedEqual,
						},
					},
				},
			},
			syscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
					Names:  []string{"fchmod"},
					Action: specs.ActErrno,
					Args:   []specs.LinuxSeccompArg{},
				},
			},
			expectedSyscalls: map[string]specs.LinuxSyscall{
				"fchmod": {
					Names:  []string{"fchmod"},
					Action: specs.ActErrno,
					Args:   []specs.LinuxSeccompArg{},
				},
			},
			expectedProfile: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{"chmod"},
						Action: specs.ActErrno,
						Args: []specs.LinuxSeccompArg{
							{
								Index:    1,
								Value:    unix.S_ISUID,
								ValueTwo: unix.S_ISUID,
								Op:       specs.OpMaskedEqual,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			profile := specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls:      []specs.LinuxSyscall{},
			}

			generateRawRules(tc.syscallRawRules, tc.syscalls, &profile)

			assert.Equal(t, true, reflect.DeepEqual(tc.syscalls, tc.expectedSyscalls))
			assert.Equal(t, true, reflect.DeepEqual(profile, tc.expectedProfile))
		})
	}
}
