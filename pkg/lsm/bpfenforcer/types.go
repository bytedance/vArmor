// Copyright 2023 vArmor Authors
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

package bpfenforcer

import varmortypes "github.com/bytedance/vArmor/pkg/types"

type pathPattern struct {
	Flags  uint32
	Prefix [varmortypes.MaxFilePathPatternLength]byte
	Suffix [varmortypes.MaxFilePathPatternLength]byte
}

type bpfPathRule struct {
	Permissions uint32
	Pattern     pathPattern
}

type bpfNetworkRule struct {
	Flags   uint32
	Address [16]byte
	Mask    [16]byte
	Port    uint32
}

type bpfMountRule struct {
	MountFlags        uint32
	ReverseMountFlags uint32
	Fstype            [varmortypes.MaxFileSystemTypeLength]byte
	Pattern           pathPattern
}
