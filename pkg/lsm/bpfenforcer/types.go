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

type pathPattern struct {
	Flags  uint32
	Prefix [MaxFilePathPatternLength]byte
	Suffix [MaxFilePathPatternLength]byte
}

// bpfPathRule is the rule definition of file policy primitive
type bpfPathRule struct {
	Mode        uint32
	Permissions uint32
	Pattern     pathPattern
}

// bpfNetworkRule is the rule definition of network policy primitive
type bpfNetworkRule struct {
	Mode    uint32
	Flags   uint32
	Address [IpAddressSize]byte
	Mask    [IpAddressSize]byte
	Port    uint32
}

// bpfMountRule is the rule definition of mount policy primitive
type bpfMountRule struct {
	Mode              uint32
	MountFlags        uint32
	ReverseMountFlags uint32
	Fstype            [MaxFileSystemTypeLength]byte
	Pattern           pathPattern
}

// Audit Event
type EventType uint32

type BpfEvent struct {
	Header BpfEventHeader
	Body   interface{}
}

type BpfEventHeader struct {
	Mode  uint32
	Type  EventType
	MntNs uint32
	Tgid  uint32
	Ktime uint64
}

type BpfCapabilityEvent struct {
	Capability uint32
}

type BpfPathEvent struct {
	Permissions uint32
	Path        [4096]byte
	Padding     [20]byte
}

type BpfNetworkEvent struct {
	SaFamily uint32
	SinAddr  uint32
	Sin6Addr [16]byte
	Port     uint32
}

type BpfPtraceEvent struct {
	Permissions uint32
	External    bool
}

type BpfMountEvent struct {
	DevName [4096]byte
	Type    [16]byte
	Flags   uint32
}
