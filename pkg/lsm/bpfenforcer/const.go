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

package bpfenforcer

const (
	// MaxTargetContainerCountForBpfLsm is the max count of target containers for BPF LSM,
	// it's equal to the OUTER_MAP_ENTRIES_MAX of BPF code
	MaxTargetContainerCountForBpfLsm int = 100

	// MaxBpfFileRuleCount is the max rule count of file operation primitive.
	MaxBpfFileRuleCount = 50

	// MaxBpfBprmRuleCount is the max rule count of execution file primitive.
	MaxBpfBprmRuleCount = 50

	// MaxBpfNetworkRuleCount is the max rule count of network access primitive.
	MaxBpfNetworkRuleCount = 50

	// MaxBpfMountRuleCount is the max rule count of mount operation primitive.
	MaxBpfMountRuleCount = 50

	// MaxFilePathPatternLength is the max length of path pattern,
	// it's equal to FILE_PATH_PATTERN_SIZE_MAX in BPF code
	MaxFilePathPatternLength = 64

	// PathPatternSize is the size of `struct path_pattern` in BPF code
	PathPatternSize = 4 + MaxFilePathPatternLength*2

	// PathRuleSize is the size of `struct path_rule` in BPF code, it's
	// also the value size of the inner map for file and execution access control.
	PathRuleSize = 4*2 + PathPatternSize

	// IpAddressSize is the size of IP address and mask.
	IpAddressSize = 16

	// NetRuleSize is the size of `struct net_rule` in BPF code, it's
	// also the value size of the inner map for network access control.
	NetRuleSize = 4*3 + IpAddressSize*2

	// MaxFileSystemTypeLength is the max length of fstype pattern,
	// it's equal to FILE_SYSTEM_TYPE_MAX in BPF code
	MaxFileSystemTypeLength = 16

	// MountRuleSize is the size of `struct mount_rule` in BPF code, it's
	// also the value size of the inner map for mount access control.
	MountRuleSize = 4*3 + MaxFileSystemTypeLength + PathPatternSize
)
