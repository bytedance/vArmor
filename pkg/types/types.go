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

package types

import (
	"time"
)

const (
	// K8sCriNamespace is the CRI namespace of Kubernetes
	K8sCriNamespace string = "k8s.io"

	// RuntimeEndpoint is the socket address of the containerd
	RuntimeEndpoint string = "/run/containerd/containerd.sock"

	// RuntimeTimeout is the timeout period when accessing the containerd server
	// to retrieve container and pod information
	RuntimeTimeout time.Duration = time.Second * 5

	// MaxTargetContainerCountForBpfLsm is the max count of target containers for BPF LSM,
	// it's equal to the OUTER_MAP_ENTRIES_MAX of BPF code
	MaxTargetContainerCountForBpfLsm int = 100

	// MaxBpfFileRuleCount is the max count of BPF file rules,
	// it's equal to the FILE_INNER_ENTRIES_MAX of BPF code
	MaxBpfFileRuleCount int = 50

	// MaxBpfBprmRuleCount is the max count of BPF process rules,
	// it's equal to the BPRM_INNER_MAP_ENTRIES_MAX of BPF code
	MaxBpfBprmRuleCount int = 50

	// MaxBpfNetworkRuleCount is the max count of BPF network rules,
	// it's equal to the NET_INNER_MAP_ENTRIES_MAX of BPF code
	MaxBpfNetworkRuleCount int = 50

	// MaxBpfMountRuleCount is the max count of BPF mount rules,
	// it's equal to the MOUNT_INNER_MAP_ENTRIES_MAX of BPF code
	MaxBpfMountRuleCount int = 50

	// MaxFilePathPatternLength is the max length of path pattern,
	// it's equal to the FILE_PATH_PATTERN_SIZE_MAX of BPF code
	MaxFilePathPatternLength int = 64

	// MaxFileSystemTypeLength is the max length of fstype pattern,
	// it's equal to the FILE_SYSTEM_TYPE_MAX of BPF code
	MaxFileSystemTypeLength int = 16
)

// ContainerInfo describes the information collected by the runtime monitor
type ContainerInfo struct {
	PID            uint32
	ContainerID    string
	ContainerName  string
	PodID          string
	PodName        string
	PodNamespace   string
	PodUID         string
	PodAnnotations map[string]string
}
