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

// Package types defines the types used in vArmor
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
)

// ContainerInfo describes the information collected by the runtime monitor
type ContainerInfo struct {
	PID            uint32
	MntNsID        uint32
	ContainerID    string
	ContainerName  string
	PodID          string
	PodUID         string
	PodName        string
	PodNamespace   string
	PodIPs         []string
	PodAnnotations map[string]string
	Image          string
	ProfileName    string
}
