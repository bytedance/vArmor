// Copyright 2021-2023 vArmor Authors
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

// Package types defines the types used in vArmor.
package types

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// Enforcer represents policy enforcement mechanisms.
type Enforcer int

const (
	// Enforcer types
	AppArmor     Enforcer = 0x00000001
	BPF          Enforcer = 0x00000002
	Seccomp      Enforcer = 0x00000004
	NetworkProxy Enforcer = 0x00000008
	Unknown      Enforcer = 0x00000010

	// AppArmor Profile process Status
	Succeeded Status = "succeeded"
	Failed    Status = "failed"

	// AgentLabelSelector is the label selector for agents.
	AgentLabelSelector string = "app.kubernetes.io/component=varmor-agent"

	// Event type for the bpf tracer
	SchedProcessFork uint32 = 1
	SchedProcessExec uint32 = 2

	// ReconcileAnnotation control whether to force agents to update the profile
	ReconcileAnnotation string = "profile-reconcile-counter"

	// DefaultProxyUID is the default UID which the proxy sidecar process runs as
	DefaultProxyUID int64 = 1337
	// DefaultProxyPort is the default listen port which the proxy sidecar process listens on
	DefaultProxyPort uint16 = 15001
	// DefaultProxyAdminPort is the default listen port which the proxy sidecar process listens on for admin requests
	DefaultProxyAdminPort uint16 = 15000
	// DefaultProxyInitImage is the default init image for the proxy sidecar process
	ProxyInitImage = "elkeid-test-cn-beijing.cr.volces.com/public/iptables:0.1"
	// DefaultProxyImage is the default image for the proxy sidecar process
	ProxyImage = "elkeid-test-cn-beijing.cr.volces.com/public/envoy:v1.32-latest"
)

type Status string

// ProfileStatus describes the process result of an ArmorProfile object by agents.
type ProfileStatus struct {
	Namespace   string `json:"namespace"`
	ProfileName string `json:"armorProfile"` //  varmor-{namespace}-{name} or varmor-cluster-{namespace}-{name}
	NodeName    string `json:"nodeName"`
	Status      Status `json:"status"`
	Message     string `json:"message"`
}

// PolicyStatus used to cache the status of ArmorProfile and VarmorProfile objects.
type PolicyStatus struct {
	SuccessedNumber int32
	FailedNumber    int32
	NodeMessages    map[string]string // Use NodeName as its key
}

// BehaviorData describes the behavior data of the target container that collected by agents.
type BehaviorData struct {
	Namespace     string               `json:"namespace"`
	ProfileName   string               `json:"armorProfile"` //  varmor-{namespace}-{name}
	DynamicResult varmor.DynamicResult `json:"dynamicResult"`
	NodeName      string               `json:"nodeName"`
	Status        Status               `json:"status"`
	Message       string               `json:"message"`
}

// ModelingStatus used to cache the status of ArmorProfileModel objects.
type ModelingStatus struct {
	CompletedNumber int32
	FailedNumber    int32
	NodeMessages    map[string]string // Use NodeName as its key
}

func GetEnforcerType(enforcer string) Enforcer {
	t := Enforcer(0)

	enforcer = strings.ToLower(enforcer)
	if strings.Contains(enforcer, "apparmor") {
		t |= AppArmor
	}
	if strings.Contains(enforcer, "bpf") {
		t |= BPF
	}
	if strings.Contains(enforcer, "seccomp") {
		t |= Seccomp
	}
	if strings.Contains(enforcer, "networkproxy") {
		t |= NetworkProxy
	}

	if t == 0 {
		return Unknown
	} else {
		return t
	}
}

// Pod saves the rule for matching the traffic of pods
type Pod struct {
	Mode        uint32
	Namespace   string
	PodSelector *metav1.LabelSelector
	Ports       []varmor.Port
}

// Service saves the rule for matching the traffic of services and endpointslices
type Service struct {
	Mode            uint32
	Namespace       string
	Name            string
	ServiceSelector *metav1.LabelSelector
}

// EgressInfo caches the pod and service rules that a policy wants to match.
type EgressInfo struct {
	ToPods     []Pod
	ToServices []Service
}
