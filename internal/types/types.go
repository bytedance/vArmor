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

package types

import (
	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

const (
	// VarmorPolicy Mode
	AlwaysAllowMode    varmor.VarmorPolicyMode = "AlwaysAllow"
	RuntimeDefaultMode varmor.VarmorPolicyMode = "RuntimeDefault"
	EnhanceProtectMode varmor.VarmorPolicyMode = "EnhanceProtect"
	CustomPolicyMode   varmor.VarmorPolicyMode = "CustomPolicy"
	DefenseInDepthMode varmor.VarmorPolicyMode = "DefenseInDepth"

	// VarmorPolicy Phase
	VarmorPolicyPending    varmor.VarmorPolicyPhase = "Pending"
	VarmorPolicyModeling   varmor.VarmorPolicyPhase = "Modeling"
	VarmorPolicyCompleted  varmor.VarmorPolicyPhase = "Completed"
	VarmorPolicyProtecting varmor.VarmorPolicyPhase = "Protecting"
	VarmorPolicyError      varmor.VarmorPolicyPhase = "Error"
	VarmorPolicyFailed     varmor.VarmorPolicyPhase = "Failed"
	VarmorPolicyUnknown    varmor.VarmorPolicyPhase = "Unknown"
	VarmorPolicyUnchanged  varmor.VarmorPolicyPhase = "Unchanged"

	// VarmorPolicy Condition Type
	VarmorPolicyCreated varmor.VarmorPolicyConditionType = "Created"
	VarmorPolicyUpdated varmor.VarmorPolicyConditionType = "Updated"

	// ArmorProfile Condition Type
	ArmorProfileReady      varmor.ArmorProfileConditionType      = "Ready"
	ArmorProfileModelReady varmor.ArmorProfileModelConditionType = "Ready"

	// AppArmor Profile process Status
	Succeeded Status = "succeeded"
	Failed    Status = "failed"

	// AgentLabelSelector is the label selector for agents.
	AgentLabelSelector string = "app.kubernetes.io/component=varmor-agent"
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
	SuccessedNumber int
	FailedNumber    int
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
	CompletedNumber int
	FailedNumber    int
	NodeMessages    map[string]string // Use NodeName as its key
}

type AaLogRecord struct {
	Resource      string
	ActiveHat     string
	AaMode        string
	Time          int64
	Operation     string
	Profile       string
	Name          string
	Name2         string
	Attr          string
	Parent        uint64
	Pid           uint64
	Task          uint64
	Info          string
	ErrorCode     int32
	DeniedMask    string
	RequestedMask string
	MagicToken    uint64
	Family        string
	Protocol      string
	SockType      string
	Fsuid         uint64
	Ouid          uint64
	Signal        string
	Peer          string
	PeerProfile   string
	Bus           string
	Path          string
	Interface     string
	Member        string
}
