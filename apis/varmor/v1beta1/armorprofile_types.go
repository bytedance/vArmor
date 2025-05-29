/*
Copyright The vArmor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type profileMode string

const (
	ProfileModeEnforce  profileMode = "enforce"
	ProfileModeComplain profileMode = "complain"
)

type CapabilitiesContent struct {
	Mode         uint32 `json:"mode,omitempty"`
	Capabilities uint64 `json:"capabilities"`
}

type PathPattern struct {
	Flags  uint32 `json:"flags"`
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
}

type FileContent struct {
	Mode        uint32      `json:"mode,omitempty"`
	Permissions uint32      `json:"permissions"`
	Pattern     PathPattern `json:"pattern"`
}

type NetworkAddress struct {
	IP      string   `json:"ip,omitempty"`
	CIDR    string   `json:"cidr,omitempty"`
	Port    uint16   `json:"port,omitempty"`
	EndPort uint16   `json:"endPort,omitempty"`
	Ports   []uint16 `json:"ports,omitempty"`
}

type NetworkSocket struct {
	Domains   uint64 `json:"domains,omitempty"`
	Types     uint64 `json:"types,omitempty"`
	Protocols uint64 `json:"protocols,omitempty"`
}

type NetworkContent struct {
	Mode    uint32          `json:"mode,omitempty"`
	Flags   uint32          `json:"flags"`
	Socket  *NetworkSocket  `json:"socket,omitempty"`
	Address *NetworkAddress `json:"address,omitempty"`
}

type PtraceContent struct {
	Mode        uint32 `json:"mode,omitempty"`
	Permissions uint32 `json:"permissions,omitempty"`
	Flags       uint32 `json:"flags,omitempty"`
}

type MountContent struct {
	Mode              uint32      `json:"mode,omitempty"`
	MountFlags        uint32      `json:"mountFlags"`
	ReverseMountflags uint32      `json:"reverseMountflags"`
	Pattern           PathPattern `json:"pattern"`
	Fstype            string      `json:"fstype"`
}

type BpfContent struct {
	Capabilities *CapabilitiesContent `json:"capabilities,omitempty"`
	Files        []FileContent        `json:"files,omitempty"`
	Processes    []FileContent        `json:"processes,omitempty"`
	Networks     []NetworkContent     `json:"networks,omitempty"`
	Ptrace       *PtraceContent       `json:"ptrace,omitempty"`
	Mounts       []MountContent       `json:"mounts,omitempty"`
}

type Profile struct {
	Name           string      `json:"name"`
	Enforcer       string      `json:"enforcer"`
	Mode           profileMode `json:"mode"`
	Content        string      `json:"content,omitempty"`
	BpfContent     *BpfContent `json:"bpfContent,omitempty"`
	SeccompContent string      `json:"seccompContent,omitempty"`
}

type BehaviorModeling struct {
	// Enable is the switch for modeling
	Enable bool `json:"enable"`
	// Duration is the duration in minutes to modeling
	Duration int `json:"duration"`
}

type ArmorProfileSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Target                  Target           `json:"target,omitempty"`
	Profile                 Profile          `json:"profile"`
	BehaviorModeling        BehaviorModeling `json:"behaviorModeling"`
	UpdateExistingWorkloads bool             `json:"updateExistingWorkloads"`
}

// ArmorProfileConditionType defines the type of condition for ArmorProfile.
// +enum
type ArmorProfileConditionType string

const (
	// ArmorProfileReady indicates that the ArmorProfile is ready.
	// This condition is set to True when the desired number of profiles are loaded and the conditions are met.
	ArmorProfileReady ArmorProfileConditionType = "Ready"
	// ArmorProfileModelReady indicates that the ArmorProfileModel is ready.
	// This condition is set to True when the model has been successfully created and is ready for use.
	ArmorProfileModelReady ArmorProfileModelConditionType = "Ready"
)

type ArmorProfileCondition struct {
	// Type of condition.
	Type ArmorProfileConditionType `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status v1.ConditionStatus `json:"status"`
	// Last time the condition transitioned from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// A human readable message indicating details about the transition.
	// +optional
	Message string `json:"message,omitempty"`
	// NodeName is the name of the node where the condition is applicable.
	NodeName string `json:"nodeName"`
}

type ArmorProfileStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// DesiredNumberLoaded is the desired number of profiles that should be loaded.
	DesiredNumberLoaded int32 `json:"desiredNumberLoaded"`
	// CurrentNumberLoaded is the current number of profiles that are loaded.
	CurrentNumberLoaded int32 `json:"currentNumberLoaded"`
	// Conditions is a list of conditions that describe the state of the ArmorProfile.
	Conditions []ArmorProfileCondition `json:"conditions,omitempty"`
}

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="PROFILE",type=string,JSONPath=`.spec.profile.name`
//+kubebuilder:printcolumn:name="ENFORCER",type=string,JSONPath=`.spec.profile.enforcer`
//+kubebuilder:printcolumn:name="MODE",type=string,JSONPath=`.spec.profile.mode`
//+kubebuilder:printcolumn:name="DESIRED",type=integer,JSONPath=`.status.desiredNumberLoaded`
//+kubebuilder:printcolumn:name="CURRENT",type=integer,JSONPath=`.status.currentNumberLoaded`
//+kubebuilder:printcolumn:name="AGE",type=date,JSONPath=`.metadata.creationTimestamp`

// ArmorProfile is the Schema for the armorprofiles API
// It's an internal interface, used by vArmor only.
type ArmorProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the profiles for hardening target workloads.
	Spec ArmorProfileSpec `json:"spec"`
	// Status defines the observed state of ArmorProfile
	Status ArmorProfileStatus `json:"status,omitempty"`
}

//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true

// ArmorProfileList contains a list of ArmorProfile
type ArmorProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArmorProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArmorProfile{}, &ArmorProfileList{})
}
