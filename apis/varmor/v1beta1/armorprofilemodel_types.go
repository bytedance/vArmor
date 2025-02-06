/*
Copyright The Kubernetes Authors.

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

type File struct {
	Path        string   `json:"path"`
	Owner       bool     `json:"owner"`
	Permissions []string `json:"permissions"`
	OldPath     string   `json:"oldPath"`
}

type Network struct {
	Family   string `json:"family"`
	SockType string `json:"sockType"`
	Protocol string `json:"protocol"`
}

type Ptrace struct {
	Peer        string   `json:"peer"`
	Permissions []string `json:"permissions"`
}

type Signal struct {
	Peer        string   `json:"peer"`
	Permissions []string `json:"permissions"`
	Signals     []string `json:"signals"`
}

type AppArmor struct {
	Profiles     []string  `json:"profiles,omitempty"`
	Executions   []string  `json:"executions,omitempty"`
	Files        []File    `json:"files,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Networks     []Network `json:"networks,omitempty"`
	Ptraces      []Ptrace  `json:"ptraces,omitempty"`
	Signals      []Signal  `json:"signals,omitempty"`
	Unhandled    []string  `json:"unhandled,omitempty"`
}

type Seccomp struct {
	Syscalls []string `json:"syscalls,omitempty"`
}

type DynamicResult struct {
	AppArmor *AppArmor `json:"apparmor,omitempty"`
	Seccomp  *Seccomp  `json:"seccomp,omitempty"`
}

type StaticResult struct {
}

type StorageType string

// ArmorProfileModelData defines the behavior model and the profile
type ArmorProfileModelData struct {
	// DynamicResult stores the behavior data that has been collected with the BehaviorModeling mode.
	DynamicResult DynamicResult `json:"dynamicResult,omitempty"`
	// StaticResult stores the static analysis data.
	StaticResult StaticResult `json:"staticResult,omitempty"`
	// Profile stores the AppArmor and Seccomp profiles that are generate from the DynamicResult and StaticResult.
	Profile Profile `json:"profile,omitempty"`
	// StorageType indicates which storage type to use to save the DynamicResult, StaticResult and profiles.
	// Possible values: CRDInternal, LocalDisk
	StorageType StorageType `json:"storageType,omitempty"`
}

type ArmorProfileModelConditionType string

type ArmorProfileModelCondition struct {
	// Type of ArmorProfile condition.
	Type ArmorProfileModelConditionType `json:"type"`
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
	Message  string `json:"message,omitempty"`
	NodeName string `json:"nodeName"`
}

// ArmorProfileModelStatus defines the observed state of ArmorProfileModel
type ArmorProfileModelStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	DesiredNumber   int `json:"desiredNumber,omitempty"`
	CompletedNumber int `json:"completedNumber,omitempty"`
	// It indicate whether the AppArmor Profile for target is built successfully
	Ready      bool                         `json:"ready"`
	Conditions []ArmorProfileModelCondition `json:"conditions,omitempty"`
}

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="STORAGE-TYPE",type=string,JSONPath=`.data.storageType`
//+kubebuilder:printcolumn:name="DESIRED",type=integer,JSONPath=`.status.desiredNumber`
//+kubebuilder:printcolumn:name="COMPLETED",type=integer,JSONPath=`.status.completedNumber`
//+kubebuilder:printcolumn:name="READY",type=boolean,JSONPath=`.status.ready`
//+kubebuilder:printcolumn:name="AGE",type=date,JSONPath=`.metadata.creationTimestamp`

// ArmorProfileModel is the Schema for the armorprofilemodels API
type ArmorProfileModel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Data   ArmorProfileModelData   `json:"data"`
	Status ArmorProfileModelStatus `json:"status,omitempty"`
}

//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true

// ArmorProfileModelList contains a list of ArmorProfileModel
type ArmorProfileModelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArmorProfileModel `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArmorProfileModel{}, &ArmorProfileModelList{})
}
