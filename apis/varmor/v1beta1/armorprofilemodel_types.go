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

type File struct {
	Path        string   `json:"path"`
	Owner       bool     `json:"owner,omitempty"`
	Permissions []string `json:"permissions"`
	OldPath     string   `json:"oldPath,omitempty"`
}

type Socket struct {
	Domain   string `json:"domain,omitempty"`
	Type     string `json:"type,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type Address struct {
	IP    string   `json:"ip"`
	Ports []uint16 `json:"ports"`
}

type Network struct {
	Sockets  []Socket  `json:"sockets,omitempty"`
	Egresses []Address `json:"egresses,omitempty"`
}

type Ptrace struct {
	Peer        string   `json:"peer,omitempty"`
	Permissions []string `json:"permissions"`
	External    bool     `json:"external,omitempty"`
}

type Signal struct {
	Peer        string   `json:"peer"`
	Permissions []string `json:"permissions"`
	Signals     []string `json:"signals"`
}

type AppArmor struct {
	Profiles     []string `json:"profiles,omitempty"`
	Executions   []string `json:"executions,omitempty"`
	Files        []File   `json:"files,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Network      *Network `json:"networks,omitempty"`
	Ptraces      []Ptrace `json:"ptraces,omitempty"`
	Signals      []Signal `json:"signals,omitempty"`
	Unhandled    []string `json:"unhandled,omitempty"`
}

type Mount struct {
	Path  string   `json:"path"`
	Type  string   `json:"type,omitempty"`
	Flags []string `json:"flags,omitempty"`
}

type BPF struct {
	Executions   []string `json:"executions,omitempty"`
	Files        []File   `json:"files,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Network      *Network `json:"network,omitempty"`
	Ptraces      []Ptrace `json:"ptraces,omitempty"`
	Mounts       []Mount  `json:"mounts,omitempty"`
}

type Seccomp struct {
	Syscalls []string `json:"syscalls,omitempty"`
}

type DynamicResult struct {
	// AppArmor contains the AppArmor behavior data collected.
	AppArmor *AppArmor `json:"apparmor,omitempty"`
	// BPF contains the BPF behavior data collected.
	BPF *BPF `json:"bpf,omitempty"`
	// Seccomp contains the syscalls collected.
	Seccomp *Seccomp `json:"seccomp,omitempty"`
}

type StaticResult struct {
}

// StorageType indicates which storage type to use to save the DynamicResult, StaticResult and profiles.
// +enum
type StorageType string

const (
	// StorageTypeCRDInternal indicates that the data is stored in the CRD object itself.
	StorageTypeCRDInternal StorageType = "CRDInternal"
	// StorageTypeLocalDisk indicates that the data is stored in the local disk.
	StorageTypeLocalDisk StorageType = "LocalDisk"
	// StorageTypePVPVC indicates that the data is stored in a Persistent Volume.
	StorageTypePVPVC StorageType = "PV/PVC"
)

type ArmorProfileModelData struct {
	// DynamicResult stores the behavior data that has been collected with the BehaviorModeling mode.
	DynamicResult DynamicResult `json:"dynamicResult,omitempty"`
	// StaticResult stores the static analysis data.
	StaticResult StaticResult `json:"staticResult,omitempty"`
	// Profile stores profiles that are generate from the DynamicResult and StaticResult.
	Profile Profile `json:"profile,omitempty"`
}

// ArmorProfileModelConditionType defines the type of condition for ArmorProfileModel.
// +enum
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
	Message string `json:"message,omitempty"`
	// The name of the node where the condition is applicable.
	NodeName string `json:"nodeName"`
}

type ArmorProfileModelStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// desiredNumber is the number of desired results to be received from the agents.
	// It is used to determine whether the modeling is completed.
	DesiredNumber int32 `json:"desiredNumber,omitempty"`
	// completedNumber is the number of results that have been received from the agents.
	// It is used to determine whether the modeling is completed.
	CompletedNumber int32 `json:"completedNumber,omitempty"`
	// ready indicate whether the profile is generated and ready to use.
	Ready bool `json:"ready"`
	// conditions is a list of conditions that are used to indicate the status of the ArmorProfileModel.
	Conditions []ArmorProfileModelCondition `json:"conditions,omitempty"`
}

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="STORAGE-TYPE",type=string,JSONPath=`.storageType`
//+kubebuilder:printcolumn:name="DESIRED",type=integer,JSONPath=`.status.desiredNumber`
//+kubebuilder:printcolumn:name="COMPLETED",type=integer,JSONPath=`.status.completedNumber`
//+kubebuilder:printcolumn:name="READY",type=boolean,JSONPath=`.status.ready`
//+kubebuilder:printcolumn:name="AGE",type=date,JSONPath=`.metadata.creationTimestamp`

// ArmorProfileModel is the Schema for the armorprofilemodels API
// ArmorProfileModel is used to store the behavior model and the profiles generated from the DynamicResult and StaticResult.
type ArmorProfileModel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// storageType indicates which storage type to use to save the DynamicResult, StaticResult and profiles.
	// Possible values: CRDInternal, LocalDisk
	StorageType StorageType `json:"storageType,omitempty"`
	// data contains the behavior model and the profiles.
	// It is used to store the DynamicResult, StaticResult and the generated profiles.
	Data ArmorProfileModelData `json:"data"`
	// status defines the observed state of ArmorProfileModel
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
