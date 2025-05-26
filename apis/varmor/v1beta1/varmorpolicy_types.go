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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
//+kubebuilder:resource:shortName=vpol
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="ENFORCER",type=string,JSONPath=`.spec.policy.enforcer`
//+kubebuilder:printcolumn:name="MODE",type=string,JSONPath=`.spec.policy.mode`
//+kubebuilder:printcolumn:name="TARGET-KIND",type=string,JSONPath=`.spec.target.kind`
//+kubebuilder:printcolumn:name="TARGET-NAME",type=string,JSONPath=`.spec.target.name`
//+kubebuilder:printcolumn:name="TARGET-SELECTOR",type=string,JSONPath=`.spec.target.selector`
//+kubebuilder:printcolumn:name="PROFILE-NAME",type=string,JSONPath=`.status.profileName`
//+kubebuilder:printcolumn:name="READY",type=boolean,JSONPath=`.status.ready`
//+kubebuilder:printcolumn:name="STATUS",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="AGE",type=date,JSONPath=`.metadata.creationTimestamp`

// VarmorPolicy is the Schema for the varmorpolicies API
// VarmorPolicy is a namespaced security policy for hardening the workloads in the same namespace.
type VarmorPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired policy to be used for hardening the target workloads.
	Spec VarmorPolicySpec `json:"spec"`
	// Status describes the observed status of the policy.
	Status VarmorPolicyStatus `json:"status,omitempty"`
}

//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true

// VarmorPolicyList contains a list of VarmorPolicy
type VarmorPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VarmorPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VarmorPolicy{}, &VarmorPolicyList{})
}
