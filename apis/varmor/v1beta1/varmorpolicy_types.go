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

// Target Structure
type Target struct {
	// Kind is used to specify the type of workloads for the protection targets.
	// Available values: Deployment, StatefulSet, DaemonSet, Pod.
	Kind string `json:"kind"`
	// Name is used to specify a specific workload name.
	Name string `json:"name,omitempty"`
	// Containers are used to specify the names of the protected containers. If it is empty, sandbox protection
	// will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).
	Containers []string `json:"containers,omitempty"`
	// LabelSelector is used to match workloads that meet the specified conditions (Note: the type of workloads
	// is determined by the KIND field)
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// MatchSourceType Structure
type MatchSourceType struct {
	Path      string `json:"path,omitempty"`
	Directory string `json:"dir,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

// ProcessPathType Structure
type ProcessPathType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Path       string            `json:"path"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// ProcessDirectoryType Structure
type ProcessDirectoryType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Directory  string            `json:"dir"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// ProcessPatternType Structure
type ProcessPatternType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Pattern   string `json:"pattern"`
	OwnerOnly bool   `json:"ownerOnly,omitempty"`

	Action string `json:"action,omitempty"`
}

// ProcessType Structure
type ProcessType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchPaths       []ProcessPathType      `json:"matchPaths,omitempty"`
	MatchDirectories []ProcessDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []ProcessPatternType   `json:"matchPatterns,omitempty"`

	Action string `json:"action,omitempty"`
}

// FilePathType Structure
type FilePathType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Path       string            `json:"path"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// FileDirectoryType Structure
type FileDirectoryType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Directory  string            `json:"dir"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// FilePatternType Structure
type FilePatternType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Pattern   string `json:"pattern"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	OwnerOnly bool   `json:"ownerOnly,omitempty"`

	Action string `json:"action,omitempty"`
}

// FileType Structure
type FileType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchPaths       []FilePathType      `json:"matchPaths,omitempty"`
	MatchDirectories []FileDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []FilePatternType   `json:"matchPatterns,omitempty"`

	Action string `json:"action,omitempty"`
}

// NetworkProtocolType Structure
type NetworkProtocolType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Protocol   string            `json:"protocol"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// NetworkType Structure
type NetworkType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchProtocols []NetworkProtocolType `json:"matchProtocols,omitempty"`

	Action string `json:"action,omitempty"`
}

// CapabilitiesCapabilityType Structure
type CapabilitiesCapabilityType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Capability string            `json:"capability"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// CapabilitiesType Structure
type CapabilitiesType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchCapabilities []CapabilitiesCapabilityType `json:"matchCapabilities,omitempty"`

	Action string `json:"action,omitempty"`
}

// See SecuritySpec in https://github.com/kubearmor/KubeArmor/blob/main/KubeArmor/types/types.go
type CustomPolicy struct {
	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`
	// AppArmor Profile Raw Rules
	AppArmor string `json:"apparmor,omitempty"`
	Action   string `json:"action"`
}

type AttackProtectionRules struct {
	// Rules is the list of built-in attack protection rules to be used.
	Rules []string `json:"rules"`
	// Targets are used to specify the workloads to which the policy applies. They must be specified as full paths to executable files,
	// and this feature is only effective when using AppArmor as the enforcer.
	Targets []string `json:"targets,omitempty"`
}

type FileRule struct {
	// Pattern can be any string (maximum length 64 bytes) that conforms to the policy syntax, used for matching file paths and filenames
	Pattern string `json:"pattern"`
	// Permissions are used to specify the file permissions to be disabled.
	Permissions []string `json:"permissions"`
}

type NetworkEgressRule struct {
	// IPBlock defines policy on a particular IPBlock with CIDR. If this field is set then neither of the IP field can be.
	IPBlock string `json:"ipBlock,omitempty"`
	// IP defines policy on a particular IP. If this field is set then neither of the IPBlock field can be.
	IP string `json:"ip,omitempty"`
	// Port defines policy on a particular port. If this field is zero or missing, this rule matches all ports.
	Port int `json:"port,omitempty"`
}

type NetworkRule struct {
	// Egresses are the list of egress rules to be applied to restrict particular IPs and ports.
	Egresses []NetworkEgressRule `json:"egresses"`
}

type PtraceRule struct {
	// StrictMode is used to indicate whether to restrict ptrace permissions for all source and destination processes.
	//     Default: false
	//     If set to false, it restricts ptrace-related permissions only for processes in other containers.
	//     If set to true, it restricts ptrace-related permissions for all processes, except those within the init mnt namespace.
	StrictMode bool `json:"strictMode,omitempty"`
	// Permissions are used to indicate which ptrace-related permissions of the target container should be restricted.
	// Available values: trace, traceby, read, readby.
	//
	// trace, traceby
	//    For "write" operations, or other operations that are more dangerous, such as: ptrace attaching (PTRACE_ATTACH) to
	//    another process or calling process_vm_writev(2).
	// read, readby
	//    For "read" operations or other operations that are less dangerous, such as: get_robust_list(2); kcmp(2); reading
	//    /proc/pid/auxv, /proc/pid/environ, or /proc/pid/stat; or readlink(2) of a /proc/pid/ns/* file.
	//
	Permissions []string `json:"permissions"`
}

type MountRule struct {
	// SourcePattern can be any string (maximum length 64 bytes) that conforms to the policy syntax, used for matching file paths and filenames
	SourcePattern string `json:"sourcePattern"`
	// Fstype is used to specify the type of filesystem to enforce. It can be '*' to match any type.
	Fstype string `json:"fstype"`
	// Flags are used to specify the mount flags to enforce. They are almost the same as the 'MOUNT FLAGS LIST' of AppArmor.
	//
	// Available values:
	//
	//       All Flags: all
	//   Command Flags: ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec,
	//                  sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime,
	//                  silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime
	//   Generic Flags: remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave),
	//                  make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared
	//
	Flags []string `json:"flags"`
}

type BpfRawRules struct {
	Files     []FileRule  `json:"files,omitempty"`
	Processes []FileRule  `json:"processes,omitempty"`
	Network   NetworkRule `json:"network,omitempty"`
	Ptrace    PtraceRule  `json:"ptrace,omitempty"`
	Mounts    []MountRule `json:"mounts,omitempty"`
}

type EnhanceProtect struct {
	// HardeningRules are used to specify the built-in hardening rules
	HardeningRules []string `json:"hardeningRules,omitempty"`
	// AttackProtectionRules are used to specify the built-in attack protection rules
	AttackProtectionRules []AttackProtectionRules `json:"attackProtectionRules,omitempty"`
	// VulMitigationRules are used to specify the built-in vulnerability mitigation rules
	VulMitigationRules []string `json:"vulMitigationRules,omitempty"`
	// AppArmorRawRules is used to set native AppArmor rules, each rule must end with a comma
	AppArmorRawRules []string `json:"appArmorRawRules,omitempty"`
	// BpfRawRules is used to set native BPF rules
	BpfRawRules BpfRawRules `json:"bpfRawRules,omitempty"`
}

type DefenseInDepth struct {
	// ModelingDuration is the duration in minutes to modeling
	ModelingDuration int `json:"modelingDuration"`
	// AutoEnable decides whether or not to enable the access control after modeling is complete
	AutoEnable bool `json:"autoEnable,omitempty"`
}

type VarmorPolicyMode string

type Policy struct {
	// Enforcer is used to specify which LSM to use for mandatory access control.
	// Available values: AppArmor, BPF
	Enforcer string `json:"enforcer"`
	// Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, CustomPolicy, DefenseInDepth
	Mode VarmorPolicyMode `json:"mode"`
	// EnhanceProtect is used for building a policy for Hardening & AttackProtection & VulMitigation rules from templates.
	EnhanceProtect EnhanceProtect `json:"enhanceProtect,omitempty"`
	// [Experimental] CustomPolicy is almost the same as KubeArmor's SecuritySpec to increase compatibility.
	// Only worked with the AppArmor enforcer.
	CustomPolicy CustomPolicy `json:"customPolicy,omitempty"`
	// [Experimental] DefenseInDepth is used for the defense-in-depth sandbox features.
	// Only worked with the AppArmor enforcer.
	DefenseInDepth DefenseInDepth `json:"defenseInDepth,omitempty"`
	// Privileged is used to identify whether the policy is for the privileged container.
	// Only used for the AppArmor enforcer.
	Privileged bool `json:"privileged,omitempty"`
}

// VarmorPolicySpec defines the desired state of VarmorPolicy
type VarmorPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// A label query over ArmorProfile that are managed by VarmorPolicy.
	// Must match in order to be controlled.
	// It must match the VarmorPolicy's labels.
	Target Target `json:"target"`
	Policy Policy `json:"policy"`
}

type VarmorPolicyConditionType string

type VarmorPolicyCondition struct {
	// Type of ArmorProfile condition.
	Type VarmorPolicyConditionType `json:"type"`
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
}

type VarmorPolicyPhase string

// VarmorPolicyStatus defines the observed state of VarmorPolicy
type VarmorPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	ProfileName string `json:"profileName"`
	// Conditions
	Conditions []VarmorPolicyCondition `json:"conditions,omitempty"`
	// Ready is used to indicate whether the profile of policy is loaded.
	Ready bool `json:"ready"`
	// Phase is used to indicate the processing phase of the policy.
	// Possible values: Pending, Modeling, Completed, Protecting, Error.
	// (Note: You can find out which varmor-agent has an error by reading the ArmorProfile/status corresponding to the current VarmorPolicy)
	Phase VarmorPolicyPhase `json:"phase,omitempty"`
}

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
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
type VarmorPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VarmorPolicySpec   `json:"spec,omitempty"`
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
