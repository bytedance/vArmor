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
	"github.com/opencontainers/runtime-spec/specs-go"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type Target struct {
	// Kind is used to specify the type of workloads for the protection targets.
	// Available values: Deployment, StatefulSet, DaemonSet, Pod.
	Kind string `json:"kind"`
	// Name is used to specify a specific workload name.
	// +optional
	Name string `json:"name,omitempty"`
	// Containers are used to specify the names of the protected containers. If it is empty, sandbox protection
	// will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).
	// +optional
	Containers []string `json:"containers,omitempty"`
	// LabelSelector is used to match workloads that meet the specified conditions.
	// Note that the selector field and name field are mutually exclusive.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

type AttackProtectionRules struct {
	// Rules is the list of built-in attack protection rules to be used.
	Rules []string `json:"rules"`
	// Targets specify the executable files for which the rules and rawRules apply.
	// They must be specified as full paths to the executable files.
	// This feature is only effective when using AppArmor as the enforcer.
	// +optional
	Targets []string `json:"targets,omitempty"`
}

type FileRule struct {
	// Pattern can be any string (maximum length 128 bytes) that conforms to the policy syntax,
	// used for matching file paths and filenames
	Pattern string `json:"pattern"`
	// Permissions are used to specify the file permissions to be disabled.
	//
	// Available values: all(*), read(r), write(w), exec(x), append(a)
	//
	Permissions []string `json:"permissions"`
}

type NetworkEgressRule struct {
	// IPBlock defines policy on a particular IPBlock with CIDR.
	// +optional
	IPBlock string `json:"ipBlock,omitempty"`
	// IP defines policy on a particular IP. Note that the ip field and ipBlock field are mutually exclusive.
	// +optional
	IP string `json:"ip,omitempty"`
	// Port defines policy on a particular port. If this field is zero or missing, this rule matches all ports.
	// +optional
	Port int `json:"port,omitempty"`
}

type NetworkSocketRule struct {
	// Domains specifies the communication domains of socket.
	//
	// Available values:
	//       all(*), unix, inet, ax25, ipx, appletalk, netrom, bridge, atmpvc, x25,
	//       inet6, rose, netbeui, security, key, netlink, packet, ash, econet, atmsvc,
	//       rds, sna, irda, pppox, wanpipe, llc, ib, mpls, can, tipc, bluetooth, iucv,
	//       rxrpc, isdn, phonet, ieee802154, caif, alg, nfc, vsock, kcm, qipcrtr, smc,
	//       xdp, mctp
	//
	Domains []string `json:"domains,omitempty"`
	// Types specifies the communication semantics of socket.
	//
	// Available values: all(*), stream, dgram, raw, rdm, seqpacket, dccp, packet
	//
	Types []string `json:"types,omitempty"`
	// Protocols specifies the particular protocols to be used with the socket.
	// Note that the protocols field and types field are mutually exclusive.
	//
	// Available values: all(*), icmp, tcp, udp
	//
	Protocols []string `json:"protocols,omitempty"`
}

type NetworkRule struct {
	// Sockets are the list of socket rules to restrict all socket(2) operations.
	Sockets []NetworkSocketRule `json:"sockets,omitempty"`
	// Egresses are the list of egress rules to be applied to restrict particular IPs and ports.
	Egresses []NetworkEgressRule `json:"egresses,omitempty"`
}

type PtraceRule struct {
	// StrictMode is used to indicate whether to restrict ptrace operations for all source and destination processes.
	// Default is false.
	// If set to false, it allows a process to perform trace and read operations on other processes within the same container,
	// and also allows a process to be subjected to traceby and readby operations by other processes within the same container.
	// If set to true, it prohibits all trace, read, traceby, and readby operations within the container.
	// +optional
	StrictMode bool `json:"strictMode,omitempty"`
	// Permissions are used to indicate which ptrace-related permissions of the target container should be restricted.
	//
	// Available values: all(*), trace, traceby, read, readby.
	//    - trace: prohibiting tracing of other processes.
	//    - read: prohibiting reading of other processes.
	//    - traceby: prohibiting being traced by other processes (excluding the host processes).
	//    - readby: prohibiting being read by other processes (excluding the host processes).
	//
	//  The trace, traceby permissions for "write" operations, or other operations that are more dangerous, such as:
	//  ptrace attaching (PTRACE_ATTACH) to another process or calling process_vm_writev(2).
	//
	//  The read, readby permissions for "read" operations or other operations that are less dangerous, such as:
	//  get_robust_list(2); kcmp(2); reading /proc/pid/auxv, /proc/pid/environ, or /proc/pid/stat; or readlink(2)
	//  of a /proc/pid/ns/* file.
	Permissions []string `json:"permissions"`
}

type MountRule struct {
	// SourcePattern can be any string (maximum length 128 bytes) that conforms to the policy syntax,
	// used for matching file paths and filenames
	SourcePattern string `json:"sourcePattern"`
	// Fstype is used to specify the type of filesystem to enforce. It can be '*' to match any type.
	Fstype string `json:"fstype"`
	// Flags are used to specify the mount flags to enforce. They are almost the same as the 'MOUNT FLAGS LIST' of AppArmor.
	//
	// Available values:
	//       All Flags: all(*)
	//   Command Flags: ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec,
	//                  sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime,
	//                  silent, loud, relatime, norelatime, iversion, noiversion, strictatime,
	//                  nostrictatime
	//   Generic Flags: remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private),
	//                  make-slave(slave), make-shared(shared), make-runbindable, make-rprivate,
	//                  make-rslave, make-rshared
	//     Other Flags: umount
	//
	Flags []string `json:"flags"`
}

type BpfRawRules struct {
	Files     []FileRule   `json:"files,omitempty"`
	Processes []FileRule   `json:"processes,omitempty"`
	Network   *NetworkRule `json:"network,omitempty"`
	Ptrace    *PtraceRule  `json:"ptrace,omitempty"`
	Mounts    []MountRule  `json:"mounts,omitempty"`
}

type AppArmorRawRules struct {
	// Rules define the custom AppArmor rules. You should make sure that they satisfy
	// the AppArmor syntax on your own.
	Rules string `json:"rules"`
	// Targets specify the executable files for which the rules apply.
	// They must be specified as full paths to the executable files.
	// +optional
	Targets []string `json:"targets,omitempty"`
}

type EnhanceProtect struct {
	// HardeningRules are used to specify the built-in hardening rules.
	// +optional
	HardeningRules []string `json:"hardeningRules,omitempty"`
	// AttackProtectionRules are used to specify the built-in attack protection rules.
	// +optional
	AttackProtectionRules []AttackProtectionRules `json:"attackProtectionRules,omitempty"`
	// VulMitigationRules are used to specify the built-in vulnerability mitigation rules.
	// +optional
	VulMitigationRules []string `json:"vulMitigationRules,omitempty"`
	// AppArmorRawRules is used to set custom AppArmor rules.
	// +optional
	AppArmorRawRules []AppArmorRawRules `json:"appArmorRawRules,omitempty"`
	// BpfRawRules is used to set custom BPF rules.
	// +optional
	BpfRawRules *BpfRawRules `json:"bpfRawRules,omitempty"`
	// SyscallRawRules is used to set the syscalls blocklist rules with Seccomp enforcer.
	// +optional
	SyscallRawRules []specs.LinuxSyscall `json:"syscallRawRules,omitempty"`
	// Privileged is used to identify whether the policy is for the privileged container.
	// If set to `nil` or `false`, the EnhanceProtect mode will build AppArmor or BPF profile on
	// top of the RuntimeDefault mode. Otherwise, it will build AppArmor or BPF profile on top of the AlwaysAllow mode.
	// Default is false.
	//
	// Note:
	// If set to `true`, vArmor will not build Seccomp profile for the target workloads.
	// +optional
	Privileged bool `json:"privileged,omitempty"`
	// AuditViolations determines whether to audit the actions that violate the mandatory access
	// control rules. Currently, this feature supports AppArmor and BPF enforcers. Any detected
	// violation will be logged to `/var/log/varmor/violations.log` file in the host.
	//
	// Default is false.
	// +optional
	AuditViolations bool `json:"auditViolations,omitempty"`
	// AllowViolations determines whether to allow the actions that are against the mandatory
	// access control rules. Currently, this feature supports AppArmor and BPF enforcers.
	// Any detected violation will be allowed instead of being blocked.
	//
	// Default is false.
	// +optional
	AllowViolations bool `json:"allowViolations,omitempty"`
}

type ModelingOptions struct {
	// Duration is the duration in minutes to modeling
	Duration int `json:"duration"`
}

type VarmorPolicyMode string

type Policy struct {
	// Enforcer is used to specify which LSM to use for mandatory access control.
	// Available values: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp
	Enforcer string `json:"enforcer"`
	// Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth
	//
	// Note:
	// BehaviorModeling and DefenseInDepth modes are experimental features and currently only work
	// with AppArmor/Seccomp/AppArmorSeccomp enforcers.
	Mode VarmorPolicyMode `json:"mode"`
	// EnhanceProtect is used to specify which built-in or custom rules are employed to protect the target workloads.
	// +optional
	EnhanceProtect *EnhanceProtect `json:"enhanceProtect,omitempty"`
	// ModelingOptions is used for the modeling settings.
	// +optional
	ModelingOptions *ModelingOptions `json:"modelingOptions,omitempty"`
}

// VarmorPolicySpec defines the desired state of VarmorPolicy or VarmorClusterPolicy
type VarmorPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Target specifies the workloads and their containers you want to harden.
	Target Target `json:"target"`
	// Policy specifies which enforcer, mode and rules you want to use to apply to the target.
	Policy Policy `json:"policy"`
	// UpdateExistingWorkloads is used to indicate whether to perform a rolling update on target existing workloads,
	// thus enabling or disabling the protection of the target workloads when policies are created or deleted.
	// Default is false.
	//
	// Note:
	// vArmor only performs a rolling update on Deployment, StatefulSet, or DaemonSet type workloads.
	// If `.spec.target.kind` is Pod, you need to rebuild the Pod yourself to enable or disable protection.
	// +optional
	UpdateExistingWorkloads bool `json:"updateExistingWorkloads,omitempty"`
}

type VarmorPolicyConditionType string

type VarmorPolicyCondition struct {
	// Type of ArmorProfile condition.
	// Possible values: Created, Updated, Ready
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

// VarmorPolicyStatus defines the observed state of VarmorPolicy or VarmorClusterPolicy
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
	//
	// Note:
	// You can find out which varmor-agent has an error by reading the
	// ArmorProfile/status corresponding to the current VarmorPolicy
	Phase VarmorPolicyPhase `json:"phase,omitempty"`
}

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
type VarmorPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VarmorPolicySpec   `json:"spec"`
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
