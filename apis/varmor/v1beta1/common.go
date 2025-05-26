package v1beta1

import (
	"github.com/opencontainers/runtime-spec/specs-go"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type Target struct {
	// kind is used to specify the type of workloads for the protection targets.
	// Available values: Deployment, StatefulSet, DaemonSet, Pod.
	Kind string `json:"kind"`
	// name is used to specify a specific workload in the policy's namespace or all namespace.
	// Note that the name field and selector field are mutually exclusive.
	// +optional
	Name string `json:"name,omitempty"`
	// containers are used to specify the names of the containers. If it is empty, sandbox protection
	// will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).
	// +optional
	Containers []string `json:"containers,omitempty"`
	// selector is a label selector which selects workloads in the policy's namespace or all namespace.
	// This field follows standard label selector semantics.
	// Note that the selector field and name field are mutually exclusive.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

type AttackProtectionRules struct {
	// rules is the list of built-in attack protection rules to be used.
	Rules []string `json:"rules"`
	// targets specify the executable files for which the rules and rawRules apply.
	// They must be specified as full paths to the executable files.
	// This feature is only effective when using AppArmor as the enforcer.
	// +optional
	Targets []string `json:"targets,omitempty"`
}

type AppArmorRawRules struct {
	// rules define the custom AppArmor rules. You should make sure that they satisfy
	// the AppArmor syntax on your own.
	Rules string `json:"rules"`
	// targets specify the executable files for which the rules apply.
	// They must be specified as full paths to the executable files.
	// +optional
	Targets []string `json:"targets,omitempty"`
}

// VarmorPolicyMode defines the mode of VarmorPolicy and VarmorClusterPolicy.
// +enum
type VarmorPolicyMode string

const (
	// AlwaysAllowMode indicates that no mandatory access control rules are imposed on container, allowing all
	// operations by default.
	AlwaysAllowMode VarmorPolicyMode = "AlwaysAllow"
	// RuntimeDefaultMode uses the default security profile of the containerd, specifically based on the
	// "cri-containerd.apparmor.d" profile provided by containerd.
	RuntimeDefaultMode VarmorPolicyMode = "RuntimeDefault"
	// EnhanceProtectMode provides built-in rules and custom interfaces for Allow-by-Default protection.
	// By default (when the `EnhanceProtect.Privileged` field is nil or false), its profile is based on
	// `RuntimeDefaultMode`. When `EnhanceProtect.Privileged` is true, it enables enhanced protection
	// based on `AlwaysAllowMode`.
	EnhanceProtectMode VarmorPolicyMode = "EnhanceProtect"
	// BehaviorModelingMode dynamically models the behavior of target workloads and generates security profiles
	// based on the modeling results.
	BehaviorModelingMode VarmorPolicyMode = "BehaviorModeling"
	// DefenseInDepthMode applies Deny-by-Default security profiles to target workloads, implementing layered
	// defense by restricting unauthorized operations.
	DefenseInDepthMode VarmorPolicyMode = "DefenseInDepth"
)

type EnhanceProtect struct {
	// hardeningRules are used to specify the built-in hardening rules.
	// +optional
	HardeningRules []string `json:"hardeningRules,omitempty"`
	// attackProtectionRules are used to specify the built-in attack protection rules.
	// +optional
	AttackProtectionRules []AttackProtectionRules `json:"attackProtectionRules,omitempty"`
	// vulMitigationRules are used to specify the built-in vulnerability mitigation rules.
	// +optional
	VulMitigationRules []string `json:"vulMitigationRules,omitempty"`
	// appArmorRawRules is used to set custom AppArmor rules.
	// +optional
	AppArmorRawRules []AppArmorRawRules `json:"appArmorRawRules,omitempty"`
	// bpfRawRules is used to set custom BPF rules.
	// +optional
	BpfRawRules *BpfRawRules `json:"bpfRawRules,omitempty"`
	// syscallRawRules is used to set the syscalls blocklist rules with Seccomp enforcer.
	// +optional
	SyscallRawRules []specs.LinuxSyscall `json:"syscallRawRules,omitempty"`
	// privileged is used to identify whether the policy is for the privileged container.
	// If set to `nil` or `false`, the EnhanceProtect mode will build AppArmor or BPF profile on
	// top of the RuntimeDefault mode. Otherwise, it will build AppArmor or BPF profile on top of the AlwaysAllow mode.
	// Default is false.
	//
	// Note:
	// If set to `true`, vArmor will not build Seccomp profile for the target workloads.
	// +optional
	Privileged bool `json:"privileged,omitempty"`
	// auditViolations determines whether to audit the actions that violate the mandatory access
	// control rules. Any detected violation will be logged to `/var/log/varmor/violations.log`
	// file in the host. Please note that the Seccomp enforcer does not support auditing violations
	// when the allowViolations field is set to `false`.
	//
	// Default is false.
	// +optional
	AuditViolations bool `json:"auditViolations,omitempty"`
	// allowViolations determines whether to allow the actions that are against the mandatory
	// access control rules. Any detected violation will be allowed instead of being blocked.
	//
	// Default is false.
	// +optional
	AllowViolations bool `json:"allowViolations,omitempty"`
}

type ModelingOptions struct {
	// duration is the duration in minutes to modeling
	Duration int `json:"duration"`
}

type Policy struct {
	// enforcer is used to specify which LSM to use for mandatory access control.
	// Available values: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp
	Enforcer string `json:"enforcer"`
	// mode used to specify the protection mode.
	// Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth
	//
	// Note:
	// BehaviorModeling and DefenseInDepth modes are experimental features and currently only work
	// with AppArmor and Seccomp enforcers.
	Mode VarmorPolicyMode `json:"mode"`
	// enhanceProtect is used to specify which built-in or custom rules are employed to protect the target workloads.
	// +optional
	EnhanceProtect *EnhanceProtect `json:"enhanceProtect,omitempty"`
	// modelingOptions is used for the modeling settings.
	// +optional
	ModelingOptions *ModelingOptions `json:"modelingOptions,omitempty"`
}

type VarmorPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// target specifies the workloads and their containers you want to harden.
	Target Target `json:"target"`
	// policy specifies which enforcer, mode and rules you want to use to apply to the target.
	Policy Policy `json:"policy"`
	// updateExistingWorkloads is used to indicate whether to perform a rolling update on target existing workloads,
	// thus enabling or disabling the protection of the target workloads when policies are created or deleted.
	// Default is false.
	//
	// Note:
	// vArmor only performs a rolling update on Deployment, StatefulSet, or DaemonSet type workloads.
	// If `.spec.target.kind` is Pod, you need to rebuild the Pod yourself to enable or disable protection.
	// +optional
	UpdateExistingWorkloads bool `json:"updateExistingWorkloads,omitempty"`
}

// VarmorPolicyConditionType defines the type of VarmorPolicy and VarmorClusterPolicy condition.
// Possible values: Created, Updated, Ready
// +enum
type VarmorPolicyConditionType string

const (
	// VarmorPolicyCreated indicates that the policy has been created.
	VarmorPolicyCreated VarmorPolicyConditionType = "Created"
	// VarmorPolicyUpdated indicates that the policy has been updated.
	VarmorPolicyUpdated VarmorPolicyConditionType = "Updated"
	// VarmorPolicyReady indicates that the policy has been processed and is ready to be used.
	VarmorPolicyReady VarmorPolicyConditionType = "Ready"
)

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

// VarmorPolicyPhase defines the phase of VarmorPolicy or VarmorClusterPolicy.
// Possible values: Pending, Modeling, Completed, Protecting, Error, Failed, Unknown, Unchanged
// +enum
type VarmorPolicyPhase string

const (
	// VarmorPolicyPending indicates that the policy is pending to be processed.
	VarmorPolicyPending VarmorPolicyPhase = "Pending"
	// VarmorPolicyProtecting indicates that the policy has been processed and is protecting the target workloads.
	VarmorPolicyProtecting VarmorPolicyPhase = "Protecting"
	// VarmorPolicyModeling indicates that the policy is in the modeling phase.
	VarmorPolicyModeling VarmorPolicyPhase = "Modeling"
	// VarmorPolicyCompleted indicates that the policy has been completed the modeling.
	VarmorPolicyCompleted VarmorPolicyPhase = "Completed"
	// VarmorPolicyError indicates that an error occurred while processing the policy.
	VarmorPolicyError VarmorPolicyPhase = "Error"
	// VarmorPolicyFailed indicates that the policy has failed to be processed.
	VarmorPolicyFailed VarmorPolicyPhase = "Failed"
	// VarmorPolicyUnknown indicates that the phase of the policy is unknown.
	VarmorPolicyUnknown VarmorPolicyPhase = "Unknown"
	// VarmorPolicyUnchanged indicates that the policy has not changed since the last reconciliation.
	VarmorPolicyUnchanged VarmorPolicyPhase = "Unchanged"
)

type VarmorPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// ProfileName is the name of the AppArmor, BPF and Seccomp profile that is generated by the policy.
	// It is in the format of "varmor-{namespace}-{name}" for namespaced policies or "varmor-cluster-{namespace}-{name}"
	// for cluster-scoped policies.
	// It is equivalent to the name of the ArmorProfile object that is created by the policy.
	ProfileName string `json:"profileName"`
	// Conditions is a list of conditions that indicate the status of the policy.
	// It can include conditions such as Created, Updated, Ready, etc.
	// +optional
	Conditions []VarmorPolicyCondition `json:"conditions,omitempty"`
	// Ready is used to indicate whether the profile of policy is loaded.
	Ready bool `json:"ready"`
	// Phase is used to indicate the processing phase of the policy.
	// Possible values: Pending, Modeling, Completed, Protecting, Error.
	//
	// Note:
	// You can find out which varmor-agent has an error by reading the
	// ArmorProfile/status corresponding to the current VarmorPolicy
	// +optional
	Phase VarmorPolicyPhase `json:"phase,omitempty"`
}
