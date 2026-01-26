// Copyright 2025 vArmor Authors
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

package policy

import (
	"fmt"
	"reflect"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

// ValidateAddPolicy validates policy objects for creation operations.
// This is a generic validation function that supports both VarmorPolicy and VarmorClusterPolicy types.
// It performs comprehensive validation checks including target specification, policy mode requirements,
// and naming constraints to ensure the policy can be safely created and processed by the controller.
//
// Parameters:
//   - policy: The policy object to validate (can be *varmor.VarmorPolicy or *varmor.VarmorClusterPolicy)
//   - behaviorModelingEnabled: Flag indicating if the behavior modeling feature of vArmor is enabled
//
// Returns:
//   - bool: true if validation passes, false otherwise
//   - string: Detailed error message if validation fails, empty string if validation passes
func ValidateAddPolicy(policy interface{}, behaviorModelingEnabled bool) (bool, string) {
	var spec varmor.VarmorPolicySpec
	var namespace, name string
	var clusterScope bool

	switch p := policy.(type) {
	case *varmor.VarmorPolicy:
		spec = p.Spec
		namespace = p.Namespace
		name = p.Name
	case *varmor.VarmorClusterPolicy:
		spec = p.Spec
		namespace = varmorconfig.Namespace
		name = p.Name
		clusterScope = true
	default:
		return false, "The policy type is not supported."
	}

	// Validate target workload kind - only supported Kubernetes resource types are allowed
	if spec.Target.Kind != "Deployment" && spec.Target.Kind != "StatefulSet" && spec.Target.Kind != "DaemonSet" && spec.Target.Kind != "Pod" {
		return false, "The target kind is not supported. You should specify the target kind as a Deployment, StatefulSet, DaemonSet, or Pod."
	}

	// Ensure either target name or selector is specified, but not both
	if spec.Target.Name == "" && spec.Target.Selector == nil {
		return false, "The target name and selector are empty. You should specify the target workload either by name or selector."
	}

	// Target name and selector are mutually exclusive to avoid ambiguity
	if spec.Target.Name != "" && spec.Target.Selector != nil {
		return false, "The target name and selector are exclusive. You shouldn't specify the target workload using both name and selector."
	}

	// EnhanceProtect mode requires specific configuration to function properly
	if spec.Policy.Mode == varmor.EnhanceProtectMode && spec.Policy.EnhanceProtect == nil {
		return false, "The enhanceProtect field should be set when the policy runs in the EnhanceProtect mode."
	}

	// BehaviorModeling mode requires the feature to be enabled in the system
	if !behaviorModelingEnabled && spec.Policy.Mode == varmor.BehaviorModelingMode {
		return false, "The BehaviorModeling feature of vArmor is not enabled. Please enable it first."
	}

	// BehaviorModeling mode requires modeling options configuration
	if behaviorModelingEnabled && spec.Policy.Mode == varmor.BehaviorModelingMode && spec.Policy.ModelingOptions == nil {
		return false, "The modelingOptions field should be set when the policy runs in the BehaviorModeling mode."
	}

	// Do not exceed the length of a standard Kubernetes name (63 characters)
	// Note: The advisory length of AppArmor profile name is 100 (See https://bugs.launchpad.net/apparmor/+bug/1499544).
	profileName := varmorprofile.GenerateArmorProfileName(namespace, name, clusterScope)
	if len(profileName) > 63 {
		if clusterScope {
			return false, fmt.Sprintf("The length of policy object name is too long, please limit it to %d bytes.", 63-len(varmorprofile.ClusterProfileNameTemplate)+4-len(namespace))
		} else {
			return false, fmt.Sprintf("The length of policy object name is too long, please limit it to %d bytes.", 63-len(varmorprofile.ProfileNameTemplate)+4-len(namespace))
		}
	}

	// All validations passed
	return true, ""
}

// ValidateUpdatePolicy validates policy objects for update operations.
// This is a generic validation function that supports both VarmorPolicy and VarmorClusterPolicy types.
// It performs comprehensive validation checks to ensure policy updates maintain consistency
// and do not violate system constraints, particularly for in-progress operations like behavior modeling.
//
// Parameters:
//   - policy: The updated policy object to validate (can be *varmor.VarmorPolicy or *varmor.VarmorClusterPolicy)
//   - oldEnforcer: The previous enforcer configuration from the existing policy
//   - oldTarget: The previous target configuration from the existing policy
//
// Returns:
//   - bool: true if validation passes, false otherwise
//   - string: Detailed error message if validation fails, empty string if validation passes
func ValidateUpdatePolicy(policy interface{}, oldEnforcer string, oldTarget varmor.Target) (bool, string) {
	// Extract common policy specification fields from different policy types
	var newEnforcers varmortypes.Enforcer
	var newSpec varmor.VarmorPolicySpec
	var newStatus varmor.VarmorPolicyStatus

	switch p := policy.(type) {
	case *varmor.VarmorPolicy:
		newEnforcers = varmortypes.GetEnforcerType(p.Spec.Policy.Enforcer)
		newSpec = p.Spec
		newStatus = p.Status
	case *varmor.VarmorClusterPolicy:
		newEnforcers = varmortypes.GetEnforcerType(p.Spec.Policy.Enforcer)
		newSpec = p.Spec
		newStatus = p.Status
	default:
		return false, "The policy type is not supported."
	}

	oldEnforcers := varmortypes.GetEnforcerType(oldEnforcer)

	// Disallow modifying the target field of a policy.
	// Target modifications require policy recreation to ensure proper workload association and security consistency
	if !reflect.DeepEqual(newSpec.Target, oldTarget) {
		return false, "Modifying the target field of a policy is not allowed. You need to recreate the policy object."
	}

	// Disallow switching the mode of a policy from BehaviorModeling to others when behavior modeling is still incomplete.
	// This prevents interrupting ongoing behavior modeling processes and ensures data consistency
	if newSpec.Policy.Mode != varmor.BehaviorModelingMode &&
		newStatus.Phase == varmor.VarmorPolicyModeling {
		return false, "Switching the mode of a policy from BehaviorModeling to others is not allowed when behavior modeling is still incomplete."
	}

	// Disallow modifying the enforcer field of a policy when behavior modeling is still incomplete.
	// Enforcer changes during modeling could invalidate collected behavior data and modeling results
	if newSpec.Policy.Mode == varmor.BehaviorModelingMode &&
		newStatus.Phase == varmor.VarmorPolicyModeling &&
		newEnforcers != oldEnforcers {
		return false, "Modifying the enforcer field of a policy is not allowed when behavior modeling is still incomplete."
	}

	// Disallow removing the activated AppArmor or Seccomp enforcer.
	if (newEnforcers&oldEnforcers != oldEnforcers) && (newEnforcers|varmortypes.BPF != oldEnforcers) {
		return false, "Modifying a policy to remove the AppArmor or Seccomp enforcer is not allowed. To remove them, you need to recreate the policy object."
	}

	// Make sure the enhanceProtect field has been set when the policy runs in the EnhanceProtect mode.
	// EnhanceProtect mode requires specific configuration to function properly and provide enhanced protection
	if newSpec.Policy.Mode == varmor.EnhanceProtectMode &&
		newSpec.Policy.EnhanceProtect == nil {
		return false, "The enhanceProtect field should be set when the policy runs in the EnhanceProtect mode."
	}

	// Make sure the modelingOptions field has been set when the policy runs in BehaviorModeling mode.
	// Behavior modeling requires configuration options to guide the modeling process and define modeling parameters
	if newSpec.Policy.Mode == varmor.BehaviorModelingMode &&
		newSpec.Policy.ModelingOptions == nil {
		return false, "The modelingOptions field should be set when the policy runs in the BehaviorModeling mode."
	}

	// All validations passed
	return true, ""
}
