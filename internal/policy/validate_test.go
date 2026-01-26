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
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// TestValidateAddPolicy_ValidVarmorPolicy tests valid VarmorPolicy validation
func TestValidateAddPolicy_ValidVarmorPolicy(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid policy should pass validation")
	assert.Equal(t, "", message, "Should return empty message when validation passes")
}

// TestValidateAddPolicy_ValidVarmorClusterPolicy tests valid VarmorClusterPolicy validation
func TestValidateAddPolicy_ValidVarmorClusterPolicy(t *testing.T) {
	policy := &varmor.VarmorClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid cluster policy should pass validation")
	assert.Equal(t, "", message, "Should return empty message when validation passes")
}

// TestValidateAddPolicy_UnsupportedPolicyType tests unsupported policy type
func TestValidateAddPolicy_UnsupportedPolicyType(t *testing.T) {
	invalidPolicy := "invalid policy type"

	valid, message := ValidateAddPolicy(invalidPolicy, true)
	assert.False(t, valid, "Unsupported policy type should fail validation")
	assert.Equal(t, "The policy type is not supported.", message)
}

// TestValidateAddPolicy_UnsupportedTargetKind tests unsupported target kind
func TestValidateAddPolicy_UnsupportedTargetKind(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Service", // unsupported type
				Name: "test-service",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.False(t, valid, "Unsupported target kind should fail validation")
	assert.Contains(t, message, "The target kind is not supported")
}

// TestValidateAddPolicy_EmptyTargetNameAndSelector tests when both target name and selector are empty
func TestValidateAddPolicy_EmptyTargetNameAndSelector(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				// Both Name and Selector are empty
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.False(t, valid, "Empty target name and selector should fail validation")
	assert.Contains(t, message, "The target name and selector are empty")
}

// TestValidateAddPolicy_BothTargetNameAndSelector tests when both target name and selector are specified
func TestValidateAddPolicy_BothTargetNameAndSelector(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.False(t, valid, "Both target name and selector specified should fail validation")
	assert.Contains(t, message, "The target name and selector are exclusive")
}

// TestValidateAddPolicy_EnhanceProtectModeWithoutConfig tests EnhanceProtect mode without configuration
func TestValidateAddPolicy_EnhanceProtectModeWithoutConfig(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.EnhanceProtectMode,
				// EnhanceProtect is nil
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.False(t, valid, "EnhanceProtect mode without configuration should fail validation")
	assert.Contains(t, message, "The enhanceProtect field should be set when the policy runs in the EnhanceProtect mode")
}

// TestValidateAddPolicy_BehaviorModelingModeWithoutFeature tests BehaviorModeling mode when feature is not enabled
func TestValidateAddPolicy_BehaviorModelingModeWithoutFeature(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.BehaviorModelingMode,
			},
		},
	}

	// behaviorModelingEnabled = false
	valid, message := ValidateAddPolicy(policy, false)
	assert.False(t, valid, "BehaviorModeling mode without feature enabled should fail validation")
	assert.Contains(t, message, "The BehaviorModeling feature of vArmor is not enabled")
}

// TestValidateAddPolicy_BehaviorModelingModeWithoutOptions tests BehaviorModeling mode without configuration options
func TestValidateAddPolicy_BehaviorModelingModeWithoutOptions(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.BehaviorModelingMode,
				// ModelingOptions is nil
			},
		},
	}

	// behaviorModelingEnabled = true
	valid, message := ValidateAddPolicy(policy, true)
	assert.False(t, valid, "BehaviorModeling mode without configuration options should fail validation")
	assert.Contains(t, message, "The modelingOptions field should be set when the policy runs in the BehaviorModeling mode")
}

// TestValidateAddPolicy_ValidBehaviorModelingMode tests valid BehaviorModeling mode
func TestValidateAddPolicy_ValidBehaviorModelingMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.BehaviorModelingMode,
				ModelingOptions: &varmor.ModelingOptions{
					Duration: 30,
				},
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid BehaviorModeling mode should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateAddPolicy_ValidEnhanceProtectMode tests valid EnhanceProtect mode
func TestValidateAddPolicy_ValidEnhanceProtectMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.EnhanceProtectMode,
				EnhanceProtect: &varmor.EnhanceProtect{
					HardeningRules: []string{"rule1", "rule2"},
				},
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid EnhanceProtect mode should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateAddPolicy_ValidTargetSelector tests valid target selector
func TestValidateAddPolicy_ValidTargetSelector(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid target selector should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateAddPolicy_SupportedTargetKinds tests all supported target kinds
func TestValidateAddPolicy_SupportedTargetKinds(t *testing.T) {
	supportedKinds := []string{"Deployment", "StatefulSet", "DaemonSet", "Pod"}

	for _, kind := range supportedKinds {
		t.Run(kind, func(t *testing.T) {
			policy := &varmor.VarmorPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: varmor.VarmorPolicySpec{
					Target: varmor.Target{
						Kind: kind,
						Name: "test-workload",
					},
					Policy: varmor.Policy{
						Enforcer: "AppArmor",
						Mode:     varmor.RuntimeDefaultMode,
					},
				},
			}

			valid, message := ValidateAddPolicy(policy, true)
			assert.True(t, valid, "Supported target kind %s should pass validation", kind)
			assert.Equal(t, "", message)
		})
	}
}

// TestValidateAddPolicy_LongPolicyName tests policy name that is too long
func TestValidateAddPolicy_LongPolicyName(t *testing.T) {
	// Create a policy with a very long name
	longName := "this-is-a-very-long-policy-name-that-exceeds-the-kubernetes-name-length-limit-of-63-characters"
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      longName,
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.False(t, valid, "Policy name that is too long should fail validation")
	assert.Contains(t, message, "The length of policy object name is too long")
}

// TestValidateAddPolicy_ValidDefenseInDepthMode tests valid DefenseInDepth mode
func TestValidateAddPolicy_ValidDefenseInDepthMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.DefenseInDepthMode,
				DefenseInDepth: &varmor.DefenseInDepth{
					AllowViolations: true,
				},
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid DefenseInDepth mode should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateAddPolicy_ValidAlwaysAllowMode tests valid AlwaysAllow mode
func TestValidateAddPolicy_ValidAlwaysAllowMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.AlwaysAllowMode,
			},
		},
	}

	valid, message := ValidateAddPolicy(policy, true)
	assert.True(t, valid, "Valid AlwaysAllow mode should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateUpdatePolicy_ValidUpdate tests valid policy update
func TestValidateUpdatePolicy_ValidUpdate(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid policy update should pass validation")
	assert.Equal(t, "", message, "Validation passes when validation passes")
}

// TestValidateUpdatePolicy_UnsupportedPolicyType tests unsupported policy type
func TestValidateUpdatePolicy_UnsupportedPolicyType(t *testing.T) {
	invalidPolicy := "invalid policy type"
	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(invalidPolicy, oldEnforcer, oldTarget)
	assert.False(t, valid, "Unsupported policy type should fail validation")
	assert.Equal(t, "The policy type is not supported.", message)
}

// TestValidateUpdatePolicy_TargetModified tests target field modification
func TestValidateUpdatePolicy_TargetModified(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "modified-deployment", // Modified target name
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment", // Original target name
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.False(t, valid, "Target field modification should fail validation")
	assert.Contains(t, message, "Modifying the target field of a policy is not allowed")
}

// TestValidateUpdatePolicy_SwitchFromBehaviorModelingIncomplete tests switch from BehaviorModeling mode but modeling is not complete
func TestValidateUpdatePolicy_SwitchFromBehaviorModelingIncomplete(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode, // Switch from BehaviorModeling to RuntimeDefault
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyModeling, // Modeling is not complete
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.False(t, valid, "Switch from BehaviorModeling mode but modeling is not complete should fail validation")
	assert.Contains(t, message, "Switching the mode of a policy from BehaviorModeling to others is not allowed")
}

// TestValidateUpdatePolicy_SwitchFromBehaviorModelingComplete tests switch from BehaviorModeling mode but modeling is complete
func TestValidateUpdatePolicy_SwitchFromBehaviorModelingComplete(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode, // Switch from BehaviorModeling to RuntimeDefault
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyCompleted, // Modeling is complete
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Switch from BehaviorModeling mode to RuntimeDefault mode should pass validation")
	assert.Equal(t, "", message, "Validation passes when validation passes")
}

// TestValidateUpdatePolicy_EnforcerModifiedDuringModeling tests modification of enforcer field during modeling
func TestValidateUpdatePolicy_EnforcerModifiedDuringModeling(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "BPF", // Modified enforcer
				Mode:     varmor.BehaviorModelingMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyModeling, // Modeling is not complete
		},
	}

	oldEnforcer := "AppArmor" // Original enforcer
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.False(t, valid, "Modification of enforcer field during modeling should fail validation")
	assert.Contains(t, message, "Modifying the enforcer field of a policy is not allowed when behavior modeling is still incomplete.")
}

// TestValidateUpdatePolicy_EnforcerModifiedAfterModeling tests modification of enforcer field after modeling
func TestValidateUpdatePolicy_EnforcerModifiedAfterModeling(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "SeccompAppArmorBPF", // Modified enforcer
				Mode:     varmor.BehaviorModelingMode,
				ModelingOptions: &varmor.ModelingOptions{
					Duration: 30,
				},
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyCompleted, // Modeling is complete
		},
	}

	oldEnforcer := "AppArmor" // Original enforcer
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Modification of enforcer field after modeling should pass validation")
	assert.Equal(t, "", message, "Validation passes when validation passes")
}

// TestValidateUpdatePolicy_RemoveAppArmorEnforcer tests removal of AppArmor enforcer
func TestValidateUpdatePolicy_RemoveAppArmorEnforcer(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "BPF", // Removed AppArmor
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmorBPF" // Original contains AppArmor and BPF
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.False(t, valid, "Removal of AppArmor enforcer should fail validation")
	assert.Contains(t, message, "Modifying a policy to remove the AppArmor or Seccomp enforcer is not allowed")
}

// TestValidateUpdatePolicy_EnhanceProtectModeWithoutConfig tests EnhanceProtect mode without configuration
func TestValidateUpdatePolicy_EnhanceProtectModeWithoutConfig(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.EnhanceProtectMode,
				// EnhanceProtect is nil
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.False(t, valid, "EnhanceProtect mode without configuration should fail validation")
	assert.Contains(t, message, "The enhanceProtect field should be set when the policy runs in the EnhanceProtect mode")
}

// TestValidateUpdatePolicy_BehaviorModelingModeWithoutOptions tests BehaviorModeling mode without configuration options
func TestValidateUpdatePolicy_BehaviorModelingModeWithoutOptions(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.BehaviorModelingMode,
				// ModelingOptions is nil
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.False(t, valid, "BehaviorModeling mode without configuration options should fail validation")
	assert.Contains(t, message, "The modelingOptions field should be set when the policy runs in the BehaviorModeling mode")
}

// TestValidateUpdatePolicy_ValidVarmorClusterPolicy tests valid VarmorClusterPolicy update
func TestValidateUpdatePolicy_ValidVarmorClusterPolicy(t *testing.T) {
	policy := &varmor.VarmorClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid cluster policy update should pass validation")
	assert.Equal(t, "", message, "Validation passes when validation passes")
}

// TestValidateUpdatePolicy_ValidEnhanceProtectMode tests valid EnhanceProtect mode update
func TestValidateUpdatePolicy_ValidEnhanceProtectMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.EnhanceProtectMode,
				EnhanceProtect: &varmor.EnhanceProtect{
					HardeningRules: []string{"rule1", "rule2"},
				},
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid EnhanceProtect mode update should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateUpdatePolicy_ValidBehaviorModelingMode tests valid BehaviorModeling mode update
func TestValidateUpdatePolicy_ValidBehaviorModelingMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.BehaviorModelingMode,
				ModelingOptions: &varmor.ModelingOptions{
					Duration: 30,
				},
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid BehaviorModeling mode update should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateUpdatePolicy_ValidDefenseInDepthMode tests valid DefenseInDepth mode update
func TestValidateUpdatePolicy_ValidDefenseInDepthMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.DefenseInDepthMode,
				DefenseInDepth: &varmor.DefenseInDepth{
					AllowViolations: true,
				},
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid DefenseInDepth mode update should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateUpdatePolicy_ValidAlwaysAllowMode tests valid AlwaysAllow mode update
func TestValidateUpdatePolicy_ValidAlwaysAllowMode(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmor",
				Mode:     varmor.AlwaysAllowMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor"
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid AlwaysAllow mode update should pass validation")
	assert.Equal(t, "", message)
}

// TestValidateUpdatePolicy_ValidEnforcerCombination tests valid enforcer combination update
func TestValidateUpdatePolicy_ValidEnforcerCombination(t *testing.T) {
	policy := &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{
				Kind: "Deployment",
				Name: "test-deployment",
			},
			Policy: varmor.Policy{
				Enforcer: "AppArmorBPF", // AddBPF enforcer
				Mode:     varmor.RuntimeDefaultMode,
			},
		},
		Status: varmor.VarmorPolicyStatus{
			Phase: varmor.VarmorPolicyProtecting,
		},
	}

	oldEnforcer := "AppArmor" // Original only AppArmor
	oldTarget := varmor.Target{
		Kind: "Deployment",
		Name: "test-deployment",
	}

	valid, message := ValidateUpdatePolicy(policy, oldEnforcer, oldTarget)
	assert.True(t, valid, "Valid enforcer combination update should pass validation")
	assert.Equal(t, "", message)
}
