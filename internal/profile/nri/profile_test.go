package nri

import (
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateEnhanceProtectProfile(t *testing.T) {
	tests := []struct {
		name           string
		enhanceProtect *varmor.EnhanceProtect
		namespace      string
		target         varmor.Target
		isClusterScope bool
		check          func(*testing.T, *varmor.NriContent)
	}{
		{
			name:           "Nil Input",
			enhanceProtect: nil,
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.Nil(t, c)
			},
		},
		{
			name: "Only Builtin Rules (Deny Mode)",
			enhanceProtect: &varmor.EnhanceProtect{
				RejectContainerRules: []string{"disallow-privileged-container", "disallow-latest-tag"},
				AllowViolations:      false,
			},
			namespace: "default",
			target: varmor.Target{
				Kind: "Pod",
			},
			isClusterScope: false,
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Contains(t, c.BuiltinRules, "package nri.authz")
				assert.Contains(t, c.BuiltinRules, "deny[d] {")
				assert.Contains(t, c.BuiltinRules, "builtin.is_privileged_container")
				assert.Contains(t, c.BuiltinRules, "builtin.has_latest_tag")
				// mode field is no longer generated in the Rego body, the rule name determines the mode
				// assert.Contains(t, c.BuiltinRules, "\"mode\": \"deny\"")
				assert.Empty(t, c.Rules)
				assert.Equal(t, "default", c.Namespace)
				assert.Equal(t, "Pod", c.Target.Kind)
				assert.False(t, c.IsClusterScope)
			},
		},
		{
			name: "Only Builtin Rules (AuditAllow Mode)",
			enhanceProtect: &varmor.EnhanceProtect{
				RejectContainerRules: []string{"disallow-host-network"},
				AllowViolations:      true,
			},
			namespace: "",
			target: varmor.Target{
				Kind: "Pod",
			},
			isClusterScope: true,
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Contains(t, c.BuiltinRules, "audit_allow[d] {")
				// assert.Contains(t, c.BuiltinRules, "\"mode\": \"audit-allow\"")
				assert.True(t, c.IsClusterScope)
			},
		},
		{
			name: "Only Raw Rules",
			enhanceProtect: &varmor.EnhanceProtect{
				NriRawRules: "package nri.authz\ndeny[msg] { true; msg := \"always\" }",
			},
			namespace: "test-ns",
			target: varmor.Target{
				Kind: "Pod",
			},
			isClusterScope: false,
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Empty(t, c.BuiltinRules)
				assert.Equal(t, "package nri.authz\ndeny[msg] { true; msg := \"always\" }", c.Rules)
				assert.Equal(t, "test-ns", c.Namespace)
			},
		},
		{
			name: "Both Builtin and Raw Rules",
			enhanceProtect: &varmor.EnhanceProtect{
				RejectContainerRules: []string{"disallow-root-container"},
				NriRawRules:          "package nri.authz\ndeny[msg] { true }",
			},
			namespace: "",
			target: varmor.Target{
				Kind: "Pod",
			},
			isClusterScope: true,
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.NotEmpty(t, c.BuiltinRules)
				assert.NotEmpty(t, c.Rules)
				assert.Contains(t, c.BuiltinRules, "runs_as_root")
				assert.True(t, c.IsClusterScope)
			},
		},
		{
			name: "With Options",
			enhanceProtect: &varmor.EnhanceProtect{
				NriOptions: &varmor.NriOptions{
					Timeout:       5000,
					FailurePolicy: "Fail",
				},
				AuditViolations: true,
			},
			namespace: "my-ns",
			target: varmor.Target{
				Kind: "Pod",
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test",
					},
				},
			},
			isClusterScope: false,
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Equal(t, 5000, c.Timeout)
				assert.Equal(t, "Fail", c.FailurePolicy)
				assert.True(t, c.AuditViolations)
				assert.Equal(t, "my-ns", c.Namespace)
				assert.Equal(t, "Pod", c.Target.Kind)
				assert.NotNil(t, c.Target.Selector)
				assert.Equal(t, "test", c.Target.Selector.MatchLabels["app"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateEnhanceProtectProfile(tt.enhanceProtect, tt.namespace, tt.target, tt.isClusterScope)
			tt.check(t, got)
		})
	}
}
