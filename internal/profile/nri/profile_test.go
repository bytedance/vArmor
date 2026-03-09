package nri

import (
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestGenerateEnhanceProtectProfile(t *testing.T) {
	tests := []struct {
		name           string
		enhanceProtect *varmor.EnhanceProtect
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
			name: "Only Preset Rules (Deny Mode)",
			enhanceProtect: &varmor.EnhanceProtect{
				RejectContainerRules: []string{"disallow-privileged-container", "disallow-latest-tag"},
				AllowViolations:      false,
			},
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Contains(t, c.PresetRules, "package nri.authz")
				assert.Contains(t, c.PresetRules, "deny[d] {")
				assert.Contains(t, c.PresetRules, "builtin.is_privileged_container")
				assert.Contains(t, c.PresetRules, "builtin.has_latest_tag")
				// mode field is no longer generated in the Rego body, the rule name determines the mode
				// assert.Contains(t, c.PresetRules, "\"mode\": \"deny\"")
				assert.Empty(t, c.Rules)
			},
		},
		{
			name: "Only Preset Rules (AuditAllow Mode)",
			enhanceProtect: &varmor.EnhanceProtect{
				RejectContainerRules: []string{"disallow-host-network"},
				AllowViolations:      true,
			},
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Contains(t, c.PresetRules, "audit_allow[d] {")
				// assert.Contains(t, c.PresetRules, "\"mode\": \"audit-allow\"")
			},
		},
		{
			name: "Only Raw Rules",
			enhanceProtect: &varmor.EnhanceProtect{
				NriRawRules: "package nri.authz\ndeny[msg] { true; msg := \"always\" }",
			},
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Empty(t, c.PresetRules)
				assert.Equal(t, "package nri.authz\ndeny[msg] { true; msg := \"always\" }", c.Rules)
			},
		},
		{
			name: "Both Preset and Raw Rules",
			enhanceProtect: &varmor.EnhanceProtect{
				RejectContainerRules: []string{"disallow-root-container"},
				NriRawRules:          "package nri.authz\ndeny[msg] { true }",
			},
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.NotEmpty(t, c.PresetRules)
				assert.NotEmpty(t, c.Rules)
				assert.Contains(t, c.PresetRules, "runs_as_root")
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
			check: func(t *testing.T, c *varmor.NriContent) {
				assert.NotNil(t, c)
				assert.Equal(t, 5000, c.Timeout)
				assert.Equal(t, "Fail", c.FailurePolicy)
				assert.True(t, c.AuditViolations)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateEnhanceProtectProfile(tt.enhanceProtect)
			tt.check(t, got)
		})
	}
}
