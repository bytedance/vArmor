package nrienforcer_test

import (
	"context"
	"testing"

	"github.com/bytedance/vArmor/pkg/nrienforcer"
	"github.com/containerd/nri/pkg/api"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

func TestEvaluator(t *testing.T) {
	// Create a temporary policy file
	rawPolicy := `
package nri.authz
import future.keywords.in

deny[decision] {
    input.container.labels["env"] == "forbidden"
    decision := {"id": "TEST-001", "message": "forbidden env"}
}

deny[decision] {
    some arg in input.spec.process.args
    arg == "--privileged"
    decision := {"id": "TEST-002", "message": "privileged arg"}
}

deny[decision] {
    endswith(input.image, ":latest")
    decision := {"id": "TEST-003", "message": "latest image tag"}
}

audit_deny[decision] {
    endswith(input.image, ":edge")
    decision := {"id": "TEST-004", "message": "edge image tag - audit deny"}
}

audit_allow[decision] {
    endswith(input.image, ":stable")
    decision := {"id": "TEST-005", "message": "stable image tag - audit allow"}
}
`

	presetPolicy := `
package nri.authz
import data.varmor.nri.builtin
import future.keywords.in

deny[d] {
	builtin.is_privileged_container
	d := {"id": "NRI-001", "message": "Privileged preset"}
}

deny[d] {
	builtin.has_dangerous_capabilities
	d := {"id": "NRI-002", "message": "Dangerous capabilities preset"}
}

deny[d] {
	builtin.has_latest_tag
	d := {"id": "NRI-003", "message": "Latest tag preset"}
}

deny[d] {
	builtin.runs_as_root
	d := {"id": "NRI-004", "message": "Runs as root preset"}
}
`

	// Init OPA
	evaluator, err := nrienforcer.NewEvaluator(context.Background())
	if err != nil {
		t.Fatalf("Failed to init OPA: %v", err)
	}

	options := nrienforcer.Options{
		FailurePolicy: "Fail",
	}

	// Add policy
	err = evaluator.UpdatePolicy(context.Background(), "test-profile", presetPolicy, rawPolicy, options)
	if err != nil {
		t.Fatalf("Failed to update policy: %v", err)
	}

	tests := []struct {
		name             string
		input            nrienforcer.Input
		expectDeny       bool
		expectAuditDeny  bool
		expectAuditAllow bool
		expectPresetDeny bool
		expectedMessages []string
	}{
		{
			name: "Allowed",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:1.35",
			},
			expectDeny:       false,
			expectAuditDeny:  false,
			expectAuditAllow: false,
			expectPresetDeny: false,
		},
		{
			name: "Forbidden Label (Raw Rule)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "forbidden",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:1.35",
			},
			expectDeny:       true,
			expectAuditDeny:  false,
			expectAuditAllow: false,
			expectPresetDeny: false,
			expectedMessages: []string{"forbidden env"},
		},
		{
			name: "Privileged (Preset Rule)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{"SYS_ADMIN"},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{},
					},
				},
				Image: "busybox:1.35",
			},
			expectDeny:       true,
			expectAuditDeny:  false,
			expectAuditAllow: false,
			expectPresetDeny: true,
			expectedMessages: []string{"Privileged preset"},
		},
		{
			name: "Dangerous Capabilities (Preset Rule)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{"NET_ADMIN"},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:1.35",
			},
			expectDeny:       true,
			expectAuditDeny:  false,
			expectAuditAllow: false,
			expectPresetDeny: true,
			expectedMessages: []string{"Dangerous capabilities preset"},
		},
		{
			name: "Latest Image Tag (Raw Rule)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:latest",
			},
			expectDeny:       true,
			expectAuditDeny:  false,
			expectAuditAllow: false,
			expectPresetDeny: true,
			expectedMessages: []string{"latest image tag", "Latest tag preset"},
		},
		{
			name: "Edge Image Tag (Audit Deny)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:edge",
			},
			expectDeny:       false,
			expectAuditDeny:  true,
			expectAuditAllow: false,
			expectPresetDeny: false,
			expectedMessages: []string{"edge image tag - audit deny"},
		},
		{
			name: "Stable Image Tag (Audit Allow)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{},
						},
						User: specs.User{
							UID: 1000,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:stable",
			},
			expectDeny:       false,
			expectAuditDeny:  false,
			expectAuditAllow: true,
			expectPresetDeny: false,
			expectedMessages: []string{"stable image tag - audit allow"},
		},
		{
			name: "Runs as Root (Preset Rule)",
			input: nrienforcer.Input{
				Container: &api.Container{
					Labels: map[string]string{
						"env": "production",
					},
				},
				Spec: &specs.Spec{
					Process: &specs.Process{
						Args: []string{"/bin/sh"},
						Capabilities: &specs.LinuxCapabilities{
							Effective: []string{},
						},
						User: specs.User{
							UID: 0,
						},
					},
					Linux: &specs.Linux{
						MaskedPaths: []string{"/proc/kcore"},
					},
				},
				Image: "busybox:1.35",
			},
			expectDeny:       true,
			expectAuditDeny:  false,
			expectAuditAllow: false,
			expectPresetDeny: true,
			expectedMessages: []string{"Runs as root preset"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := evaluator.Evaluate(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			hasDeny := false
			hasAuditDeny := false
			hasAuditAllow := false
			hasPresetDeny := false
			allMessages := []string{}

			for _, res := range results {
				for _, msg := range res.DenyMessages {
					hasDeny = true
					allMessages = append(allMessages, msg)
					for _, expectedMsg := range tt.expectedMessages {
						if msg == expectedMsg && (expectedMsg == "Privileged preset" || expectedMsg == "Dangerous capabilities preset" || expectedMsg == "Latest tag preset" || expectedMsg == "Runs as root preset") {
							hasPresetDeny = true
						}
					}
				}
				for _, msg := range res.AuditDenyMessages {
					hasAuditDeny = true
					allMessages = append(allMessages, msg)
				}
				for _, msg := range res.AuditAllowMessages {
					hasAuditAllow = true
					allMessages = append(allMessages, msg)
				}
			}

			assert.Equal(t, tt.expectDeny, hasDeny, "Deny status mismatch")
			assert.Equal(t, tt.expectAuditDeny, hasAuditDeny, "Audit deny status mismatch")
			assert.Equal(t, tt.expectAuditAllow, hasAuditAllow, "Audit allow status mismatch")
			assert.Equal(t, tt.expectPresetDeny, hasPresetDeny, "Preset deny status mismatch")

			if len(tt.expectedMessages) > 0 {
				for _, expectedMsg := range tt.expectedMessages {
					assert.Contains(t, allMessages, expectedMsg, "Expected message not found")
				}
			}
		})
	}
}

func TestPolicyFieldPathIssues(t *testing.T) {
	// 这个测试演示了 Rego 策略中字段路径写错不会报错，而是静默失败的问题

	rawPolicyWithWrongPath := `
package nri.authz

deny[decision] {
    # 错误的路径：使用 input.container.image 而不是 input.image
    endswith(input.container.image, ":latest")
    decision := {"id": "WRONG-PATH", "message": "This rule won't match"}
}

deny[decision] {
    # 正确的路径
    endswith(input.image, ":latest")
    decision := {"id": "CORRECT-PATH", "message": "This rule will match"}
}
`

	evaluator, err := nrienforcer.NewEvaluator(context.Background())
	if err != nil {
		t.Fatalf("Failed to init OPA: %v", err)
	}

	options := nrienforcer.Options{
		FailurePolicy: "Fail",
	}

	// Add policy - 注意：即使有错误的路径，UpdatePolicy 也会成功！
	err = evaluator.UpdatePolicy(context.Background(), "test-wrong-path", "", rawPolicyWithWrongPath, options)
	if err != nil {
		t.Fatalf("Failed to update policy (unexpected, should succeed even with wrong paths): %v", err)
	}

	// Test input with latest tag
	input := nrienforcer.Input{
		Image: "busybox:latest",
		Spec: &specs.Spec{
			Process: &specs.Process{
				Args: []string{"/bin/sh"},
			},
		},
	}

	results, err := evaluator.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// 检查结果
	hasCorrectRule := false
	hasWrongRule := false
	for _, res := range results {
		for _, msg := range res.DenyMessages {
			if msg == "This rule will match" {
				hasCorrectRule = true
			}
			if msg == "This rule won't match" {
				hasWrongRule = true
			}
		}
	}

	// 验证：只有正确的规则会匹配，错误的路径不会报错也不会匹配
	assert.True(t, hasCorrectRule, "Correct path rule should match")
	assert.False(t, hasWrongRule, "Wrong path rule should NOT match (and won't error either)")

	t.Log("✓ Key insight: Wrong field paths in Rego won't error, they just won't match!")
	t.Log("  - Always test your policies to verify they work as expected")
	t.Log("  - Check logs to see if expected rules are being matched")
}
