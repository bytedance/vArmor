---
sidebar_position: 4
---

# Seccomp

Use Seccomp to reduce the system calls available to a container. A Seccomp filter matches syscall numbers and supported argument conditions; it does not provide pathname-based file policy or HTTP request inspection.

## Before you start

The documented Kubernetes minimum is 1.19. Check the container runtime and [Installation](../../getting_started/installation.md). Select `Seccomp` or a supported combination as `spec.policy.enforcer`.

## Write a policy

Use [Policy Modes](../policies_and_rules/policy_modes/index.md) to choose between a runtime default, targeted hardening, or an allowlist where appropriate. [Custom Rules](../policies_and_rules/custom_rules.md#seccomp-enforcer) describes custom syscall controls. Behavior modeling is experimental and requires a separate installation option; do not enable it as an implicit prerequisite for ordinary hardening.

Follow [Writing Policies](../policies_and_rules/writing_policies.md) to select the workload and limit the first rollout to a dedicated test target.

## Verify and update

Check the generated profile and the actual Pod's Seccomp security context. Then test a permitted syscall-dependent operation and an operation that should be blocked, using the selected application container.

**A running container does not pick up a changed Seccomp filter.** After a profile update, recreate the affected containers through the workload controller, wait for readiness, and repeat the behavioral checks.

## Auditing and limitations

Seccomp's blocking and logging behavior differs from AppArmor and BPF. In the documented EnhanceProtect observation configuration, both `allowViolations` and `auditViolations` must be true, with no active behavior-modeling policy. Blocked syscalls do not produce vArmor `DENIED` events in the same way as AppArmor/BPF. Read the [Seccomp exceptions](../policies_and_rules/policy_modes/index.md#disposition-actions-and-auditing) before depending on an audit-only rollout.

The audit stream can report `AUDIT|ALLOWED`, and attribution for short-lived processes can be incomplete. See [Audit Logs](../../getting_started/usage_instructions.md#audit-logs). Check the syscall result as well as the audit configuration when troubleshooting.
