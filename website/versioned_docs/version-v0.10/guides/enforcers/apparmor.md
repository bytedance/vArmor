---
sidebar_position: 2
---

# AppArmor

Use AppArmor to restrict operations such as file access, program execution and capabilities through Linux AppArmor profiles. It is useful when the nodes already support AppArmor and you need built-in hardening rules or path-based controls.

AppArmor supports restricting socket operations at the kernel layer. For additional destination IP or port matching, use [BPF](bpf.md).

## Before you start

The nodes must have AppArmor LSM enabled; the documented minimum kernel is 4.15. Check [Installation](../../getting_started/installation.md) and the runtime support on every node that can host the workload. Enabling the vArmor component does not enable a missing kernel LSM.

## Write a policy

Select `AppArmor` as `spec.policy.enforcer`. Start with `EnhanceProtect` and a small set of [built-in rules](../policies_and_rules/built_in_rules/index.md), or use the [custom AppArmor rules](../policies_and_rules/custom_rules.md#apparmor-enforcer). Read [Policy Modes](../policies_and_rules/policy_modes/index.md) before using experimental modeling or an allowlist profile.

Follow [Writing Policies](../policies_and_rules/writing_policies.md) for target selection and rollout. The [usage example](../../getting_started/usage_instructions.md#example) provides an AppArmor-specific starting point.

## Verify enforcement

Check the policy and its referenced ArmorProfile, then inspect the actual Pod's AppArmor security context/annotations. Verify a required operation still succeeds and a prohibited operation fails in the selected application container.

AppArmor audit events depend on the mode and rule qualifiers. For an observation rollout, configure both behavior and auditing deliberately; see [Disposition Actions and Auditing](../policies_and_rules/policy_modes/index.md#disposition-actions-and-auditing) and [Audit Logs](../../getting_started/usage_instructions.md#audit-logs).

## Updates and boundaries

Rules in an already attached profile can be updated without recreating the workload. Attaching an enforcer to a previously unprotected container is a different operation: check the workload template and create new containers as required. Confirm the updated behavior after the agents load the profile.

AppArmor is kernel enforcement, not a replacement for hardware virtualization or an HTTP proxy. A path-based rule does not inspect encrypted application requests. Audit attribution for short-lived processes can also be incomplete; use the shared [usage guide](../../getting_started/usage_instructions.md) when interpreting events.
