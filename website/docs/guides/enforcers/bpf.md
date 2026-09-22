---
sidebar_position: 3
---

# BPF

The BPF enforcer uses Linux BPF LSM hooks to enforce controls over files, execution, capabilities, network operations, ptrace and mounts. Choose it for the operations exposed by vArmor's BPF rules, not as a general-purpose eBPF programming interface.

## Before you start

The documented prerequisites are Linux 5.10+ on x86_64 or 6.6+ on arm64, containerd 1.6.0+, and an enabled BPF LSM. Enable `bpfLsmEnforcer.enabled` in the Helm installation after checking the nodes. See [Installation](../../getting_started/installation.md); the kernel version alone does not establish that BPF LSM is enabled.

## Write a policy

Select `BPF` as `spec.policy.enforcer`, or a supported combination. Use the [built-in rules](../policies_and_rules/built_in_rules/index.md) and [custom BPF rules](../policies_and_rules/custom_rules.md#bpf-enforcer) for the operations you need. `DefenseInDepth` is not supported with BPF; check the [mode documentation](../policies_and_rules/policy_modes/index.md) before choosing a mode.

BPF network rules control socket and destination properties at the kernel layer. They do not match decrypted HTTP paths, methods or injected headers. Choose NetworkProxy when those application-level controls are needed; check both layers if combining them.

## Verify and update

Use [Writing Policies](../policies_and_rules/writing_policies.md) to select the workload. Check policy and ArmorProfile status, then test permitted and prohibited operations in the actual protected container. Consult [Audit Logs](../../getting_started/usage_instructions.md#audit-logs) to correlate events with the workload.

Rules for a workload already protected by BPF can be updated dynamically. Adding the enforcer to an existing workload and changing its target are separate lifecycle operations; follow [Usage Instructions](../../getting_started/usage_instructions.md). A successful policy update alone is not a behavioral test.

## Limits and performance

Only the operations and matching semantics exposed by vArmor's BPF API are supported. Do not assume that every AppArmor rule has an identical BPF equivalent. Rule-specific limits belong to the [custom rule reference](../policies_and_rules/custom_rules.md), and measurements belong to [Performance](../performance/index.md); benchmark results are not a universal overhead guarantee.
