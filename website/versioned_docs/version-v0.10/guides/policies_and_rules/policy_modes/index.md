---
slug: /guides/policies_and_rules/policy_modes
sidebar_position: 1
---

# The Policy Modes

## Overview

The modes can be specified through the `spec.policy.mode` field of [VarmorPolicy](../../getting_started/usage_instructions#varmorpolicy) or [VarmorClusterPolicy](../../getting_started/usage_instructions#varmorclusterpolicy) objects. The modes supported by different enforcers are shown in the following table.

|Policy Mode|AppArmor|BPF|Seccomp|NetworkProxy|Description|
|-----------|--------|---|-------|------------|-----------|
|AlwaysAllow|✔️|✔️|✔️|✔️|No mandatory access control rules are imposed on container.|
|RuntimeDefault|✔️|✔️|✔️|✔️|Basic protection is provided by using the default profile of containerd. See [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go) and [seccomp_default](https://github.com/containerd/containerd/blob/main/contrib/seccomp/seccomp_default.go).|
|EnhanceProtect|✔️|✔️|✔️|✔️|- Predefined [Built-in Rules](../built_in_rules/index.md) are ready to use out of the box.<br />- Tailor protection policies to specific requirements via customizable interfaces.<br />- Support Audit-Only and Interception-with-Audit modes for monitoring and auditing.<br />- Generate AppArmor/BPF profiles based on RuntimeDefault or AlwaysAllow modes.|
|BehaviorModeling|✔️|✔️|✔️|🏗️|- Uses BPF and audit technologies to perform behavior modeling across workloads.<br />- Behavior models are stored in the corresponding [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) object.<br />- See [BehaviorModeling Mode](behavior_modeling.md) for details.|
|DefenseInDepth|✔️|🏗️|✔️|✔️|- Provide Deny-by-Default protection via the behavior model or custom profiles.<br />- Provide custom rule interfaces and audit-only mode to develop and manage profiles.<br />- See [DefenseInDepth Mode](defense_in_depth.md) for details.|

<br />

## Disposition Actions and Auditing

Which `action` (`DENIED` / `AUDIT` / `ALLOWED`) a violation event ultimately produces is determined jointly by the **policy mode** and the **rule qualifiers**.

### EnhanceProtect: Disposition and Auditing of Built-in Rules

The EnhanceProtect mode protects workloads by combining [built-in rules](../built_in_rules/index.md) and [custom rules](../custom_rules.md). This section describes only the disposition and auditing behavior of the **built-in rules** (the behavior of custom rules is controlled by their own qualifiers, see [Custom Rules](../custom_rules.md)). The built-in rules' behavior is governed by the following two orthogonal switches:

- `allowViolations` decides **block or allow**: `false` (default) blocks, `true` allows.
- `auditViolations` decides **whether an audit event is produced**: `true` logs, `false` (default) stays silent.

> **Common pitfall**: Blocking and auditing are independent — setting `allowViolations=false` alone only blocks and produces no event; to obtain a `DENIED` audit log while blocking, you must also set `auditViolations=true`.

| `allowViolations` | `auditViolations` | Blocked | Event produced | `action` |
| --- | --- | --- | --- | --- |
| `false` (default) | `false` | Yes | No (silent) | — |
| `false` (default) | `true` | Yes | Yes | `DENIED` |
| `true` | `true` | No | Yes | `AUDIT` |
| `true` | `false` | No | No (silent) | — |

> **Seccomp exception**: Due to how Seccomp works, the table above applies only to AppArmor and BPF. Seccomp produces an event (allowed and logged, i.e. observation mode) only when both `allowViolations=true` and `auditViolations=true` are set (and no policy is currently in the BehaviorModeling mode); all other combinations block silently and produce no event — it cannot emit a `DENIED` audit log while blocking. In addition, events produced by Seccomp are uniformly marked with the combined action `AUDIT|ALLOWED`, because its audit log cannot tell whether an event comes from the EnhanceProtect mode (which maps to `AUDIT`) or the DefenseInDepth mode (which maps to `ALLOWED`).

### DefenseInDepth: Disposition and Auditing of the Profile

DefenseInDepth describes the overall disposition and auditing behavior of the **Profile** formed by combining the custom rules. It uses an **allowlist** (any access not listed is an **implicit deny**), which requires no extra `audit` qualifier — the AppArmor kernel logs it by default (BPF support is under construction):

- When `allowViolations` is `false` (default), disallowed access is blocked and logged as `DENIED`.
- When `allowViolations` is `true`, disallowed access is allowed and logged as `ALLOWED`.

> **Seccomp exception**: Under DefenseInDepth, when `allowViolations=true` the allowed syscalls are logged as well, but due to how Seccomp works these events are uniformly marked with the combined action `AUDIT|ALLOWED` (see the Seccomp exception above).

> Note the distinction between the two kinds of "deny": EnhanceProtect generates **explicit `deny` rules** that are silent by default, whereas DefenseInDepth relies on the **implicit deny** of an allowlist, which is logged by default. See [The DefenseInDepth Mode](defense_in_depth.md) for details.

### NetworkProxy: Disposition and Auditing of Custom Network Rules

Whether in the EnhanceProtect or the DefenseInDepth mode, the disposition and auditing behavior of user-defined NetworkProxy rules differs from that of AppArmor / BPF / Seccomp: it is **not governed by `allowViolations` and is self-contained** — its blocking and auditing behavior is determined entirely by its own rule qualifiers and `defaultAction`, and it **never produces `ALLOWED`** (it maps only to `DENIED` / `AUDIT`). See [Custom Rules](../custom_rules.md) for details.

## Notes

* vArmor policy supports dynamic switching the running mode and updating sandbox rules without restarting the workloads. The following scenarios require special handling:
  * When using the **Seccomp enforcer**, the workload needs to be restarted for changes to the **Seccomp Profile** to take effect.
  * The **BehaviorModeling** mode can only be switched to other modes after the modeling is completed.
  * When switching to **BehaviorModeling** mode from other modes or when the modeling has already been completed, you need to update the modeling duration and restart the target workload to restart the modeling process.
* vArmor supports modifying policies to add new enforcers, and the newly added enforcers only take effect on newly created Workloads.
* vArmor supports modifying policies to remove the BPF enforcer.
* When using the **NetworkProxy enforcer**, it is recommended to work with the AppArmor/BPF enforcer to drop the *NET_ADMIN* capability of the target container and prohibit creation of and switching to the [ProxyUID](../../../getting_started/interface_specification.md#networkproxyconfig), so as to prevent it from bypassing network proxy rules.
* When using the **NetworkProxy enforcer**, it is recommended to block business containers from accessing the [admin ports](../../../getting_started/interface_specification.md#networkproxyconfig) of all network proxy sidecars in the Pod CIDR.

## Experimentals

import DocCardList from '@theme/DocCardList';

<DocCardList />
