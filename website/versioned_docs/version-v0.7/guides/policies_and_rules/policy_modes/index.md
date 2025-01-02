---
slug: /guides/policies_and_rules/policy_modes
sidebar_position: 1
---

# The Policy Modes

## Overview
The modes can be specified through the `spec.policy.mode` field of [VarmorPolicy](../../getting_started/usage_instructions#varmorpolicy) or [VarmorClusterPolicy](../../getting_started/usage_instructions#varmorclusterpolicy) objects. The modes supported by different enforcers are shown in the following table.


|Policy Mode|AppArmor|BPF|Seccomp|Description|
|-----------|--------|---|-------|-----------|
|AlwaysAllow|✔️|✔️|✔️|No mandatory access control rules are imposed on container.|
|RuntimeDefault|✔️|✔️|✔️|Basic protection is provided using the same default policy as the container runtime components (such as containerd's [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go)).|
|EnhanceProtect|✔️|✔️|✔️|- It offers 5 types of [built-in rules](../built_in_rules/index.md) and custom interfaces to meet various protection requirements.<br />- Enhanced protection is based on the RuntimeDefault mode by default. (The `spec.policy.privileged` field is `nil` or `false`)<br />- Also supports enhanced protection on the basis of the AlwaysAllow mode. (The `spec.policy.privileged` field is `true`)|
|BehaviorModeling|✔️|🏗️|✔️|- Utilize BPF and Audit technologies to perform behavior modeling on multiple workloads.<br />- The behavior model will be stored in the corresponding [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) object.<br />- Dynamic switching mode is not supported.<br />- Please refer to the [BehaviorModeling Mode](behavior_modeling.md) for more details.|
|DefenseInDepth|✔️||✔️|- Protect the workloads based on the [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) object.<br />- Please refer to the [DefenseInDepth Mode](defense_in_depth.md) for more details.|

<br />
Note:
* vArmor policy supports dynamic switching of running modes (limited to AlwaysAllow, EnhanceProtect, RuntimeDefault, DefenseInDepth) and updating sandbox rules without having to restart the workloads. However, when using the **Seccomp enforcer**, the workload must be restarted for changes to the **Seccomp Profile** to take effect.
* vArmor supports modifying policies to add new enforcers, but does not support removing enforcers that have been set. In addition, newly added enforcers only take effect for newly created Workloads.

## Experimentals
import DocCardList from '@theme/DocCardList';

<DocCardList />
