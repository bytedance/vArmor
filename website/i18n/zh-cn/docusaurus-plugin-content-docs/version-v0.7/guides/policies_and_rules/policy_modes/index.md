---
slug: /guides/policies_and_rules/policy_modes
sidebar_position: 1
---

# 策略模式

## 概览

您可以通过 [VarmorPolicy](../../getting_started/usage_instructions#varmorpolicy) 或  [VarmorClusterPolicy](../../getting_started/usage_instructions#varmorclusterpolicy) 对象的 `spec.policy.mode` 字段来指定策略的运行模式。不同 enforcers 支持的模式如下表所示。

|运行模式|AppArmor|BPF|Seccomp|说明|
|------|--------|----|-------|---|
|AlwaysAllow|✔️|✔️|✔️|在容器启动时不对其施加任何强制访问控制|
|RuntimeDefault|✔️|✔️|✔️|使用与容器运行时组件相同的默认策略（如 containerd 的 [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go)）进行基础防护|
|EnhanceProtect|✔️|✔️|✔️|- 支持 5 类 [内置规则](../built_in_rules/index.md) 和自定义接口，以满足不同的防护需求。<br />- 默认在 RuntimeDefault 模式的基础上进行增强防护（当 `spec.policy.enhanceProtect.privileged` 为 `nil` 或 `false` 时）<br />- 支持在 AlwaysAllow 模式的基础上进行增强防护（当 `spec.policy.enhanceProtect.privileged` 为 `true`）|
|BehaviorModeling|✔️|🏗️|✔️|- 利用 BPF & Audit 等技术同时对多个工作负载进行行为建模<br />- 行为模型保存在对应的 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对象中<br />- 不可切换防护模式<br />- 请参见 [BehaviorModeling 模式](behavior_modeling.md)|
|DefenseInDepth|✔️||✔️|- 基于行为模型 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对工作负载进行防护<br />- 请参见 [DefenseInDepth 模式](defense_in_depth.md)|

<br />

注意：
* vArmor 策略支持动态切换运行模式（限 EnhanceProtect, RuntimeDefault, AlwaysAllow, DefenseInDepth）、更新沙箱规则，而无需重启工作负载。但当使用 **Seccomp enforcer** 时，需要重启工作负载来使 **Seccomp Profile** 的变更生效。
* vArmor 支持修改策略为其添加新的 enforcer，但不支持删除已经设置的 enforcer。新添加的 enforcer 仅对新创建的 Workloads 生效。


## 实验特性
import DocCardList from '@theme/DocCardList';

<DocCardList />
