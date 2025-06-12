# 策略模式

[English](README.md) | 简体中文

## 概览

可通过 [VarmorPolicy](../../../getting_started/usage_instructions.zh_CN.md#varmorpolicy) 或 [VarmorClusterPolicy](../../../getting_started/usage_instructions.zh_CN.md#varmorclusterpolicy) 对象的 `spec.policy.mode` 字段来指定策略的运行模式。不同 enforcers 支持的模式如下表所示。

|运行模式|AppArmor|BPF|Seccomp|说明|
|------|--------|----|-------|---|
|AlwaysAllow|✔️|✔️|✔️|容器上不施加任何强制访问控制规则。|
|RuntimeDefault|✔️|✔️|✔️|通过使用 containerd 的默认配置文件来提供基础防护。详见 [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go) 和 [seccomp_default](https://github.com/containerd/containerd/blob/main/contrib/seccomp/seccomp_default.go)。|
|EnhanceProtect|✔️|✔️|✔️|- 预定义的[内置规则](../built_in_rules.zh_CN.md)开箱即用。<br />- 可通过可定制的接口根据特定需求定制保护策略。<br />- 支持仅报警和报警拦截模式，用于监控和审计。<br />- 基于 RuntimeDefault 或 AlwaysAllow 模式生成 AppArmor/BPF 配置文件。|
|BehaviorModeling|✔️|🏗️|✔️|- 利用 BPF & Audit 技术对工作负载进行行为建模<br />- 行为模型保存在对应的 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对象中<br />- 不支持动态切换运行模式<br />- 详情请参阅 [BehaviorModeling 模式](behavior_modeling.zh_CN.md)|
|DefenseInDepth|✔️|🏗️|✔️|- 通过行为模型或自定义配置文件提供默认拒绝保护。<br />- 提供自定义规则接口和仅报警模式，方便开发和管理配置文件。<br />- 详情请参阅 [DefenseInDepth 模式](defense_in_depth.zh_CN.md)|

<br />

注意：
* vArmor 策略支持动态切换运行模式（限 EnhanceProtect, RuntimeDefault, AlwaysAllow, DefenseInDepth）、更新沙箱规则，而无需重启工作负载。但当使用 Seccomp enforcer 时，需要重启工作负载来使 Seccomp Profile 的变更生效。
* vArmor 支持修改策略为其添加新的 enforcer，新添加的 enforcer 仅对新创建的 Workloads 生效。
* vArmor 支持修改策略移除 BPF enforcer。


## 实验特性

* [BehaviorModeling 模式](behavior_modeling.zh_CN.md)
* [DefenseInDepth 模式](defense_in_depth.zh_CN.md)
