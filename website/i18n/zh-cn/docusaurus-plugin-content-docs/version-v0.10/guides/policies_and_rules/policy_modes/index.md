---
slug: /guides/policies_and_rules/policy_modes
sidebar_position: 1
---

# 策略模式

## 概览

您可以通过 [VarmorPolicy](../../getting_started/usage_instructions#varmorpolicy) 或  [VarmorClusterPolicy](../../getting_started/usage_instructions#varmorclusterpolicy) 对象的 `spec.policy.mode` 字段来指定策略的运行模式。不同 enforcers 支持的模式如下表所示。

|运行模式|AppArmor|BPF|Seccomp|NetworkProxy|说明|
|------|--------|----|-------|------------|---|
|AlwaysAllow|✔️|✔️|✔️|✔️|容器上不施加任何强制访问控制规则。|
|RuntimeDefault|✔️|✔️|✔️|✔️|通过使用 containerd 的默认配置文件来提供基础防护。详见 [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go) 和 [seccomp_default](https://github.com/containerd/containerd/blob/main/contrib/seccomp/seccomp_default.go)。|
|EnhanceProtect|✔️|✔️|✔️|✔️|- 预定义的[内置规则](../built_in_rules/index.md)开箱即用。<br />- 可通过可定制的接口根据特定需求定制保护策略。<br />- 支持仅审计和拦截并审计模式，用于监控和审计。<br />- 基于 RuntimeDefault 或 AlwaysAllow 模式生成 AppArmor/BPF 配置文件。|
|BehaviorModeling|✔️|✔️|✔️|🏗️|- 利用 BPF & Audit 技术对工作负载进行行为建模<br />- 行为模型保存在对应的 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对象中<br />- 详情请参阅 [BehaviorModeling 模式](behavior_modeling.md)|
|DefenseInDepth|✔️|🏗️|✔️|✔️|- 通过行为模型或自定义配置文件提供默认拒绝保护。<br />- 提供自定义规则接口和仅审计模式，方便开发和管理配置文件。<br />- 详情请参阅 [DefenseInDepth 模式](defense_in_depth.md)|

<br />

## 处置动作与审计

违规事件将被如何处置、以及在审计事件中记录为何种动作（`DENIED` / `AUDIT` / `ALLOWED`），都由**策略模式**与**规则限定词**共同决定。

### EnhanceProtect：内置规则的处置与审计

EnhanceProtect 模式组合[内置规则](../built_in_rules/index.md)与[自定义规则](../custom_rules.md)进行防护。本节仅描述**内置规则**的处置与审计行为（自定义规则的行为由各自的限定词控制，详见[自定义规则](../custom_rules.md)）。内置规则的行为由下面两个相互正交的开关决定：

- `allowViolations` 决定**拦截还是放行**：`false`（默认）拦截，`true` 放行。
- `auditViolations` 决定**是否产生审计事件**：`true` 留痕，`false`（默认）静默。

> **易踩坑**：拦截与审计相互独立，仅设 `allowViolations=false` 只会拦截、不产生任何事件；想在拦截的同时记录审计日志，需要把 `auditViolations` 也设为 `true`。

| allowViolations | auditViolations | 是否拦截 | 是否产生事件 | action |
| --- | --- | --- | --- | --- |
| false（默认） | false | 拦截 | 否（静默） | — |
| false（默认） | true | 拦截 | 是 | DENIED |
| true | true | 放行 | 是 | AUDIT |
| true | false | 放行 | 否（静默） | — |

> **Seccomp 例外**：受限于 Seccomp 的原理，上表仅适用于 AppArmor 与 BPF。Seccomp 只有在同时设置 `allowViolations=true` 与 `auditViolations=true`（且当前无策略处于 BehaviorModeling 模式）时，才会以放行并记录的方式产生事件（即观察模式）；其余组合一律拦截且不产生任何事件——它无法在拦截的同时输出 `DENIED` 审计日志。此外，Seccomp 产生的事件统一标记为组合动作 `AUDIT|ALLOWED`——因为其审计日志无法区分事件来自 EnhanceProtect 模式（对应 `AUDIT`）还是 DefenseInDepth 模式（对应 `ALLOWED`）。

### DefenseInDepth：Profile 的处置与审计

DefenseInDepth 描述的是组合自定义规则后形成的 **Profile** 的整体处置与审计行为。它使用**允许清单**，未列出的访问属于**隐式拒绝**（无需额外的 `audit` 限定词，AppArmor 内核默认即记录；BPF 支持建设中）：

- `allowViolations` 为 `false`（默认）时，未被允许的访问被拦截并记录为 `DENIED`。
- `allowViolations` 为 `true` 时，未被允许的访问被放行并记录为 `ALLOWED`。

> **Seccomp 例外**：在 DefenseInDepth 下，`allowViolations=true` 时被放行的系统调用同样会被记录，但受限于 Seccomp 原理，其事件统一标记为组合动作 `AUDIT|ALLOWED`。

> 请注意区分两种"拒绝"：EnhanceProtect 生成的是**显式 `deny` 规则**，默认静默；而 DefenseInDepth 用的是**允许清单**的隐式拒绝，默认即记录。详情请参阅 [DefenseInDepth 模式](defense_in_depth.md)。

### NetworkProxy：自定义网络规则的处置与审计

不管处于 EnhanceProtect 还是 DefenseInDepth 模式，用户自定义的 NetworkProxy 规则的处置与审计行为都与 AppArmor / BPF / Seccomp 不同：它**不受 `allowViolations` 控制，自成一体**——拦截与审计行为完全由自身的规则限定词与 `defaultAction` 决定，且**永远不会产生 `ALLOWED`**（只映射 `DENIED` / `AUDIT`）。详见[自定义规则](../custom_rules.md)。

# 注意事项

* vArmor 策略支持动态切换运行模式、更新沙箱规则，而无需重启工作负载。以下场景需特殊处理：
  * 使用 **Seccomp enforcer** 时，需要重启工作负载来使 **Seccomp Profile** 的变更生效。
  * 建模完成后，方可将 **BehaviorModeling** 切换为其他模式。
  * 从其他模式切换到 **BehaviorModeling** 或建模已经完成时，您需要更新建模时长并重启目标工作负载，以重新启动行为建模过程。
* vArmor 支持修改策略为其添加新的 enforcer，新添加的 enforcer 仅对新创建的 Workloads 生效。
* vArmor 支持修改策略移除 BPF enforcer。
* 使用 **NetworkProxy enforcer** 时，建议配合 AppArmor 或 BPF enforcer 使用，移除目标容器的 *NET_ADMIN* 权限，并禁止创建及切换至 [ProxyUID](../../../getting_started/interface_specification.md#networkproxyconfig)，从而防止其绕过网络代理规则。
* 使用 **NetworkProxy enforcer** 时，建议禁止业务容器访问 Pod CIDR 内所有网络代理边车容器的[管理端口(proxyAdminPort)](../../../getting_started/interface_specification.md#networkproxyconfig)。

## 实验特性

import DocCardList from '@theme/DocCardList';

<DocCardList />
