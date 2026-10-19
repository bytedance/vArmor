# VP / VCP / AP / APM 与策略状态

## 1. 对象职责

- **VarmorPolicy（VP）**：namespace-scoped 用户策略，保护同 namespace 中匹配的 Deployment、StatefulSet、DaemonSet 或 Pod。
- **VarmorClusterPolicy（VCP）**：cluster-scoped 用户策略，可跨 namespace 选择目标；匹配时优先级高于 VP。
- **ArmorProfile（AP）**：manager 为策略生成的内部执行对象，包含实际 Profile、目标和 BehaviorModeling 状态，由 agent 处理。
- **ArmorProfileModel（APM）**：BehaviorModeling 结果对象，保存跨节点行为模型和生成的 Profile；数据量过大时可能使用本地存储，需结合 `storageType` 判断可见性。

链路：`VP/VCP → status.profileName → 同名 AP → agent 节点条件 → Pod 注入/运行时行为`。

## 1.1 生命周期与优先级

VP/VCP 是声明层对象，AP 是由 manager 根据当前策略状态生成的执行层对象，二者不是同一个资源层次。策略变更通常经历“校验/匹配 → AP 创建或更新 → 节点加载 → 新 Pod 注入或 Workload 滚动更新”，任一阶段滞后都可能造成新旧配置并存。

- 先确认策略当前 generation、status 反映的 generation 和 AP 所对应的策略版本是否一致；旧 status 不能证明新配置已经落地。
- VCP 的跨 namespace 目标可能使其与 namespace 内 VP 同时命中；是否覆盖、合并或优先，以实际版本控制器语义、最终 AP/profileName 和 Pod 最终配置为准。
- 删除策略、切换模式或修改 target 后，AP、PodTemplate 和旧 Pod 的清理/更新可能不同步；残留 AP 或旧 Pod 注入不等于当前策略仍在主动生效。
- APM 是行为建模产物，不是普通模式下 AP 的替代品；完成建模仍需确认后续模式切换和 Profile 生成是否成功。

## 1.2 诊断取证层次

策略诊断不能只依据概览中的名称、模式、Enforcer 和 Ready 摘要。按问题选择详情对象：

- 分析策略设计、内置规则、自定义规则、target 或 Enforcer 配置：读取对应 VP/VCP 详情。它是用户声明的策略意图来源。
- 判断规则是否完成编译、是否已加载到目标：结合 VP/VCP 的 `status` 与对应 AP 详情。AP 是 Manager 编译后的实施产物，不应把其生成内容误认为用户原始规则。
- 分析行为建模结果：读取 APM，并结合其状态和存储类型判断可见性。

同名策略可能属于不同资源类型或 namespace。诊断时应使用概览返回的 `kind`、`name`、`namespace` 精确定位，不要根据命名规则猜测 AP 名称。

## 2. target 语义

- `kind` 仅支持 Deployment、StatefulSet、DaemonSet、Pod；
- `name` 与 `selector` 互斥，至少需要一个；
- `selector` 按 Kubernetes label selector 语义匹配 Workload；
- `containers` 为空通常表示业务 containers 全部纳入，initContainers/ephemeralContainers 需单独理解；
- VP 受 namespace 限制，VCP 可以跨 namespace；
- 创建后 `spec.target` 不可修改，目标变化应视为策略生命周期变化；
- 目标还必须满足 Webhook 的匹配标签/对象范围；匹配字段和取值以实际 WebhookConfiguration、部署配置和版本为准，示例 annotation 不能直接作为判据；
- 目标或 container 上的显式 `unconfined` 设置可能优先于策略，需检查 PodTemplate 和实际 Pod。

## 3. policy 语义

### Enforcer

策略可以组合 `AppArmor`、`BPF`、`Seccomp`、`NetworkProxy`，组合名和可用组合随版本/配置变化。不要仅通过字符串猜测能力，需同时看集群配置和节点能力。

### Mode

- **AlwaysAllow**：不施加 vArmor 额外强制访问控制，适合建立对照基线；不等于关闭 Kubernetes 其他安全机制。
- **RuntimeDefault**：使用 vArmor 的运行时默认基线。
- **EnhanceProtect**：以 Allow-by-Default 为主，使用内置规则和自定义规则增强防护。
- **BehaviorModeling**：在指定时间内采集行为并生成 APM，是独立建模阶段。
- **DefenseInDepth**：以 Deny-by-Default/allowlist 使用行为模型或自定义 Profile，支持范围受版本和 enforcer 限制。

各模式的默认 Profile、基线和 Enforcer 差异见 `modules/policy-mode-profiles.md`。模式名以实际版本 CRD 为准；当前本地源码与官方 main 文档中的模式包括 AlwaysAllow、RuntimeDefault、EnhanceProtect、BehaviorModeling、DefenseInDepth。不要把其他产品或旧版本术语当作当前模式。

## 4. 状态语义

VP/VCP：

- `status.profileName`：生成的 Profile/AP 名称；namespace policy 常见形式为 `varmor-{namespace}-{policy}`，cluster policy 常见形式为 `varmor-cluster-{namespace}-{policy}`，以实际 status 为准；
- `status.conditions`：Created、Updated、Ready 等结果，`status=false` 时优先读取 `reason/message`；
- `status.ready`：Profile 是否已被所需 Agents 处理，不代表目标 Pod 一定已注入；
- `status.phase`：常见 Pending、Modeling、Completed、Protecting、Error/Failed 等阶段；
- BehaviorModeling 未完成时，不应把普通模式切换当作可用更新。

AP：

- AP 与策略 `status.profileName` 同名；官方实现中 VP 的 AP 位于策略 namespace，VCP 的 AP 位于
  vArmor 组件 namespace。以实际对象为准，未知时的最小发现路径见 `playbooks/policy.md` 第 2.1 节。
- `status.desiredNumberLoaded`：期望处理并响应的 Agent 数量；
- `status.currentNumberLoaded`：已经处理并响应的 Agent 数量；
- `status.conditions`：可包含失败节点 `nodeName` 和原因。

APM：

- APM 与行为数据上报使用的 Profile 名同名；当前 VP/VCP API 没有独立的 `status.armorProfileModel` 字段；
- `status.desiredNumber` / `status.completedNumber`：期望与已完成上报的节点结果数量；
- `status.ready`：行为模型和生成的 Profile 是否就绪；
- `status.conditions`：节点粒度的建模状态，可包含 `nodeName`、`reason`、`message`；
- `storageType`：顶层存储类型，常见 `CRDInternal`、`LocalDisk`、`PV/PVC`；
- `data.dynamicResult` / `data.profile`：顶层 `data` 下的行为结果与生成 Profile。数据使用外部存储时，CRD 内可能不包含完整内容。

## 5. 常见异常解释

### 策略被拒绝或 Ready=False

检查 target kind/name/selector、模式必需字段、BehaviorModeling 是否启用及 modelingOptions、DefenseInDepth 配置、enforcer 组合、NetworkProxy 参数、策略名长度和 Webhook 校验信息。

### 策略 Ready=True 但没有目标防护

依次区分：selector 没有目标；目标缺少匹配标签；对象/namespace 不在 Webhook 作用范围；PodTemplate 没重新创建；container 被显式 unconfined；VP 与 VCP 重叠，且实际控制器按其版本语义选择或合并结果。

### AP 不存在或长期 Pending

通常指向 manager 未 reconcile、无 Leader、策略未真正接受、目标链未建立或 AP 创建/更新失败。不能直接归因 agent。

### AP 部分加载

`currentNumberLoaded < desiredNumberLoaded` 或存在失败节点条件，按失败节点关联 agent、内核/LSM、运行时、Profile 类型和节点资源。

### 删除/更新后仍有旧防护

检查 Workload PodTemplate、裸 Pod、旧 Pod 的 ownerReferences 和 SecurityContext。`updateExistingWorkloads` 只对支持滚动更新的 Workload 类型有效；Pod 类型需要重新创建。

## 6. BehaviorModeling 专项

重点核对 containerd、BTF、审计来源、建模开关、agent/classifier 资源和节点覆盖。建模无数据时分三段验证：采集能力 → 上报 → manager 汇总/持久化。建模只描述观察到的行为，不证明行为完整，也不自动等于安全许可清单。
