# 策略未生效诊断路标

## 入口信号

- VP/VCP `ready=false`、phase 异常或 conditions 报错；
- AP 不存在、Pending，或 `currentNumberLoaded < desiredNumberLoaded`；
- 策略/AP 健康，但 Pod 没有 vArmor 注入痕迹；
- Pod 已注入但实际没有约束，或审计事件与预期不符。

## 五段定位

1. **匹配**：target kind/name/selector、namespace、VCP 优先级、匹配标签、container 范围和 unconfined；
2. **编译**：策略 mode、enforcer、模式专属字段、规则和 NetworkProxy 配置；
3. **注入**：Webhook 规则、Service/Endpoint/证书、最终 Pod SecurityContext/annotation；
4. **加载**：AP 节点条件、目标节点 agent、Profile 类型和节点能力；
5. **执行**：事件中的 Profile/enforcer/action/Pod UID/时间与实际业务行为。

在“注入”与“加载”之间补充 Workload 生命周期判断：比较 PodTemplate、实际 Pod 的创建时间和 ownerReferences，确认当前 Pod 是否由包含新注入的模板创建。这样可以把“策略已更新但旧 Pod 仍运行”与真正的 Webhook/Agent 故障区分开。

## 典型场景

### Ready=False

先看 conditions 的 reason/message，再关联 manager 和 validating webhook。不要先改规则。

### Ready=True 但 AP 不存在或无目标

核对 selector 实际是否命中 Workload，以及是否把 Ready 误解为“有业务目标”。VCP 可能优先覆盖 VP。

### AP 部分节点未加载

根据失败 nodeName 逐节点关联 agent、kernel/LSM/BTF、runtime 和 Profile 加载证据。

### AP 完整但 Pod 没注入

核对 Webhook 配置和匹配标签、Pod/Workload API 版本、target kind、PodTemplate 创建时间，以及是否显式 unconfined。

### Pod 已注入但行为未受约束

核对 Pod 实际使用的 Profile、节点加载状态、enforcer 对应字段和 Pod 是否为旧实例。Seccomp 更新尤其需要重建 Workload。

### NetworkProxy 未生效

依次检查 proxy annotation、initContainer、sidecar readiness、Secret/证书、重定向、ProxyUID/端口、规则层级和 HTTPS MITM；不要把 L7 path/method 未命中直接解释为 L4 网络故障。

## Enforcer 与最终配置对照

将策略声明的 enforcer 与 AP 内容、实际 Pod 引用、节点加载状态和运行时事件逐项对照。VP/VCP 重叠时，以最终 AP 归属和 Pod 实际配置判断；多个 enforcer 同时存在时，先找出最早且能解释业务现象的拒绝层。跨层冲突和 NetworkProxy 规则层次见 `enforcer-conflicts.md`。

## 结论要求

必须明确“未匹配/未编译/未注入/模板已注入但 Pod 未更新/未加载/已加载但未触发/已触发且被允许/已触发且被拒绝/业务问题/证据不足”中的哪一种；如果只能证明链路中断，报告中不要声称已定位根因。
