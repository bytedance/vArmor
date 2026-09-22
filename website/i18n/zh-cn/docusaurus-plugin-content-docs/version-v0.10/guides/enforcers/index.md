---
sidebar_position: 1
sidebar_label: 执行器
---

# 执行器：概览与选择 {#enforcers-overview-and-selection}

从需要控制的行为出发选择执行器，再检查节点和工作负载的运行前提。执行器提供执行机制，策略模式和规则共同决定允许哪些行为。

| 目标 | 建议入口 | 主要前提 |
| --- | --- | --- |
| 限制文件访问和程序执行 | [AppArmor](apparmor.md) 或 [BPF](bpf.md) | 节点启用对应的 Linux LSM |
| 限制系统调用 | [Seccomp](seccomp.md) | 更新过滤规则需要创建新容器 |
| 在内核层限制 socket 操作及目标 IP/端口 | [BPF](bpf.md) | 满足内核和运行时要求；不检查 HTTP 路径 |
| 限制 HTTP 请求、TLS 目标，或通过 MITM 检查 HTTPS | [NetworkProxy](networkproxy/index.md) | 容器注入、流量重定向，以及 MITM 所需的应用信任配置 |

## 选择模式和作用域 {#choose-a-mode-and-scope}

通过[策略模式](../policies_and_rules/policy_modes/index.md)选择兼容的模式。`EnhanceProtect` 增加指定的限制；支持 `DefenseInDepth` 的执行器可以使用允许列表。`BehaviorModeling` 为实验功能，需要显式启用，且不支持 NetworkProxy。BPF 不支持 `DefenseInDepth`。

`VarmorPolicy` 选择同命名空间的工作负载；`VarmorClusterPolicy` 具有集群作用域，优先于匹配的命名空间策略。首次使用应限制在专属命名空间和明确的目标上，参见[编写策略](../policies_and_rules/writing_policies.md)。

## 组合执行器 {#combining-enforcers}

`AppArmorSeccomp`、`AppArmorNetworkProxy` 等受支持的组合可以在同一策略中覆盖不同操作。每个执行器仍有各自的依赖、更新方式和审计语义。组合不会使原本不支持的模式变为可用，也不会使某层允许覆盖另一层的拒绝。

选择组合前检查[执行器字段](../../getting_started/interface_specification.md#policy)。NetworkProxy 作用于 Pod 网络命名空间中的重定向流量，不应从其他执行器的容器选择能力推导出逐容器网络隔离。

## 下一步 {#next-steps}

1. 阅读[安装](../../getting_started/installation.md)，核对环境及已启用组件。
2. 按[编写策略](../policies_and_rules/writing_policies.md)创建和验证策略。
3. 通过[使用说明](../../getting_started/usage_instructions.md)查看状态与操作，通过[指标](../../getting_started/metrics.md)监控组件。
