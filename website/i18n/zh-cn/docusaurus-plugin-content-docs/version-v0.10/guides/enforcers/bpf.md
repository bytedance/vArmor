---
sidebar_position: 3
---

# BPF

BPF 强制访问控制器使用 Linux BPF LSM hook，对文件、程序执行、capabilities、网络操作、ptrace 和 mount 等进行控制。它提供的是 vArmor 规则暴露的能力，并非通用 eBPF 编程接口。

## 使用前提 {#before-you-start}

需要 x86_64 上 Linux 5.10+、arm64 上 Linux 6.6+、containerd 1.6.0+，并启用 BPF LSM。核对节点后通过 Helm 的 `bpfLsmEnforcer.enabled` 启用，详见[安装](../../getting_started/installation.md)。内核版本满足要求不代表 BPF LSM 已开启。

## 编写策略 {#write-a-policy}

选择 `BPF` 或受支持的组合，使用[内置规则](../policies_and_rules/built_in_rules/index.md)或[自定义 BPF 规则](../policies_and_rules/custom_rules.md#bpf-enforcer)。BPF 不支持 `DefenseInDepth`，选择前核对[策略模式](../policies_and_rules/policy_modes/index.md)。

BPF 网络规则控制内核层的 socket 和目标属性，不匹配解密后的 HTTP 路径、方法或注入头。需要这些控制时选择 NetworkProxy；组合使用时需要同时检查两层。

BPF 出站规则还支持按 Kubernetes 资源描述目标：`toServices` 匹配 Service 及其后端端点，`toPods` 匹配所选 Pod 及端口。配置方式和使用条件见 [NetworkEgressRule](../../getting_started/interface_specification.md#networkegressrule)；使用 `toPods` 前需启用 [Pod 出站访问控制](../../getting_started/installation.md#enable-pod-egress-control)。

## 验证与更新 {#verify-and-update}

按照[编写策略](../policies_and_rules/writing_policies.md)选择工作负载，检查策略和 ArmorProfile 状态，并在实际受保护的业务容器中验证允许与拒绝操作。通过[审计日志](../../getting_started/usage_instructions.md#audit-logs)关联事件与工作负载。

已有 BPF 保护的工作负载可以动态更新规则。添加强制访问控制器与改变目标有各自的生命周期要求，参见[使用说明](../../getting_started/usage_instructions.md)。更新策略后，验证受影响的操作。

## 限制与性能 {#limits-and-performance}

每节点最多同时为 **256 个容器**启用 BPF 防护。每份生成配置的文件、程序执行和网络规则分别最多 **64 条**；挂载规则最多 **50 或 64 条**，取决于节点能力。网络额度由 socket 与出站规则共用，内置规则和自定义规则共同计数。详见[规则数量与节点容量](../policies_and_rules/custom_rules.md#bpf-rule-and-container-limits)。

支持范围以 vArmor BPF API 的操作及匹配语义为准，不能假定每条 AppArmor 规则都有完全等价的 BPF 实现。具体规则限制见[自定义规则](../policies_and_rules/custom_rules.md)，测量结果见[性能](../performance/index.md)；部署前应结合实际业务负载评估开销。
