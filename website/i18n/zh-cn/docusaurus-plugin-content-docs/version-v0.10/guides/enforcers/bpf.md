---
sidebar_position: 3
---

# BPF

BPF 执行器使用 Linux BPF LSM hook，对文件、程序执行、capabilities、网络操作、ptrace 和 mount 等进行控制。它提供的是 vArmor 规则暴露的能力，并非通用 eBPF 编程接口。

## 使用前提 {#before-you-start}

文档要求 x86_64 上 Linux 5.10+、arm64 上 Linux 6.6+、containerd 1.6.0+，并启用 BPF LSM。核对节点后通过 Helm 的 `bpfLsmEnforcer.enabled` 启用，详见[安装](../../getting_started/installation.md)。内核版本满足要求不代表 BPF LSM 已开启。

## 编写策略 {#write-a-policy}

选择 `BPF` 或受支持的组合，使用[内置规则](../policies_and_rules/built_in_rules/index.md)或[自定义 BPF 规则](../policies_and_rules/custom_rules.md#bpf-enforcer)。BPF 不支持 `DefenseInDepth`，选择前核对[策略模式](../policies_and_rules/policy_modes/index.md)。

BPF 网络规则控制内核层的 socket 和目标属性，不匹配解密后的 HTTP 路径、方法或注入头。需要这些控制时选择 NetworkProxy；组合使用时需要同时检查两层。

## 验证与更新 {#verify-and-update}

按照[编写策略](../policies_and_rules/writing_policies.md)选择工作负载，检查策略和 ArmorProfile 状态，并在实际受保护的业务容器中验证允许与拒绝操作。通过[审计日志](../../getting_started/usage_instructions.md#audit-logs)关联事件与工作负载。

已有 BPF 保护的工作负载可以动态更新规则。添加执行器与改变目标有各自的生命周期要求，参见[使用说明](../../getting_started/usage_instructions.md)。策略更新成功本身不是行为测试。

## 限制与性能 {#limits-and-performance}

支持范围以 vArmor BPF API 的操作及匹配语义为准，不能假定每条 AppArmor 规则都有完全等价的 BPF 实现。具体规则限制见[自定义规则](../policies_and_rules/custom_rules.md)，测量结果见[性能](../performance/index.md)；基准数据不等于所有负载的开销保证。
