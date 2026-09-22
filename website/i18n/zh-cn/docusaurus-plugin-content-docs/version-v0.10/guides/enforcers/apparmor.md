---
sidebar_position: 2
---

# AppArmor

AppArmor 通过 Linux profile 限制文件访问、程序执行和 capabilities 等操作。节点已经支持 AppArmor，且需要内置加固规则或基于路径的控制时，可以从这里开始。

## 使用前提 {#before-you-start}

节点必须启用 AppArmor LSM，文档最低内核要求为 4.15。检查[安装说明](../../getting_started/installation.md)以及所有可能承载工作负载的节点和运行时。启用 vArmor 组件不会自动启用缺失的内核 LSM。

## 编写策略 {#write-a-policy}

将 `spec.policy.enforcer` 设置为 `AppArmor`。可以从 `EnhanceProtect` 和少量[内置规则](../policies_and_rules/built_in_rules/index.md)开始，或使用[自定义 AppArmor 规则](../policies_and_rules/custom_rules.md#apparmor-enforcer)。使用实验建模或允许列表前，先阅读[策略模式](../policies_and_rules/policy_modes/index.md)。

按照[编写策略](../policies_and_rules/writing_policies.md)选择目标并部署，[使用示例](../../getting_started/usage_instructions.md#example)可作为参考。

## 验证执行效果 {#verify-enforcement}

检查策略及其引用的 ArmorProfile，然后检查实际 Pod 的 AppArmor securityContext/annotation。在指定业务容器中验证一个正常操作成功、一个被禁止操作失败。未受约束的容器不能证明 profile 已生效。

审计行为取决于模式和规则限定符。观察模式需要同时考虑执行与审计开关，参见[处置与审计](../policies_and_rules/policy_modes/index.md#disposition-actions-and-auditing)及[审计日志](../../getting_started/usage_instructions.md#audit-logs)。

## 更新与边界 {#updates-and-boundaries}

已附加 profile 的规则可以动态更新。为原本未受保护的容器附加执行器是另一个操作：检查工作负载模板，按需创建新容器，并在 Agent 加载 profile 后验证行为。

AppArmor 不能替代硬件虚拟化或 HTTP 代理；基于路径的规则不检查加密的应用请求。短生命周期进程的审计身份关联也可能不完整，解释事件时参照[使用说明](../../getting_started/usage_instructions.md)。
