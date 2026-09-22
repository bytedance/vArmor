---
sidebar_position: 4
---

# Seccomp

Seccomp 用于缩小容器可调用的系统调用集合。过滤器匹配系统调用编号及支持的参数条件，不提供基于文件路径的策略或 HTTP 请求检查。

## 使用前提 {#before-you-start}

文档最低 Kubernetes 要求为 1.19。检查运行时及[安装说明](../../getting_started/installation.md)，将 `spec.policy.enforcer` 设置为 `Seccomp` 或支持的组合。

## 编写策略 {#write-a-policy}

通过[策略模式](../policies_and_rules/policy_modes/index.md)选择运行时默认配置、针对性加固或适用的允许列表。[自定义规则](../policies_and_rules/custom_rules.md#seccomp-enforcer)介绍系统调用控制。行为建模为实验功能，需要单独启用，不是普通加固的必需前提。

按照[编写策略](../policies_and_rules/writing_policies.md)选择目标，先在专属测试工作负载中部署。

## 验证与更新 {#verify-and-update}

检查生成的 profile 和实际 Pod 的 Seccomp securityContext。在指定业务容器中分别执行允许的操作和应被禁止的操作。

**运行中的容器不会自动采用更新后的 Seccomp 过滤器。** 更新 profile 后，应通过工作负载控制器创建替代容器，等待就绪，再验证行为。策略 Ready 不代表旧容器已经使用新过滤器。

## 审计与限制 {#auditing-and-limitations}

Seccomp 的阻断和日志行为与 AppArmor/BPF 不同。在文档描述的 EnhanceProtect 观察配置下，需要同时启用 `allowViolations` 和 `auditViolations`，且不能存在运行中的行为建模策略。被阻断系统调用不会以 AppArmor/BPF 相同方式生成 vArmor `DENIED` 事件，使用观察模式前阅读[Seccomp 例外](../policies_and_rules/policy_modes/index.md#disposition-actions-and-auditing)。

事件可能标记为 `AUDIT|ALLOWED`，短生命周期进程的身份关联可能不完整。详见[审计日志](../../getting_started/usage_instructions.md#audit-logs)。没有日志不能证明调用被允许或过滤器不存在。
