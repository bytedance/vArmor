---
sidebar_position: 0
---

# 编写策略 {#writing-policies}

先定义具体需求：保护哪个工作负载、禁止哪种操作、哪些正常操作必须继续成功，以及需要什么审计证据。先在专属 namespace 验证，再逐步部署。

## 1. 选择执行机制 {#1-choose-the-enforcement-mechanism}

通过[执行器](../enforcers/index.md)将需求映射到能力，核对[安装要求](../../getting_started/installation.md)，再选择兼容[策略模式](policy_modes/index.md)。不同执行器的规则名称和审计开关不能互换。

## 2. 准确选择工作负载 {#2-select-the-workload-precisely}

首次使用命名空间级 VarmorPolicy。target.name 和 target.selector 二选一；kind 支持 Pod、Deployment、StatefulSet、DaemonSet。target 不可变，需要变更时创建新策略。

Deployment target 的 selector 匹配 Deployment 自身 metadata.labels，不只是 Pod template 的标签。目标还需设置 `sandbox.varmor.org/enable: "true"`。排查选择错误时同时检查控制器和生成的 Pod。

VarmorClusterPolicy 优先于匹配的命名空间策略，判断结果前先检查集群策略，见[接口操作](../../getting_started/usage_instructions.md#interface-operations)。

## 3. 从最小规则开始 {#3-start-with-the-smallest-rule-set}

兼容节点可参考 [AppArmor 使用示例](../../getting_started/usage_instructions.md#example)，HTTP 允许列表可使用 [NetworkProxy 快速开始](../enforcers/networkproxy/quick-start.mdx)。一次增加一个限制，语法见[内置规则](built_in_rules/index.md)、[自定义规则](custom_rules.md)和[API](../../getting_started/interface_specification.md)。

| 检查 | 预期 |
| --- | --- |
| 业务必需的正常操作 | 成功 |
| 明确禁止的操作 | 由配置的执行器拒绝 |
| 启用审计的操作 | 身份和动作与测试相符 |

只有执行器支持相应行为时才能使用观察模式。NetworkProxy 使用自己的 qualifiers/defaultAction，allowViolations 不会把它的 deny 变为观察规则。

## 4. 应用并检查实际工作负载 {#4-apply-and-inspect-the-actual-workload}

先创建策略，再创建测试工作负载。对已有控制器工作负载，先阅读 [API](../../getting_started/interface_specification.md) 中 updateExistingWorkloads 的影响，再请求注入或 rollout。

```bash
kubectl apply -f policy.yaml
kubectl get varmorpolicy -n YOUR_NAMESPACE YOUR_POLICY -o yaml
kubectl get armorprofile -n YOUR_NAMESPACE
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o yaml
```

将大写名称替换为自有资源。根据[状态管理](../../getting_started/usage_instructions.md#state-management)检查错误，确认实际容器附加了 profile，或具备 NetworkProxy 注入容器。控制面状态不能代替实际防护验证。

## 5. 验证行为与审计 {#5-verify-behavior-and-audit-evidence}

在目标业务容器分别执行允许和拒绝操作，多容器 Pod 显式指定 kubectl exec -c。按配置关联[审计日志](../../getting_started/usage_instructions.md#audit-logs)，无事件可能是文档规定的静默行为。

网络测试区分代理拒绝、后端响应和连接故障，使用自有后端确认请求是否到达。更新策略后等待实际配置/profile 生效，再重复正反对照。

## 6. 更新、回滚和移除 {#6-update-roll-back-and-remove}

在版本控制中保存已验证策略，一次修改一个需求并保留上一个有效版本。Seccomp 变更需要新容器；NetworkProxy 配置和 Pod 模板有不同生命周期，应先阅读对应指南。

删除策略不等于已有容器已经撤防。根据[使用说明](../../getting_started/usage_instructions.md)检查模板和替代 Pod。临时教程只删除自己创建的资源和专属 namespace。

## 更多示例与工具 {#more-examples-and-tools}

[Policy Advisor](../policy_tools/policy_advisor.md)可生成起始模板，仍需按当前 API 和业务验证。仓库还有[示例](https://github.com/bytedance/vArmor/tree/main/test/examples)和[演示](https://github.com/bytedance/vArmor/tree/main/test/demos)，应选择匹配安装版本的内容。
