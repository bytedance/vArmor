---
slug: /guides/skills/policy-optimization
sidebar_position: 2
description: 自动分析与调优 EnhanceProtect 策略，减少防护规则对必要业务行为的误伤。
---

# vArmor Policy Optimization

vArmor Policy Optimization（`varmor-policy-optimization`）将策略校验、观察日志分析与候选策略生成自动化，减少手工调优工作。从符合安全目标的 EnhanceProtect 策略出发，助手自动识别与必要业务行为冲突的规则并提出优化建议；由你选择删除范围后，再生成候选策略供你审核，经你授权后才由助手更新策略。

## 可以帮你做什么

- 自动校验已有策略，或根据你确认的防护要求准备草稿。
- 自动分析观察日志、关联策略规则并解释业务冲突，供你审核取舍。
- 根据审核决定生成候选策略与变更说明，引导验证与后续迭代。

适用于 EnhanceProtect 模式的命名空间级 `VarmorPolicy` 和集群级 `VarmorClusterPolicy`。优化通过删除选定的已有规则完成；不优化 DefenseInDepth 策略，也不生成 BehaviorModeling 模型。

## 开始前的准备

按照 [Skills 总览](index.md)的说明，安装完整的 `skills/varmor-policy-optimization/` 目录。本地策略检查需要 Python 3 与 PyYAML；真实业务观察还需要通过 kubectl 访问目标 vArmor 集群，并保持采集环境在约定窗口内持续运行。

提供已有策略 YAML，或计划保护的工作负载、集群 context 与 namespace，并说明准备覆盖的业务场景。

## 使用示例

先在本地检查策略：

> 使用 varmor-policy-optimization，检查 ./checkout-policy.yaml 是否适合 EnhanceProtect 观察。说明需要注意的内容，不要连接集群或下发。

准备一轮优化：

> 帮我优化 staging 集群 shop 命名空间 Deployment checkout 的 EnhanceProtect 策略。我会测试启动、正常请求、重试和定时任务。先展示策略与观察计划，我确认后再开始。

## 典型使用流程

1. 审核初始策略，约定要覆盖的业务场景与观察窗口。
2. 授权下发观察策略，采集就绪后运行业务。
3. 查看自动分析结果，选择删除、保留或继续观察。
4. 审核候选策略及变更，确认更新，再按需进行下一轮。

每轮都有保存的任务记录，可以通过其路径稍后继续，也可以换一个会话接着处理。

## 结果与使用边界

你会得到规则分析与审核决定；有确认删除项时，还会得到候选策略、变更说明，以及验证和回滚建议。策略变更需要你的审核与授权。

观察阶段的自定义 RawRules 仍可能阻断请求或操作，助手会在运行业务前说明影响。是否完成优化取决于业务覆盖情况，日志安静不能单独作为判断依据；证据缺失或观察期间策略变化可能导致无法生成删除候选。最终策略不会自动切换为阻断模式。

安装步骤与完整流程见[英文说明](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.md)和[中文说明](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.zh_CN.md)。
