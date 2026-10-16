---
slug: /guides/skills/diagnosis
sidebar_position: 3
description: 自动诊断 vArmor 策略与组件异常，定位问题并提供处理建议。
---

# vArmor Diagnosis

vArmor Diagnosis（`varmor-diagnosis`）提供策略与组件自动诊断能力。描述策略未生效、应用出现权限错误或组件运行异常等现象后，助手会自动选择检查步骤，关联配置、状态、事件与日志，协助定位原因并给出处理建议。

## 可以帮你做什么

- 自动检查策略配置、目标匹配、注入与生效情况，排查防护未按预期生效的原因。
- 自动检查 vArmor 组件运行状态，结合相关事件与日志定位组件故障。
- 关联业务异常与防护规则，覆盖节点支持、行为建模及 NetworkProxy 等相关问题。

诊断全程只读，助手给出结论与建议，不修改策略、重启工作负载或调整节点。

## 开始前的准备

按照 [Skills 总览](index.md)的说明，安装完整的 `skills/varmor-diagnosis/` 目录。可以直接分析已有配置、事件和日志，无需连接集群；真实集群排查需要 kubectl 访问及相关资源和日志的读取权限。可选辅助脚本使用 Python 3，无额外 Python 包依赖。

尽量提供集群 context、namespace、一个已知的应用、Pod、策略或节点，以及异常现象和大致发生时间。无需提前找齐所有关联对象。

## 使用示例

排查业务异常：

> 使用 varmor-diagnosis，排查 staging 集群 shop 命名空间里的 Deployment checkout。修改策略约十分钟后开始出现权限错误。请只读排查，说明是否有证据将异常关联到 vArmor。

分析已有材料：

> 使用 varmor-diagnosis，分析这些策略 YAML、Pod 事件和审计片段。不要连接集群，说明目前能确认什么、还缺什么证据。

## 典型使用流程

1. 描述异常现象、受影响的目标及近期变更。
2. 助手自动选择相关检查，关联策略与组件证据。
3. 查看诊断结论、影响范围、置信度、处理建议与验证步骤。

## 结果与使用边界

你会得到已确认事实、可能原因与缺失证据的区分，需要时可整理成正式诊断报告。策略显示 Ready 不单独证明防护已生效，权限错误也不单独证明由 vArmor 引起。

诊断后需要收敛 EnhanceProtect 策略时，可以使用 [vArmor Policy Optimization](policy-optimization.md)。安装步骤与详细用法见[英文说明](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.md)和[中文说明](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.zh_CN.md)。
