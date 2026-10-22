---
slug: /guides/skills/network-advisor
sidebar_position: 3
description: 为应用推荐网络访问策略，并引导审核、验证与上线。
---

# 网络白名单助手

网络白名单助手（`varmor-network-advisor`）帮助你确定应用需要哪些对外访问，并推荐合适的网络访问策略。描述应用与业务需求后，助手会协助准备 NetworkProxy 白名单策略，引导你完成审核、测试与上线。

## 可以帮你做什么

- 为新应用准备网络访问策略，或调整兼容的已有策略。
- 结合你的需求与应用访问情况推荐权限，并解释每项权限的放行范围。
- 审核必要访问，验证允许与拒绝的请求，并随业务需求变化调整策略。

## 开始前的准备

按照 [Skills 总览](index.md)的说明，安装完整的 `skills/varmor-network-advisor/` 目录。执行任务需要 Python 3.9+、kubectl，以及 v0.10 或以上版本的 vArmor NetworkProxy。助手会核对所选流程需要的实际能力与权限。

提供集群 context、namespace、应用名称或 Pod 标签；如果已有策略，也一并提供。说明哪些业务场景必须正常运行。应用尚未创建时也可以开始准备，或先只要求生成草稿。

## 使用示例

从策略推荐开始：

> 使用 varmor-network-advisor，为 staging 集群 shop 命名空间的 Deployment checkout 推荐网络访问策略。下单和查单业务需要正常运行。先说明方案，暂不部署。

已有明确访问需求：

> 这个应用需要访问支付 API 和内部库存服务。请帮我明确所需访问范围，准备策略草稿供审核，暂不下发。

## 典型使用流程

1. 描述应用及访问需求，审核助手提出的策略与观察方案。
2. 授权开始观察，助手确认采集就绪后，由你创建或重建目标 Pod，并运行有代表性的业务场景。
3. 审核推荐权限，判断哪些访问属于必要业务。
4. 准备好后授权拦截测试，验证允许与拒绝的访问，再决定保留或调整策略。

已有明确需求时，也可以直接准备可审核草稿并进入验证。应用标签及工作负载、Pod 的生命周期由你管理，助手负责策略准备和已授权的策略变更。

## 结果与使用边界

复用已有策略时，本 Skill 保留系统防护模式与规则，聚焦 NetworkProxy 网络访问控制。需要收敛 EnhanceProtect 策略中的系统防护规则时，请使用 [策略自动优化](policy-optimization.md)；遇到策略未生效或组件异常时，请使用 [自动诊断](diagnosis.md)。

你会得到策略草稿、权限范围说明、审核记录与验证结果。推荐效果取决于覆盖的业务场景，出现过的访问仍需由你判断是否必要。HTTPS 的可见范围会影响访问控制的精细程度，助手会在策略审核前说明可实现的范围。

安装步骤与完整流程见[英文说明](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.md)和[中文说明](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.zh_CN.md)。
