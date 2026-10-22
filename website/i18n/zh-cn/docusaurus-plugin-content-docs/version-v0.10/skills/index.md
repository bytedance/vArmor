---
slug: /guides/skills
sidebar_position: 4
description: 借助开箱即用的智能体 Skills，完成策略与组件自动诊断、策略自动优化及网络策略推荐。
---

# Skills

为帮助用户更好地使用 vArmor，我们围绕策略制定、调优和故障排查等存在技术门槛或重复工作的环节，设计了一系列开箱即用的 Skills。使用 Codex、Claude Code 等支持 Skill 的通用 AI 智能体，即可通过自然语言完成相关任务，减少学习和手工操作成本。

## 按场景选择

| Skill | 什么时候用 | 详细说明 |
| --- | --- | --- |
| [自动诊断](diagnosis.md) | 遇到策略未生效、Pod 异常或组件故障，难以确定原因时：结合集群与节点的配置、状态、事件和日志，自动排查并给出处理建议。 | [English](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.md) · [简体中文](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.zh_CN.md) |
| [策略自动优化](policy-optimization.md) | 使用 EnhanceProtect 加固应用，希望减少业务误伤时：通过多轮观察和规则调整，结合业务需求与防护目标，逐步收敛到更合适的策略。 | [English](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.md) · [简体中文](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.zh_CN.md) |
| [网络白名单助手](network-advisor.md) | 想限制应用的对外访问，但不清楚如何制定 NetworkProxy 策略时：由助手引导观测业务访问，推荐网络白名单策略，并协助审核与验证。 | [English](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.md) · [简体中文](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.zh_CN.md) |

三个 Skills 可独立使用，按当前任务选择即可。

## 开始使用

所有 Skills 均位于项目的 [skills 目录](https://github.com/bytedance/vArmor/tree/main/skills)下。按所用智能体的技能安装方式，安装所需 Skill 的完整目录，再通过自然语言描述任务即可。请保留 `SKILL.md` 及其配套文件。

各 Skill 的独立页面介绍功能与使用流程；具体安装方法和环境要求可查阅对应的中英文说明。
