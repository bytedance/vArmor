---
slug: /guides/skills
sidebar_position: 6
description: Ready-to-use AI agent skills for policy recommendation, automated policy optimization, and automated policy and component diagnosis.
---

# Skills

To help users work more effectively with vArmor, we designed ready-to-use skills for tasks that involve specialist knowledge or repetitive work, including policy creation, tuning, and troubleshooting. You can use these skills with general-purpose AI agents that support skills, such as Codex and Claude Code, to describe tasks in natural language and reduce the learning curve and manual effort.

## Choose by scenario

| Skill | When to use it | Source guides |
| --- | --- | --- |
| [vArmor Network Allowlist Advisor](network-advisor.md) | You want to restrict outbound access but need help defining a NetworkProxy policy. The assistant guides observation of application traffic, recommends an allowlist policy, and helps you review and validate it. | [English](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.md) · [简体中文](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.zh_CN.md) |
| [vArmor Policy Optimization](policy-optimization.md) | You use EnhanceProtect and want to reduce disruption to your application. Successive rounds of observation and rule adjustment help converge on a policy that better balances business needs and protection goals. | [English](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.md) · [简体中文](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.zh_CN.md) |
| [vArmor Diagnosis](diagnosis.md) | A policy seems ineffective, a Pod behaves unexpectedly, or a component fails, and the cause is unclear. The assistant correlates cluster and node configuration, status, events, and logs to investigate automatically and recommend next steps. | [English](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.md) · [简体中文](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.zh_CN.md) |

Each skill can be used independently. Choose the one that matches your current task.

## Get started

All skills are available in the repository's [skills directory](https://github.com/bytedance/vArmor/tree/main/skills). Install the complete directory for the skill you need using your agent's skill installation method, then describe your task in natural language. Keep the skill's supporting files together with `SKILL.md`.

Each skill's page introduces its capabilities and usage. The linked source guides provide installation details and environment requirements.
