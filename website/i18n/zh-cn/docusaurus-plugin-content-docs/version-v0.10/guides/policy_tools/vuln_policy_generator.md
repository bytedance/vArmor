---
slug: /guides/policy_tools/vuln_policy_generator
sidebar_position: 2
description: 使用 AI Skill 生成漏洞缓解规则。
---

# 漏洞策略生成器

漏洞策略生成器是一个 AI Skill，用于自动化分析安全漏洞并生成 vArmor 缓解规则。给定 CVE 编号、PoC 仓库或漏洞分析文章，它会产出可以直接融合到现有 vArmor 策略中的缓解规则。

## 功能

Skill 引导 LLM 完成结构化的分析流程：

1. **信息收集** — 获取 CVE 详情、PoC 代码和相关分析文章
2. **根因分析** — 识别漏洞代码路径、所需系统调用、内核模块和权限
3. **可利用性评估** — 评估每个变体在容器环境中的实际威胁等级
4. **防御点分析** — 将每个利用步骤映射到 vArmor 可阻断点，权衡精准度与业务影响
5. **规则生成** — 产出语法正确的缓解规则（引用 vArmor API 类型定义）
6. **部署指引** — 提供观察-拦截分阶段上线方案

## 支持的漏洞类型

| 类型 | 典型案例 | vArmor 防御维度 |
|------|---------|----------------|
| 内核 LPE / 容器逃逸 | Dirty Pipe、Copy Fail、Dirty Frag | 系统调用限制、套接字协议族限制、namespace 限制 |
| 应用层 RCE / 集群接管 | IngressNightmare (CVE-2025-1974) | 网络访问控制（限制对敏感 Service/端口的访问） |
| 容器运行时逃逸 | CVE-2019-5736 (runc) | 文件写入限制 |
| 任意文件读写 | 各类 Web 应用漏洞 | 文件访问控制 |
| 凭证窃取 | ServiceAccount token 滥用 | 文件读取限制、网络外连限制 |
| 供应链漏洞 | Log4Shell 等 | 网络外连限制、进程执行限制 |

## 使用方法

### 第一步：获取 Skill

从 vArmor 仓库下载 SKILL.md 文件：

- [英文版](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_en.md)
- [中文版](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_zh.md)

### 第二步：加载到 AI 助手

将 SKILL.md 作为系统上下文加载到任何支持自定义 prompt 或 skill 的 AI 助手中（Claude、GPT、Gemini 等）。

### 第三步：提供漏洞信息

向 AI 助手提供漏洞详情，要求生成 vArmor 缓解规则：

```
用户：刚看到一个新漏洞 Dirty Frag，https://github.com/V4bel/dirtyfrag
     帮我看看能不能用 vArmor 缓解，生成防护规则
```

### 第四步：审核并融合

Skill 会产出漏洞分析报告和缓解规则。审核输出内容（尤其是业务影响评估），然后将规则融合到已有的 VarmorPolicy 或 VarmorClusterPolicy 中。

## 影响输出质量的因素

- **LLM 自身能力** — 这是一个高难度任务，需要多步技术推理并生成合法 YAML。SOTA 模型的表现明显优于小模型。
- **信息检索能力** — LLM 能获取到 PoC 源码、详细分析文章和 vArmor API 定义时，效果更好。
- **Skill prompt 质量** — 结构化方法论和参考案例引导 LLM 的推理链路。
- **人工审核** — Skill 产出的是草稿而非最终策略。部署到生产环境前务必验证。

## 输出示例

参见 [blog 文章](https://www.varmor.org/zh-cn/blog/varmor-vuln-policy-generator)，其中以 Dirty Frag 漏洞为例展示了完整的分析流程、生成的规则和分阶段部署方案。

## 与策略顾问的关系

| | 策略顾问 (Policy Advisor) | 漏洞策略生成器 |
|---|---|---|
| **形态** | Python CLI 工具 | AI Skill（prompt 文件） |
| **输入** | 应用特征、capabilities、行为数据 | 漏洞信息（CVE、PoC） |
| **输出** | 通用加固策略模板 | 针对特定漏洞的缓解规则 |
| **解决的问题** | "我该给这个应用开什么防护？" | "这个新 CVE 怎么防？" |

两个工具互为补充。策略顾问生成基线加固策略；漏洞策略生成器在新威胁出现时追加针对性缓解规则。
