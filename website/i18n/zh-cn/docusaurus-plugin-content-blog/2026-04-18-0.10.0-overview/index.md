---
slug: varmor-0.10.0-new-features-overview
title: "vArmor v0.10.0: 面向 AI Agent 的网络访问控制"
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes, AIAgent, LLM, NetworkProxy]
date: 2026-04-19T00:00
---

随着 AI Agent 的爆发式增长，越来越多的企业将 Agent 部署在 Kubernetes 集群中，以容器化的方式运行。这些 Agent 通常需要调用外部 LLM API（如 OpenAI、Anthropic 等）、执行代码、访问工具插件，甚至通过 MCP（Model Context Protocol）连接各类外部服务。然而，Agent 的高度自主性也带来了新的安全挑战——如何确保 Agent 只能访问被授权的网络资源？

vArmor v0.10.0 引入了全新的 **NetworkProxy enforcer**，通过 Sidecar 代理架构实现了 L4/L7 层级的网络流量拦截与访问控制，为 AI Agent 工作负载提供了细粒度的网络安全防护能力。本文将重点介绍这一核心特性及其在 AI Agent 防护场景中的应用。

<!--truncate-->

## AI Agent 面临的网络安全风险

在我们此前的文章《[AI 应用开发平台安全加固实践](https://varmor.org/zh-cn/blog/harden-the-AI-application-development-platform)》中，我们演示了 AI 应用开发平台中代码执行插件的安全风险，并介绍了如何使用 vArmor 的 BPF enforcer 对容器进行加固。那篇文章主要关注的是**系统调用级别**的防护——阻止攻击者在沙箱逃逸后进一步提权和渗透。

然而，随着 AI Agent 架构的演进，新的安全挑战正在浮现：

- **不受控的外部访问**：Agent 可能被 Prompt Injection 诱导访问恶意 URL，或将敏感数据外泄到未授权的外部服务。
- **LLM API 滥用**：在多租户场景下，恶意租户可能试图通过共享环境窃取或滥用其他租户的 LLM API Key。
- **横向移动**：被攻陷的 Agent 容器可能利用网络访问权限在集群内横向渗透，访问其他服务或数据库。
- **工具调用失控**：Agent 通过 MCP 等协议调用外部工具时，缺乏对出站流量目标的精确控制。

在 Kubernetes 生态中，NetworkPolicy 是最常用的网络访问控制手段，但它仅提供 L3/L4 层的控制能力，且不支持审计——策略生效后只能拦截或放行，无法记录流量访问模式。vArmor 此前的 BPF enforcer 虽然支持基于 IP/CIDR/端口的网络访问控制作为 NetworkPolicy 的补充，但它**仅支持黑名单模式**，无法实现"默认拒绝、仅允许白名单"的策略。而面对 HTTPS 加密流量和需要基于域名、URL 路径进行精细管控的 AI 场景，仅有 L3/L4 层控制也是远远不够的。

**这正是 v0.10.0 引入 NetworkProxy enforcer 的核心动机。** NetworkProxy enforcer 支持黑名单和白名单两种模式，提供了更加灵活的策略配置能力。相比 NetworkPolicy，它还支持全面的审计日志，帮助安全团队掌握 Agent 的实际网络访问模式。

## NetworkProxy Enforcer：核心架构

NetworkProxy enforcer 采用 **Sidecar 代理架构**，基于 Envoy 实现透明的流量拦截与访问控制。其核心架构如下：

```
┌───────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                    │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                      Target Pod                     │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │  │     App     │  │    Envoy    │  │    Init     │  │  │
│  │  │  Container  │◄─┤   Sidecar   │  │  Container  │  │  │
│  │  │  (AI Agent) │  │   (Proxy)   │  │  (iptables) │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
│                           │                               │
│                           │ ConfigMap                     │
│                           ▼                               │
│                  ┌─────────────────┐                      │
│                  │   Envoy Config  │                      │
│                  │    (LDS/CDS)    │                      │
│                  └─────────────────┘                      │
│                           ▲                               │
│                           │ Generate                      │
│                  ┌────────┴────────┐                      │
│                  │  vArmor Manager │                      │
│                  └─────────────────┘                      │
└───────────────────────────────────────────────────────────┘
```

**工作原理：**

1. **Init Container**：在 Pod 启动时通过 iptables 规则将出站流量重定向至 Envoy Sidecar。
2. **Envoy Sidecar**：作为透明代理拦截所有出站流量，根据 vArmor 策略中定义的规则执行访问控制。
3. **vArmor Manager**：将用户定义的 VarmorPolicy/VarmorClusterPolicy 中的网络代理规则翻译为 Envoy 的 RBAC 过滤器配置（LDS/CDS），并通过 ConfigMap 下发到 Pod。
4. **Mutation Webhook**：自动为匹配的 Pod 注入 Init Container 和 Envoy Sidecar，对应用完全透明。

### 多层级访问控制能力

NetworkProxy enforcer 提供了以下层级的访问控制能力：

| 层级 | 匹配维度 | 典型场景 |
|------|---------|---------|
| **L4（TCP）** | 目标 IP / CIDR / 端口 | 阻止访问特定 IP 段或端口 |
| **L7（HTTP）** | Host / Path / Method | 精确控制 HTTP API 访问 |
| **TLS SNI** | 域名（无需解密） | 基于域名控制 HTTPS 出站流量 |

此外，NetworkProxy enforcer 支持 `allow`、`deny`、`audit` 三种规则类型，以及 `defaultAction: deny`（白名单）和 `defaultAction: allow`（黑名单）两种策略模式，灵活适配不同安全需求。

### 策略动态更新

NetworkProxy enforcer 的网络访问控制策略支持**动态更新**。当用户修改 VarmorPolicy/VarmorClusterPolicy 中的网络代理规则时，vArmor Manager 会自动重新生成 Envoy 配置并更新对应的 ConfigMap，Envoy Sidecar 将自动加载最新配置，**无需重启 Pod**。这使得安全团队可以在不影响业务运行的前提下，实时调整 Agent 的网络访问策略。

### 与 AppArmor/BPF Enforcer 协同

在实际部署中，我们推荐将 NetworkProxy enforcer 与 AppArmor/BPF enforcer 结合使用，构建**纵深防御**体系：

- **AppArmor/BPF enforcer**：在内核层面对容器实施强制访问控制（MAC），限制系统调用、文件访问、进程执行等行为。一方面，它可以阻止沙箱逃逸和提权攻击；另一方面，它还能约束 AI Agent 可调用的系统资源和工具范围——例如限制 Agent 可执行的命令、可读写的文件路径等——从而在攻击者通过 Prompt Injection 诱导 Agent 调用工具实施攻击时，将危害限制在最小范围内。
- **NetworkProxy enforcer**：在应用协议层面控制网络出站流量，防止数据外泄和未授权的 API 访问。

两者协同工作时，AppArmor/BPF 规则在内核层优先执行，为 Agent 划定系统资源的访问边界；NetworkProxy 规则在应用协议层进一步细化网络出站控制，形成从**系统调用到网络协议**的多层次安全保障。

:::caution 注意
使用 NetworkProxy enforcer 时，建议配合 AppArmor/BPF enforcer 对目标容器**移除 `NET_ADMIN` 权能（capability）**，并**禁止创建和切换到 ProxyUID 用户**，以防止容器内的攻击者绕过网络代理规则。
:::

## AI Agent 防护实践

下面我们以一个典型的 AI Agent 部署场景为例，演示如何使用 NetworkProxy enforcer 保护 Agent 的出站网络访问。

### 场景描述

假设我们在 Kubernetes 集群中部署了一个 AI Agent 应用，该 Agent 需要：
- 调用 OpenAI API（`api.openai.com:443`）
- 访问 Kubernetes API Server（`10.96.0.1:443`）
- 除此之外，不应访问任何其他外部服务

### 策略配置

我们可以创建如下 VarmorClusterPolicy，使用默认拒绝策略，仅放行必要的出站流量：

```yaml
apiVersion: crd.varmor.org/v1beta1
kind: VarmorClusterPolicy
metadata:
  name: ai-agent-network-policy
spec:
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: ai-agent
  policy:
    enforcer: NetworkProxy
    mode: EnhanceProtect
    enhanceProtect:
      networkProxyRawRules:
        egress:
          defaultAction: deny
          rules:
          # 允许访问 Kubernetes API Server
          - qualifiers: ["allow"]
            description: "Allow access to Kubernetes API"
            ip: "10.96.0.1"
            ports: [{port: 443}]
          # 允许访问 OpenAI API (基于 TLS SNI 域名匹配)
          httpRules:
          - qualifiers: ["allow"]
            description: "Allow OpenAI API access"
            match:
              hosts: ["api.openai.com"]
              ports: [{port: 443}]
```

这条策略的效果是：
- **默认拒绝**所有出站流量
- **仅允许**访问 Kubernetes API Server（`10.96.0.1:443`）
- **仅允许**访问 OpenAI API（基于 TLS SNI 匹配 `api.openai.com`）
- 任何试图访问其他目标的流量都将被拦截，并记录审计日志

### 更精细的 HTTP 层控制

对于非加密的 HTTP 流量，或配合未来的 TLS MITM 功能，还可以实现更精细的 L7 控制。例如，仅允许 Agent 对特定 API 路径发起请求：

```yaml
httpRules:
- qualifiers: ["allow"]
  description: "Only allow chat completions API"
  match:
    hosts: ["api.openai.com"]
    paths:
    - value: "/v1/chat/completions"
      type: Exact
    methods: ["POST"]
    ports: [{port: 443}]
```

### 审计与可观测性

NetworkProxy enforcer 基于 Envoy 的 Access Log 和 Shadow RBAC + CEL 过滤器提供了全面的审计日志能力。即使规则配置为 `allow`，也可以通过 `audit` 类型的规则对特定流量进行审计记录，帮助安全团队了解 Agent 的实际网络访问模式，从而持续优化策略。

## 其他更新

除了 NetworkProxy enforcer 之外，v0.10.0 还包含以下更新：

### 新增内置规则

- **disable-access-passwd**：禁止读取 `/etc/passwd` 文件
- **disable-access-shadow**：禁止读取 `/etc/shadow` 文件
- **disable-access-ssh-dir**：禁止访问 SSH 目录
- **disable-write-skills**：禁止写入 skills 目录

这些规则进一步丰富了 vArmor 的开箱即用安全防护能力，尤其是 `disable-write-skills` 规则，可以防止 AI Agent 的 Skill/Plugin 目录被恶意篡改。

### 重构与修复

- 调整了 Webhook 延迟直方图的桶边界，提升了可观测性指标的准确度
- 修复了 policy-advisor 中 `skipRuleWithModelData` 的逻辑错误，确保所有冲突类型都被正确检查
- 升级了 Go 和 Node.js 依赖包

## 未来规划

vArmor 在 AI Agent 安全防护领域的探索才刚刚开始。在接下来的版本中，我们计划进一步增强以下能力：

**TLS MITM（中间人）支持**

实现 TLS 中间人能力后，将解锁两个关键场景：
- **API Key 治理**：在代理层自动注入和审计 LLM/GenAI 服务的 API Key，防止 Key 泄露和滥用。平台可以在 Sidecar 层统一管理 API Key，而无需将 Key 暴露给 Agent 容器本身。
- **深度包检测**：对 TLS 加密的 HTTPS 流量实现完整的 L7 层访问控制，包括请求体和响应体的审计与过滤。

**智能策略生成**

结合 LLM 技术，探索智能生成和优化安全策略的可能性，进一步降低策略管理成本。例如，根据 Agent 的行为模式自动推荐最小权限的网络访问策略。

**更广泛的协议支持**

在 HTTP 之外，探索对 gRPC、WebSocket 等 AI Agent 常用协议的原生支持，为更多场景提供精细化的访问控制。

## 总结

vArmor v0.10.0 的 NetworkProxy enforcer 标志着 vArmor 从"系统级防护"向"应用协议级防护"的重要演进。面对 AI Agent 带来的新型网络安全挑战，NetworkProxy enforcer 提供了基于 Sidecar 代理的透明流量拦截能力，支持 L4/L7/TLS SNI 多层级的访问控制，支持黑白名单策略模式和动态策略更新，并与现有的 AppArmor/BPF enforcer 无缝协同，构建起从系统调用到网络协议的纵深防御体系——不仅阻止传统的容器逃逸和提权攻击，还能有效应对 Prompt Injection 诱导 Agent 滥用工具和网络资源的新型威胁。

无论您是在运营 AI 应用开发平台、部署自主 AI Agent，还是在多租户 Kubernetes 环境中管理 LLM 工作负载，vArmor v0.10.0 都能帮助您精确控制 Agent 的网络访问行为，保障平台与用户的安全。

欢迎升级体验 vArmor v0.10.0，并通过 [GitHub](https://github.com/bytedance/vArmor) 向我们反馈使用体验！其他更新详见 [Release Notes](https://github.com/bytedance/vArmor/releases/tag/v0.10.0)。
