---
slug: varmor-0.10.0-new-features-overview
title: "vArmor v0.10.0: Network Access Control for AI Agents"
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes, AIAgent, LLM, NetworkProxy]
date: 2026-04-19T00:00
---

With the explosive growth of AI Agents, more and more enterprises are deploying Agents in Kubernetes clusters as containerized workloads. These Agents typically need to call external LLM APIs (such as OpenAI, Anthropic, etc.), execute code, access tool plugins, and even connect to various external services through MCP (Model Context Protocol). However, the high degree of autonomy of Agents also brings new security challenges — how can we ensure that an Agent only accesses authorized network resources?

vArmor v0.10.0 introduces the brand-new **NetworkProxy enforcer**, which implements L4/L7 network traffic interception and access control through a sidecar proxy architecture, providing fine-grained network security protection for AI Agent workloads. This article focuses on this core feature and its application in AI Agent protection scenarios.

<!--truncate-->

## Network Security Risks Facing AI Agents

In our previous article "[AI Application Development Platform Security Hardening Practices](https://varmor.org/blog/harden-the-AI-application-development-platform/)", we demonstrated the security risks of code execution plugins in AI application development platforms and introduced how to use vArmor's BPF enforcer to harden containers. That article primarily focused on **system call level** protection — preventing attackers from further privilege escalation and penetration after escaping the sandbox.

However, as AI Agent architectures evolve, new security challenges are emerging:

- **Uncontrolled external access**: Agents may be induced by Prompt Injection to access malicious URLs, or exfiltrate sensitive data to unauthorized external services.
- **LLM API abuse**: In multi-tenant scenarios, malicious tenants may attempt to steal or abuse other tenants' LLM API Keys through the shared environment.
- **Lateral movement**: A compromised Agent container could leverage network access to move laterally within the cluster, accessing other services or databases.
- **Uncontrolled tool invocation**: When Agents call external tools through protocols like MCP, there is a lack of precise control over outbound traffic destinations.

In the Kubernetes ecosystem, NetworkPolicy is the most common network access control mechanism, but it only provides L3/L4 layer control and does not support auditing — once a policy takes effect, it can only block or allow traffic, without the ability to record traffic access patterns. Although vArmor's BPF enforcer previously supported IP/CIDR/port-based network access control as a supplement to NetworkPolicy, it **only supports deny-list mode** and cannot implement a "default deny, allow-list only" policy. Moreover, when facing HTTPS encrypted traffic and AI scenarios that require fine-grained control based on domain names and URL paths, L3/L4 layer control alone is far from sufficient.

**This is precisely the core motivation for introducing the NetworkProxy enforcer in v0.10.0.** The NetworkProxy enforcer supports both deny-list and allow-list modes, providing more flexible policy configuration capabilities. Compared to NetworkPolicy, it also supports comprehensive audit logging, helping security teams understand the actual network access patterns of Agents.

## NetworkProxy Enforcer: Core Architecture

The NetworkProxy enforcer adopts a **sidecar proxy architecture**, leveraging Envoy to achieve transparent traffic interception and access control. Its core architecture is as follows:

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

**How it works:**

1. **Init Container**: Sets up iptables rules at Pod startup to redirect outbound traffic to the Envoy sidecar.
2. **Envoy Sidecar**: Acts as a transparent proxy to intercept all outbound traffic and enforce access control based on the rules defined in the vArmor policy.
3. **vArmor Manager**: Translates the network proxy rules defined in VarmorPolicy/VarmorClusterPolicy into Envoy RBAC filter configurations (LDS/CDS) and delivers them to the Pod via ConfigMap.
4. **Mutation Webhook**: Automatically injects the Init Container and Envoy Sidecar into matching Pods, completely transparent to the application.

### Multi-Layer Access Control

The NetworkProxy enforcer provides access control at the following layers:

| Layer | Matching Dimensions | Typical Scenarios |
|-------|-------------------|------------------|
| **L4 (TCP)** | Destination IP / CIDR / Port | Block access to specific IP ranges or ports |
| **L7 (HTTP)** | Host / Path / Method | Precise control over HTTP API access |
| **TLS SNI** | Domain name (no decryption needed) | Domain-based control of HTTPS outbound traffic |

Additionally, the NetworkProxy enforcer supports three rule types — `allow`, `deny`, and `audit` — as well as two policy modes: `defaultAction: deny` (allow-list) and `defaultAction: allow` (deny-list), flexibly adapting to different security requirements.

### Dynamic Policy Updates

The NetworkProxy enforcer's network access control policies support **dynamic updates**. When users modify the network proxy rules in a VarmorPolicy/VarmorClusterPolicy, vArmor Manager automatically regenerates the Envoy configuration and updates the corresponding ConfigMap. The Envoy sidecar will automatically load the latest configuration **without restarting the Pod**. This enables security teams to adjust Agent network access policies in real time without affecting business operations.

### Working with AppArmor/BPF Enforcers

In production deployments, we recommend combining the NetworkProxy enforcer with the AppArmor/BPF enforcer to build a **defense-in-depth** system:

- **AppArmor/BPF enforcer**: Enforces mandatory access control (MAC) on containers at the kernel level, restricting system calls, file access, process execution, and other behaviors. On one hand, it prevents sandbox escapes and privilege escalation attacks. On the other hand, it constrains the system resources and tools that an AI Agent can invoke — for example, restricting which commands the Agent can execute and which file paths it can read or write — thereby limiting the damage when an attacker uses Prompt Injection to induce the Agent to call tools for malicious purposes.
- **NetworkProxy enforcer**: Controls network outbound traffic at the application protocol level, preventing data exfiltration and unauthorized API access.

When working together, AppArmor/BPF rules execute first at the kernel level, defining the boundaries of system resource access for the Agent. NetworkProxy rules then further refine outbound network control at the application protocol level, forming a multi-layered security guarantee spanning from **system calls to network protocols**.

:::caution Note
When using the NetworkProxy enforcer, it is recommended to work with the AppArmor/BPF enforcer to **drop the `NET_ADMIN` capability** of the target container and **prohibit creation of and switching to the ProxyUID**, so as to prevent attackers inside the container from bypassing the network proxy rules.
:::

## AI Agent Protection in Practice

Below, we use a typical AI Agent deployment scenario to demonstrate how to protect Agent outbound network access using the NetworkProxy enforcer.

### Scenario Description

Suppose we have deployed an AI Agent application in a Kubernetes cluster that needs to:
- Call the OpenAI API (`api.openai.com:443`)
- Access the Kubernetes API Server (`10.96.0.1:443`)
- Access no other external services

### Policy Configuration

We can create the following VarmorClusterPolicy with a default deny policy, allowing only the necessary outbound traffic:

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
          # Allow access to Kubernetes API Server
          - qualifiers: ["allow"]
            description: "Allow access to Kubernetes API"
            ip: "10.96.0.1"
            ports: [{port: 443}]
          # Allow access to OpenAI API (TLS SNI-based domain matching)
          httpRules:
          - qualifiers: ["allow"]
            description: "Allow OpenAI API access"
            match:
              hosts: ["api.openai.com"]
              ports: [{port: 443}]
```

The effect of this policy is:
- **Default deny** all outbound traffic
- **Only allow** access to the Kubernetes API Server (`10.96.0.1:443`)
- **Only allow** access to the OpenAI API (via TLS SNI matching `api.openai.com`)
- Any traffic attempting to reach other destinations will be blocked, and audit logs will be generated

### Fine-Grained HTTP Layer Control

For unencrypted HTTP traffic, or in combination with the upcoming TLS MITM feature, even more fine-grained L7 control can be achieved. For example, allowing the Agent to make requests only to a specific API path:

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

### Auditing and Observability

The NetworkProxy enforcer provides comprehensive audit logging capabilities based on Envoy's Access Log with Shadow RBAC and CEL filters. Even when rules are configured as `allow`, `audit`-type rules can be used to record specific traffic, helping security teams understand the actual network access patterns of Agents and continuously optimize policies.

## Other Updates

In addition to the NetworkProxy enforcer, v0.10.0 also includes the following updates:

### New Built-in Rules

- **disable-access-passwd**: Prohibits reading the `/etc/passwd` file
- **disable-access-shadow**: Prohibits reading the `/etc/shadow` file
- **disable-access-ssh-dir**: Prohibits access to the SSH directory
- **disable-write-skills**: Prohibits writing to the skills directory

These rules further enrich vArmor's out-of-the-box security protection capabilities. In particular, the `disable-write-skills` rule prevents the Skill/Plugin directory of AI Agents from being tampered with.

### Refactoring and Fixes

- Adjusted the Webhook latency histogram bucket boundaries to improve the accuracy of observability metrics
- Fixed a logic error in `skipRuleWithModelData` in policy-advisor to ensure all conflict types are correctly checked
- Upgraded Go and Node.js dependencies

## Future Plans

vArmor's exploration of AI Agent security protection is just beginning. In upcoming releases, we plan to further enhance the following capabilities:

**TLS MITM (Man-in-the-Middle) Support**

Once TLS MITM capability is implemented, it will unlock two key scenarios:
- **API Key Governance**: Automated injection and auditing of API Keys for LLM/GenAI service access at the proxy layer, preventing Key leakage and abuse. Platforms can centrally manage API Keys at the sidecar layer without exposing them to the Agent container itself.
- **Deep Packet Inspection**: Full L7 layer access control for TLS-encrypted HTTPS traffic, including auditing and filtering of request and response bodies.

**Intelligent Policy Generation**

Leveraging LLM technology to explore the possibility of intelligently generating and optimizing security policies, further reducing policy management costs. For example, automatically recommending least-privilege network access policies based on Agent behavior patterns.

**Broader Protocol Support**

Beyond HTTP, exploring native support for gRPC, WebSocket, and other protocols commonly used by AI Agents, providing fine-grained access control for more scenarios.

## Conclusion

The NetworkProxy enforcer in vArmor v0.10.0 marks an important evolution of vArmor from "system-level protection" to "application protocol-level protection". Facing the new network security challenges posed by AI Agents, the NetworkProxy enforcer provides transparent traffic interception capabilities based on a sidecar proxy, supporting multi-layer access control at L4/L7/TLS SNI levels, both deny-list and allow-list policy modes, and dynamic policy updates. It works seamlessly with the existing AppArmor/BPF enforcers to build a defense-in-depth system spanning from system calls to network protocols — not only blocking traditional container escapes and privilege escalation attacks, but also effectively addressing the emerging threat of Prompt Injection inducing Agents to abuse tools and network resources.

Whether you are operating an AI application development platform, deploying autonomous AI Agents, or managing LLM workloads in a multi-tenant Kubernetes environment, vArmor v0.10.0 can help you precisely control Agent network access behavior and ensure the security of your platform and users.

We welcome you to upgrade to vArmor v0.10.0 and share your feedback through [GitHub](https://github.com/bytedance/vArmor)! For more details on other updates, see the [Release Notes](https://github.com/bytedance/vArmor/releases/tag/v0.10.0).
