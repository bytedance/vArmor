---
slug: varmor-0.10.1-new-features-overview
title: "vArmor v0.10.1: 看穿 HTTPS — AI Agent 流量检测、密钥注入与 CVE-2026-31431 缓解"
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes, AIAgent, LLM, NetworkProxy, TLSMITM]
date: 2026-05-02T00:00
---

在 vArmor v0.10.0 中，我们引入了 **NetworkProxy enforcer**——一个基于 Sidecar 代理架构的透明代理，为 Kubernetes 工作负载带来了 L4/L7 网络访问控制能力。虽然 v0.10.0 已经能够对明文 HTTP 和 TLS SNI 实施 allow/deny 策略，但 **HTTPS 加密流量仍然是一个黑盒**：代理只能通过 SNI 看到目标域名，无法检查请求路径、请求头或响应体。

vArmor v0.10.1 完成了 NetworkProxy enforcer 的**第二阶段**开发，新增了 **TLS 中间人（MITM）**能力，解锁了深度 HTTPS 检测、自动请求头注入和反域前置保护。本次发版还引入了 **IPv6 双栈支持**、**可配置的 Sidecar 资源配额**、**ConfigMap 到 Secret 的迁移**以提升安全性，并通过 CVE-2026-31431 缓解案例展示了 vArmor 的**快速 CVE 响应**能力。

<!--truncate-->

## 为什么需要 TLS MITM？

在 v0.10.0 中，NetworkProxy enforcer 可以通过 TLS SNI（Server Name Indication）匹配 HTTPS 流量——这足以控制 AI Agent 可以连接*哪些域名*，但无法控制*发送什么内容*。考虑以下实际需求：

- **API Key 治理**：在代理层注入 LLM API Key，使 Agent 容器永远无法看到实际密钥，防止通过 Prompt Injection 或容器入侵导致密钥泄露。
- **深度 L7 检测**：对 HTTPS 流量执行路径级和方法级规则（例如，仅允许对 `api.openai.com` 发起 `POST /v1/chat/completions` 请求）。
- **反域前置**：检测并阻止 TLS SNI 与 HTTP `Host` 头不一致的攻击——这是一种通过受信 CDN 域名隧道化流量的技术。
- **请求审计**：检查和记录加密流量中的 HTTP 请求（请求头和请求体）——对于审计 AI Agent 和 LLM 通信的合规性和异常检测尤为有价值。

TLS MITM 是解锁所有这些能力的关键。

## TLS MITM：工作原理

### 按策略的 CA 管理

vArmor v0.10.1 实现了**完全自动的、按策略隔离的 CA 证书管理**：

1. 当 `VarmorPolicy` 或 `VarmorClusterPolicy` 启用 MITM 时，vArmor Manager 自动为该策略生成一个专用的 **ECDSA P-256 CA 密钥对**。
2. CA 证书和密钥，连同所有 Envoy xDS 配置，存储在一个**统一的 Kubernetes Secret** 中（每个策略一个），替代了之前基于 ConfigMap 的方案。
3. CA 证书通过环境变量（`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE`、`NODE_EXTRA_CA_CERTS`、`CURL_CA_BUNDLE`）注入到目标 Pod 中作为**可信根证书**，同时附带 **Mozilla CA 证书包**（通过 Go `go:embed` 内嵌）。
4. 对于每个被拦截的 TLS 连接，Envoy sidecar 会即时生成一个支持多 SAN 的**叶子证书**，由策略专用的 CA 签发。

### 基于 Secret 的配置管理

所有代理配置已从 ConfigMap 迁移到 Secret：

| Secret 数据键 | 内容 |
|---|---|
| `lds.yaml` | Envoy Listener Discovery Service 配置 |
| `cds.yaml` | Envoy Cluster Discovery Service 配置 |
| `ca.crt` | 策略专用 CA 证书 |
| `ca.key` | 策略专用 CA 私钥 |
| `ca-bundle.crt` | Mozilla 受信 CA 证书包 |

三个 projected volume 通过**键级别隔离**确保：Envoy sidecar 可以访问 xDS 配置和 CA 材料，而应用容器只能看到用于建立信任的 CA 证书包——永远无法访问 CA 私钥。

### 反域前置保护

当启用 MITM 时，Envoy sidecar 终止客户端 TLS 连接并获得明文 HTTP 请求。vArmor 自动执行 **SNI-Host 一致性检查**：如果 TLS SNI 与 HTTP `Host` 头不匹配，请求将被以 `404` 响应拒绝。这有效阻止了域前置攻击——攻击者试图将真实目的地隐藏在受信域名的 SNI 之后。

### 通过 SecretRef 注入请求头

MITM 还支持**自动 HTTP 请求头注入**，通过策略 CRD 中的 Kubernetes Secret 引用进行配置。这是 **API Key 治理**的基础——代理可以向出站请求注入认证头（例如 `Authorization: Bearer <key>`），使 Agent 容器无需直接访问 API 凭证。

```yaml
networkProxyConfig:
  mitm:
    domains:
    - "*.openai.com"
    headerMutations:
    - domain: "*.openai.com"
      headers:
      - name: Authorization
        secretRef:
          name: openai-credentials
          key: api-key
enhanceProtect:
  networkProxyRawRules:
    egress:
      defaultAction: deny
      httpRules:
      - qualifiers: ["allow", "audit"]
        match:
          hosts:
          - "*.openai.com"
```

## IPv6 双栈支持

vArmor v0.10.1 为 NetworkProxy enforcer 添加了完整的 **IPv6 双栈支持**：

- **自动检测**：控制器自动检测集群运行的是单栈（IPv4 或 IPv6）还是双栈，并相应配置监听器和 iptables 规则。
- **专用监听器**：为 IPv4 和 IPv6 流量分别创建独立的 Envoy 监听器，确保双栈集群上透明代理行为的正确性。
- **iptables 集成**：init container 默认同时设置 `iptables` 和 `ip6tables` 重定向规则，无论集群网络配置如何均能正确工作。

这确保了 vArmor 的网络防护在已采用 IPv6 的现代 Kubernetes 集群中无缝工作。

## 可配置的 Sidecar 资源配额

TLS MITM 操作（证书生成、加解密）比简单的直通代理更消耗资源。为此，v0.10.1 引入了**可配置的 Sidecar 资源配额**：

- **MITM 感知默认值**：启用 MITM 时，默认 sidecar 资源限制自动从 `100m CPU / 128Mi 内存` 提升到 `1000m CPU / 512Mi 内存`。
- **按策略覆盖**：用户可以在策略 CRD 中通过字段级合并语义精细调整资源请求和限制。

```yaml
spec:
  policy:
    enforcer: NetworkProxy
    networkProxyConfig:
      resources:
        requests:
          cpu: 200m
          memory: 200Mi
        limits:
          cpu: 2000m
          memory: 1024Mi
```

## 快速 CVE 响应：以 CVE-2026-31431 为例

**CVE-2026-31431** 是一个严重漏洞，恶意容器可以利用 `AF_ALG` 套接字族结合 `splice()` 破坏内核页面缓存中只读文件的内容。在 Kubernetes 环境中，这可以实现**完整的容器逃逸**——一个无特权的 Pod 可以破坏共享容器镜像层的页面（如 kube-proxy 镜像中的二进制文件），当特权 DaemonSet 下次执行该二进制时，攻击者的负载将以宿主机 root 权限运行。这使得该漏洞对运行在共享 Kubernetes 集群上的 AI Agent 工作负载尤为危险。

vArmor 的架构专为**快速安全响应**而设计。当 CVE-2026-31431 被公开披露后，vArmor 用户可以立即利用 AppArmor 和 BPF enforcer 的**自定义规则接口**和**审计模式**来制定和部署缓解策略——无需等待任何软件更新：

```yaml
  policy:
    enforcer: AppArmorBPF
    mode: EnhanceProtect
    enhanceProtect:
      # Disable creating socket with AF_ALG domain (AF_ALG: Interface to kernel crypto API)
      # For AppArmor enforcer
      appArmorRawRules:
      - rules: |
          audit deny network alg,
      # For BPF enforcer
      bpfRawRules:
        network:
          sockets:
          - qualifiers: ["audit", "deny"]
            domains: ["alg"]
```

这个例子展示了 vArmor 的几个核心优势：

- **可观测性**：`audit` 限定符会记录每次被阻止的 `AF_ALG` 套接字尝试，让安全团队能够立即获得集群中潜在漏洞利用行为的可见性。同时也可以帮助识别是否有合法业务真正依赖 `AF_ALG`，从而评估从审计切换到强制拒绝的影响范围。
- **策略动态管理**：策略可以实时创建、更新并下发到工作负载——无需重启 Pod、无需重启节点、无需维护窗口。
- **自定义规则灵活性**：`appArmorRawRules` 和 `bpfRawRules` 接口允许安全团队表达任意内核级别的限制，将任何 CVE 分析在几分钟内转化为可执行的策略。

为了进一步简化这一工作流，vArmor v0.10.1 还内置了 **`copy-fail-mitigation` 规则**，用户可以通过一个规则名称直接启用相同的防护——无需手动编写策略：

| Enforcer | 防护机制 |
|---|---|
| **AppArmor** | 拒绝 `network alg` 以阻止 `AF_ALG` 套接字创建 |
| **BPF** | 在系统调用级别阻止 `AF_ALG` 族的套接字创建 |

> **关于 Seccomp**：尽管 Seccomp 技术上可以阻止 `AF_ALG` 套接字创建，但我们有意不将其作为此规则的内置 enforcer。Seccomp profile 在容器创建时应用，在容器运行期间无法动态更新或放宽，这与 AppArmor 和 BPF enforcer 支持运行时策略更新的特性不同。对于仍希望使用 Seccomp 的用户，文档中提供了通过 `syscallRawRules` 进行手动配置的示例。
## 其他改进

- **Envoy 升级**：Sidecar Envoy 升级至 v1.38-latest，引入上游性能改进和 Bug 修复。
- **代码重构**：NetworkProxy 翻译器和渲染器重构，新增专用 MITM 翻译逻辑和 MITM 感知的过滤器链构建。
- **11 个新增示例 YAML**：涵盖 MITM 策略、请求头注入、IPv6、资源配额自定义等场景。


## 已知限制

**基于 IP 的 MITM + 明文 HTTP**

当目标 IP 地址（非域名）被配置为 TLS MITM 对象时，发往该 IP 的**明文 HTTP 流量**将无法匹配 `http_chain`，其 L7 访问控制规则不会生效。这是 Envoy filter chain matching 算法的固有行为——`prefix_ranges` 匹配优先级更高，会淘汰不够具体的链。如果业务需要对同一目标同时进行 TLS MITM 和明文 HTTP L7 访问控制，请通过域名而非 IP 地址配置规则。

**CA 证书包覆盖容器原有 CA 列表**

`SSL_CERT_FILE` 等环境变量会使运行时**忽略**容器镜像原有的 CA 列表（如 `/etc/ssl/certs/ca-certificates.crt`）。用户自行添加到镜像中的自定义 CA 将会丢失。如果用户已设置了这些环境变量，vArmor 的注入会被跳过（幂等检查），用户需要手动将 vArmor CA 追加到自定义 bundle 中。

**Java（JKS）不兼容**

Java 应用使用 JKS/PKCS12 密钥库，不会从环境变量读取 PEM 格式的 CA 证书包。Java 工作负载需要手动通过 `keytool -import` 将 MITM CA 添加到默认信任存储中。

**Certificate Pinning 不兼容**

执行 Certificate Pinning 的域名（如银行 SDK、支付 SDK）**无法进行 MITM 拦截**——客户端硬编码了证书指纹，任何 MITM 证书都无法通过验证。这些域名只能通过 SNI 级别的 TLS passthrough 进行控制。用户需确保这些域名的 CDN 不允许 Host ≠ SNI 路由。

**SecretRef 轮换**

原地更新被引用的 API Key Secret 的数据不会自动传播到 Envoy。推荐的轮换工作流是：创建新的 Secret，更新策略中的 `secretRef.name` 指向新 Secret，触发 reconcile 并热更新 sidecar 配置——**无需重启 Pod**。

## 未来规划

随着第二阶段的完成，NetworkProxy enforcer 现在提供了从 L4 到 L7、覆盖明文和加密流量的全面安全解决方案。展望未来，我们计划探索：

- **用户自带 CA（`CASecretRef`）**：允许用户提供自己的 CA 证书和私钥用于 MITM 叶子证书签发，支持企业 PKI 集成和合规要求。这也将通过将用户 CA、Mozilla bundle 和 MITM CA 三方合并，解决“CA 证书包覆盖”的限制。
- **全局 Sidecar 资源配额管理**：通过 `varmor-config` ConfigMap 提供集群级默认资源配置，管理员无需逐策略配置即可统一调整 sidecar 资源，采用三层合并链（逐策略 > 全局配置 > 内置默认值）。
- **自动 SecretRef 监听**：监听被引用的 API Key Secret，当其数据变更时自动触发 re-reconcile，消除当前“创建新 Secret + 更新策略”的轮换工作流。
- **智能策略生成**：利用 LLM 技术，基于观察到的 Agent 行为模式自动推荐最小权限网络访问策略。
- **更深入的协议支持**：当前 gRPC（HTTP/2）和 WebSocket 已可通过 MITM 管道透传（因为它们基于 HTTP/1.1 upgrade 或 HTTP/2 CONNECT），未来将增加协议感知的 L7 检测——如 gRPC service/method 级别的 RBAC 规则和 WebSocket 帧级别的审计。

## 总结

vArmor v0.10.1 标志着 NetworkProxy enforcer TLS MITM 能力的完成，将其从域名级别的守门人转变为加密流量的完整**深度包检测引擎**。结合自动的按策略 CA 管理、反域前置保护、API Key 治理的请求头注入、IPv6 双栈支持，以及通过可观测、动态管理策略实现的快速 CVE 响应，本次发版显著增强了 vArmor 在生产 Kubernetes 环境中保护 AI Agent 工作负载的能力。

无论您是在运营 AI 应用平台、部署自主 AI Agent，还是在多租户 Kubernetes 环境中管理 LLM 工作负载，vArmor v0.10.1 为您提供了执行细粒度、协议感知安全策略的工具——确保您的 Agent 只能做被授权做的事。

欢迎升级体验 vArmor v0.10.1，并通过 [GitHub](https://github.com/bytedance/vArmor) 向我们反馈使用体验！完整详情请参阅 [Release Notes](https://github.com/bytedance/vArmor/releases)。
