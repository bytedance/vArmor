---
sidebar_position: 5
sidebar_label: NetworkProxy
---

# NetworkProxy

NetworkProxy 通过 vArmor 管理的 Envoy sidecar 控制被重定向的出站 TCP 流量，可限制 HTTP 请求、按 SNI 过滤 TLS 目标、通过 TLS 拦截（MITM）检查 HTTPS，或注入上游认证头。

本指南描述 **v0.10.5** 及配套 vArmor 代理镜像的行为。旧版本请先阅读[生命周期与升级](lifecycle-and-upgrades.md)。

**HTTP Header 注入**：在 MITM 拦截的 HTTPS 请求中，NetworkProxy 可以按域名添加或覆盖请求头，例如 `Authorization`。请求头的值支持直接配置或引用 Kubernetes Secret，业务应用无需自行携带该凭据。配置方法见[TLS 与凭据](tls-and-credentials.md#inject-a-credential-header)。

## 能检查哪些流量 {#what-it-can-inspect}

| 流量 | 可用策略信息 | 审计粒度 |
| --- | --- | --- |
| 明文 HTTP/1.1、HTTP/2 cleartext（h2c） | 目标 IP/端口、HTTP Host、路径和方法 | HTTP 请求 |
| TLS 透传 | 目标 IP/端口、可见的 TLS SNI | 连接；无法看到加密的 HTTP 路径/方法 |
| MITM 拦截的 HTTPS | 目标 IP/端口、解密后的 HTTP Host、路径和方法 | HTTP 请求 |
| 其他 TCP | 目标 IP/端口 | 连接 |

NetworkProxy 不检查 UDP/QUIC，也不是 DNS 策略引擎。它不提供请求体分类、提示词注入检测或业务进程级归因。其他流量路径需要相应网络和容器控制，详见[安全与兼容性](security-and-compatibility.md)。

## 工作方式 {#how-it-works}

![runc 与 Kata 中的 NetworkProxy：相同的 Pod 内流量代理路径，不同的审计日志位置](/img/networkproxy/runtime-comparison-zh.svg)

两种运行时都在 Pod 内将业务 TCP 流量重定向到 Envoy，再按策略决定是否转发。runc 由节点 Agent 记录审计；Kata 的业务容器和代理运行在同一虚拟机内，审计日志记录在 sidecar 内，无需将审计连接跨越虚拟机边界。图中的审计路径仅记录策略要求审计的流量。

两种模式的日志路径均为 `/var/log/varmor/violations.log`，分别位于节点和 sidecar 文件系统。Kata 需要配置正确的[运行时识别](../../../getting_started/installation.md#micro-vm-kata-detection-for-networkproxy-auditing)，日志查看方法见[可观测性](observability.md)。


1. 匹配策略在目标命名空间生成 Envoy 配置 Secret。
2. vArmor 向已选择并启用保护的工作负载注入 `varmor-network-proxy-init` 和 `varmor-network-proxy`，init 在 Pod 网络命名空间安装 TCP 重定向规则。
3. Envoy 根据流量协议执行规则；对 MITM 范围内的 HTTPS，先解密并检查 HTTP 请求，再通过 TLS 连接上游。
4. Envoy 加载动态配置。符合条件的审计日志记录在节点上；配置的微虚机运行时则记录在 sidecar 内。

NetworkProxy 对共享 Pod 网络命名空间中的流量实施规则。创建策略后，通过允许和拒绝请求确认执行效果。

## 推荐阅读路径 {#start-here}

- [快速开始](quick-start.mdx)：运行隔离 HTTP 允许/拒绝示例。
- [策略语义](policy-semantics.md)：理解 L4/L7 组合、默认行为和 MITM 拦截范围。
- [TLS 与凭据](tls-and-credentials.md)：配置信任、MITM 和头注入。
- [安全与兼容性](security-and-compatibility.md)：检查权限、UID、运行时及协议边界。
- [生命周期与升级](lifecycle-and-upgrades.md)：更新规则、凭据和代理工作负载。
- [可观测性](observability.md)与[故障排查](troubleshooting.md)：确认实际执行结果和定位异常。

Helm 配置见[安装](../../../getting_started/installation.md)，字段定义见[接口说明](../../../getting_started/interface_specification.md#networkproxyconfig)。
