---
sidebar_position: 5
sidebar_label: NetworkProxy
---

# NetworkProxy

NetworkProxy 通过 vArmor 管理的 Envoy sidecar 控制被重定向的出站 TCP 流量，可限制 HTTP 请求、按 SNI 过滤 TLS 目标、通过 TLS 拦截（MITM）检查 HTTPS，或注入上游认证头。

本指南描述 **v0.10.5** 及配套 vArmor 代理镜像的行为。旧版本请先阅读[生命周期与升级](lifecycle-and-upgrades.md)。相同版本标签不能证明节点缓存的镜像内容相同。

## 能检查哪些流量 {#what-it-can-inspect}

| 流量 | 可用策略信息 | 审计粒度 |
| --- | --- | --- |
| 明文 HTTP/1.1、HTTP/2 cleartext（h2c） | 目标 IP/端口、HTTP Host、路径和方法 | HTTP 请求 |
| TLS 透传 | 目标 IP/端口、可见的 TLS SNI | 连接；无法看到加密的 HTTP 路径/方法 |
| MITM 拦截的 HTTPS | 目标 IP/端口、解密后的 HTTP Host、路径和方法 | HTTP 请求 |
| 其他 TCP | 目标 IP/端口 | 连接 |

NetworkProxy 不检查 UDP/QUIC，也不是 DNS 策略引擎。它不提供请求体分类、提示词注入检测或业务进程级归因。其他流量路径需要相应网络和容器控制，详见[安全与兼容性](security-and-compatibility.md)。

## 工作方式 {#how-it-works}

1. 匹配策略在目标命名空间生成 Envoy 配置 Secret。
2. vArmor 向已选择并启用保护的工作负载注入 `varmor-network-proxy-init` 和 `varmor-network-proxy`，init 在 Pod 网络命名空间安装 TCP 重定向规则。
3. Envoy 选择协议/过滤链并执行规则；MITM 链先终止 TLS，再检查 HTTP，并建立上游 TLS。
4. Envoy 从投影文件读取动态配置。符合条件的审计事件交给节点 Agent，或配置的微虚机部署中的 sidecar 内审计接收器。

sidecar 不为各业务容器创建独立网络命名空间。策略状态成功、readiness 端口可连接都不能单独证明某个请求已执行预期规则。

## 推荐阅读路径 {#start-here}

- [快速开始](quick-start.mdx)：运行隔离 HTTP 允许/拒绝示例。
- [策略语义](policy-semantics.md)：理解 L4/L7 组合、默认行为和选链。
- [TLS 与凭据](tls-and-credentials.md)：配置信任、MITM 和头注入。
- [安全与兼容性](security-and-compatibility.md)：检查权限、UID、运行时及协议边界。
- [生命周期与升级](lifecycle-and-upgrades.md)：更新规则、凭据、镜像和旧模板。
- [可观测性](observability.md)与[故障排查](troubleshooting.md)：确认实际执行结果和定位异常。

Helm 配置见[安装](../../../getting_started/installation.md)，字段定义见[接口说明](../../../getting_started/interface_specification.md#networkproxyconfig)。
