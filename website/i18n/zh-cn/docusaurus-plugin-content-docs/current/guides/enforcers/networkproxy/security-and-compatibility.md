---
sidebar_position: 4
---

# 安全与兼容性 {#security-and-compatibility}

NetworkProxy 自身不依赖 LSM。部署前应确认集群允许注入代理容器，并满足以下权限、网络和镜像要求。

## 权限与身份 {#permissions-and-identity}

vArmor 自动配置注入容器的安全上下文，用户无需手动设置。集群准入策略需要允许注入以 root 启动的容器，并允许 init 容器使用 `NET_ADMIN`；启用 Restricted Pod Security 的命名空间需要配置适当的例外。

业务 UID 必须与 proxyUID 不同，因为代理 UID 的流量被豁免重定向。创建策略前选择 UID：proxyUID、proxyPort（默认 15001）、proxyAdminPort（默认 15000）不可变，端口之间及与业务端口之间均不能冲突。

业务容器不能持有 NET_ADMIN 或切换到代理 UID 的能力。结合容器安全上下文及适用的 AppArmor/BPF 规则限制这些能力。能改写重定向规则的进程不在此防护边界内。

## 流量范围 {#traffic-scope}

- 重定向作用于 Pod 网络命名空间；不能从 `spec.target.containers` 推断逐容器网络隔离。
- 只重定向 TCP，不检查 UDP，包括普通 UDP DNS 和 QUIC/HTTP/3。
- loopback 目标和代理 UID 流量被明确豁免，NetworkProxy 不是覆盖全部出站流量的防火墙。
- 使用独立 Pod 网络命名空间，不要将本指南的注入部署到 `hostNetwork: true`；它不是节点级网络策略机制。
- 保护代理管理接口。init 丢弃本地非代理 UID 到管理端口的流量，但不能据此假定其他 Pod 无法访问所有 sidecar 管理端点。
- Service Mesh 或其他代理也可能修改路由和 iptables。组合使用时，应检查路由冲突，并在部署前验证允许和拒绝流量。

## 镜像、运行时与资源 {#images-runtimes-and-resources}

必须使用配套的 vArmor **自定义** Envoy 和 proxyinit 镜像，不能以相似版本标签的上游 Envoy 替代。

运行时识别、iptables backend 和资源配置见[安装](../../../getting_started/installation.md)。使用 Kata 等微虚机运行时时，需配置运行时识别，并检查平台的准入和挂载要求。

根据业务负载调整代理 CPU 和内存的 requests/limits，并观察资源使用情况和请求延迟。

## IPv6 {#ipv6}

即使 IPv6 地址相同，MITM 请求目标与 HTTP hosts 规则也可能因文本写法不同而无法匹配。MITM 配置、HTTP 规则和客户端 Host/authority 应保持一致，建议使用标准压缩写法，HTTP authority 中加方括号。使用 `/128` 声明 MITM 目标时，客户端应以标准压缩 IP 写法访问；头注入的 domain 引用仍须精确等于原始 `/128` 声明。

地址写法不一致可能导致允许或拒绝规则无法匹配。

## TLS 与应用行为 {#tls-and-application-behavior}

双向信任、CA 缓存与证书固定见[TLS 与凭据](tls-and-credentials.md)。授权只检查可见协议字段，不理解允许的 API 请求体是否携带敏感信息。当前策略 API 不提供 ext_proc 等任意 Envoy filter 配置接口。
