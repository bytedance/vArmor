---
sidebar_position: 4
---

# 安全与兼容性 {#security-and-compatibility}

NetworkProxy 自身不依赖 LSM，但仍依赖 Kubernetes admission、容器注入、netfilter 重定向和配套镜像。部署前应检查以下前提。

## 权限与身份 {#permissions-and-identity}

init 使用 `runAsUser: 0`、`runAsNonRoot: false` 和 `NET_ADMIN` 配置重定向。sidecar 同样从 UID0、`runAsNonRoot: false` 启动，再由 **vArmor 自定义镜像入口**将 Envoy 降权为 proxyUID（默认 1337）。这些容器级字段覆盖注入容器继承的 Pod 非 root 默认值，不改变业务容器安全上下文。

这种注入不符合无条件强制 Restricted Pod Security 的命名空间要求。应为工作负载安排经过审查的 admission 策略，不要为了排障关闭整个集群的限制。

业务 UID 必须与 proxyUID 不同，因为代理 UID 的流量被豁免重定向。创建策略前选择 UID：proxyUID、proxyPort（默认 15001）、proxyAdminPort（默认 15000）不可变，端口之间及与业务端口之间均不能冲突。

业务容器不能持有 NET_ADMIN 或切换到代理 UID 的能力。结合容器安全上下文及适用的 AppArmor/BPF 规则限制这些能力。能改写重定向规则的进程不在此防护边界内。

## 流量范围 {#traffic-scope}

- 重定向作用于 Pod 网络命名空间；不能从 `spec.target.containers` 推断逐容器网络隔离。
- 只重定向 TCP，不检查 UDP，包括普通 UDP DNS 和 QUIC/HTTP/3。
- loopback 目标和代理 UID 流量被明确豁免，NetworkProxy 不是覆盖全部出站流量的防火墙。
- 使用独立 Pod 网络命名空间，不要将本指南的注入部署到 `hostNetwork: true`；它不是节点级网络策略机制。
- 保护代理管理接口。init 丢弃本地非代理 UID 到管理端口的流量，但不能据此假定其他 Pod 无法访问所有 sidecar 管理端点。
- Service Mesh 或其他代理也可能修改路由和 iptables。本指南不承诺通用共存支持，应验证组合后的真实路径及允许/拒绝行为。

## 镜像、运行时与资源 {#images-runtimes-and-resources}

必须使用配套的 vArmor **自定义** Envoy 和 proxyinit 镜像，不能以相似版本标签的上游 Envoy 替代。入口脚本需遵守 `VARMOR_ENVOY_UID`。使用 IfNotPresent 时，注册表中覆盖标签不会替换节点缓存；镜像行为变更应使用新标签，更新实际工作负载模板，并检查运行 imageID。

运行时识别、iptables backend 和资源配置见[安装](../../../getting_started/installation.md)。微虚机审计路径已有实现，但近期 IPv4/runc 冒烟和回归不等于验证了所有 Kata/serverless 部署；需要另外核对 admission、volume 和连通性要求。

资源默认值不是吞吐保证。提高内存限制不能修复 Envoy 实际 UID 与重定向豁免 UID 不一致。

## IPv6 {#ipv6}

IPv6 匹配和配置生成有专门测试，但所引用的 Kubernetes 回归使用 IPv4 Pod 网络，不能据此宣称完整 IPv6 集群兼容。

MITM IP 选链解析地址，而 HTTP 虚拟主机/hosts 还依赖文本。压缩与展开的等价 IPv6 写法不一定匹配。MITM 配置、HTTP 规则和客户端 Host/authority 应保持一致，建议使用标准压缩写法，HTTP authority 中加方括号。`/128` 声明生成规范化 IP 虚拟主机，但头注入引用仍须精确等于原始 `/128` 声明。

不能推断所有文本不匹配都无害；deny 规则未匹配也可能影响安全。

## TLS 与应用行为 {#tls-and-application-behavior}

双向信任、CA 缓存与证书固定见[TLS 与凭据](tls-and-credentials.md)。授权只检查可见协议字段，不理解允许的 API 请求体是否携带敏感信息。当前策略 API 不提供 ext_proc 等任意 Envoy filter 配置接口。
