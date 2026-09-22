---
sidebar_position: 2
---

# 策略语义 {#policy-semantics}

在 `EnhanceProtect` 下使用 `spec.policy.enhanceProtect.networkProxyRawRules.egress`，在 `DefenseInDepth` 下使用 `spec.policy.defenseInDepth.networkProxy.egress`。`AlwaysAllow` 和 `RuntimeDefault` 不提供应用 HTTP 允许列表；NetworkProxy 不支持 `BehaviorModeling`。

## 默认动作、限定符与组合 {#defaults-qualifiers-and-combinations}

- `defaultAction: allow`：除非命中 deny，否则允许。
- `defaultAction: deny`：必须命中 allow，且不能命中 deny。
- deny 优先于 allow，与 YAML 顺序无关。
- audit 选择日志，在默认拒绝下不会授予访问权限。`allowViolations` 不改变 NetworkProxy 的这些决定。
- 按需使用 `allow`、`deny`、`audit`、`allow,audit` 或 `deny,audit`。不要在同一条规则中同时使用 allow/deny。

同一条规则中不同条件为 **AND**；同一条件列表中的多个值为 **OR**；allow 或 deny 组内的不同规则为 **OR**。不同规则的局部条件不会被拼接成一条新规则。

**L4 allow 与 HTTP allow 同时适用时，任意一种匹配都可以授权请求。** 对整个子网/端口的 L4 allow 可以放行不满足 HTTP allow 的请求。不能把宽泛的 L4 allow 当作狭窄 HTTP 允许列表的必需前置条件；匹配的 deny 仍优先。

例如，默认拒绝且只有 `GET /public/` 的 HTTP allow 时，可见 HTTP 受此约束；再添加服务器 IP/端口的 L4 allow 后，其他请求也可能被授权，除非被显式拒绝。

## 匹配字段 {#what-a-rule-matches}

| 字段 | 明文 HTTP 或 MITM | TLS 透传 |
| --- | --- | --- |
| `rules[].ip` / `cidr` / `ports` | 原始目标地址和端口 | 原始目标地址和端口 |
| `httpRules[].match.hosts` | HTTP Host / `:authority` | TLS SNI |
| `httpRules[].match.ports` | 实际目标端口；HTTP Host 端口写法要求见下文 | 实际目标端口 |
| `paths` | 归一化的 URL 路径 | 忽略 |
| `methods` | 区分大小写的精确方法 token | 忽略 |

没有 hosts 的 HTTP 规则不会生成 SNI 权限。有 host 且限制 path/method 的规则，在 TLS 透传时仍只根据 host/port 授权或拒绝。依赖 HTTPS 路径/方法控制前必须配置 MITM。

Host/SNI 匹配忽略大小写，支持精确名称与通配后缀；`*.example.com` 不包含裸父域 `example.com` 或伪造后缀 `example.com.attacker.test`。HTTP/SNI 规则的通配匹配与 TLS 证书通配有效性是不同检查：MITM 通配证书只覆盖一层 DNS label。边界较窄时优先列举明确名称。

`methods: [GET]` 不匹配 `get` 或 `GeT`。自定义方法同样受支持，规则中的大小写应与客户端发送的方法一致。

路径区分大小写。`prefix: /api` 也匹配 `/apix`；要限制子树应使用 `/api/`，必要时另加精确 `/api`。路径匹配不含查询字符串。代理在授权和转发前归一化路径、合并重复斜杠，并解码转义的斜杠/反斜杠分隔符；后端有额外路径解释时，应检查后端实际看到的结果。

端口匹配实际目标端口，不能只靠伪造 Host 端口满足条件。显式非默认端口还要求 HTTP Host 中携带相应端口。优先使用含实际目标端口的正常 URL；向其他端口连接时伪造 `Host: ...:443` 不能满足目标 443 规则。

## 流量处理与 MITM 范围 {#chain-selection-and-mitm-scope}

`mitm.domains` 选择解密范围，**不是允许列表**。被拦截的请求仍需通过 HTTP/L4 授权。

目标 IP、TLS SNI 和协议共同决定流量是否被拦截。配置 IP MITM 后，发往该 IP 的明文请求仍执行 HTTP 规则。

| 情况 | 处理方式 |
| --- | --- |
| 发往 MITM IP 的明文 HTTP | 仍执行 HTTP 规则 |
| 使用已配置 DNS SNI 的 TLS，包括目标也是 MITM IP | 按 DNS 名称解密 HTTPS 并执行 HTTP 规则 |
| 发往 MITM IP 且无 SNI 的 TLS | 按 IP 解密 HTTPS 并执行 HTTP 规则 |
| 不在适用 MITM 范围内的 TLS | TLS 透传；加密 HTTP 不可见 |
| 非 HTTP、非 TLS 的 TCP | TCP 规则 |

## 域前置缓解边界 {#domain-fronting-boundary}

MITM 会检查解密后的请求目标（HTTP/1.1 的 Host，或 HTTP/2 的 `:authority`）。按 DNS 名称拦截的连接只能请求配置的 DNS 目标，按 IP 拦截的连接只能请求配置的 IP 目标；超出相应范围通常返回 404，不转发到上游。范围内的请求仍需满足 HTTP/L4 规则。

这**不要求下游 SNI 与 HTTP Host 一一相等**。A/B 都在配置的 DNS MITM 范围内时，SNI=A、Host=B 可以按 B 的规则继续处理。按 IP 拦截时，也不要求目标 IP 与 HTTP Host 一一相等。

上游 MITM TLS 根据路由的 HTTP authority 设置 SNI 并校验证书身份，但连接仍使用原始目标地址；不会重新按 Host 解析 IP，也不建立 DNS/IP 绑定。TLS 透传无法执行这些解密后的 Host 检查。

审计选择见[可观测性](observability.md)，身份与信任约束见[TLS 与凭据](tls-and-credentials.md)。
