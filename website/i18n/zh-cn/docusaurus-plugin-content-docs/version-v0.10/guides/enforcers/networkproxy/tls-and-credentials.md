---
sidebar_position: 3
---

# TLS 与凭据 {#tls-and-credentials}

先完成 [HTTP 快速开始](quick-start.mdx)。MITM 还要求应用信任 vArmor CA，以及 Envoy 信任上游；解释 TLS 错误前应分别检查两者。

## 两段信任关系 {#the-two-trust-relationships}

| TLS 连接 | 要求 |
| --- | --- |
| 应用 → Envoy | 应用信任策略 MITM CA，接受生成的服务端身份 |
| Envoy → 上游 | 上游证书链被代理信任，身份与路由 HTTP authority 匹配 |

vArmor 在各策略配置命名空间生成 CA，并将证书材料与 Envoy 配置一起发布。业务容器只接收包含公共根证书和 MITM CA 的 bundle，不接收 CA 私钥。业务容器尚未定义相应变量时，注入器提供 `SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE`、`NODE_EXTRA_CA_CERTS`、`CURL_CA_BUNDLE`。

环境变量不代表所有 SDK 自动兼容。已有信任变量、自定义 trust store、证书固定和 CA 缓存可能需要应用配置。文件投影更新不等于业务进程重载信任库；验证 MITM 不应使用 `curl -k`。

通常从公共可信上游开始。私有上游 CA 是另一项信任需求，不能与应用到代理的信任混淆。当前策略 API 没有通用上游 CA 引用字段。测试中修改生成 Secret 的方式不应成为生产配置流程，因为后续调和可能覆盖生成内容。

## 同时配置拦截与授权 {#configure-interception-and-authorization-together}

下面是**策略片段**，不是完整 Kubernetes 资源。请将域名替换为自有 HTTPS 服务，且 Envoy 能验证其证书：

```yaml
policy:
  enforcer: NetworkProxy
  mode: EnhanceProtect
  enhanceProtect:
    networkProxyRawRules:
      egress:
        defaultAction: deny
        httpRules:
        - qualifiers: [allow, audit]
          match:
            hosts: [api.example.com]
            ports: [{port: 443}]
            paths: [{prefix: /v1/}]
            methods: [POST]
  networkProxyConfig:
    mitm:
      domains: [api.example.com]
```

先创建策略，再创建测试工作负载，以获得 TLS 挂载。已有非 MITM Pod 应按[生命周期与升级](lifecycle-and-upgrades.md)处理，Secret 更新不能给 Pod 添加缺失的挂载。

API 支持精确 DNS、通配 DNS、IP 字面量和单主机 CIDR（IPv4 `/32`、IPv6 `/128`）。父域应与 `*.example.com` 分别列出。域名项不能含首尾空白或重复身份。IPv6 还有[文本一致性约束](security-and-compatibility.md#ipv6)。

## 注入凭据头 {#inject-a-credential-header}

Secret 必须位于**目标工作负载的命名空间**。VarmorClusterPolicy 的每个目标命名空间均需要自己的引用 Secret。以下仅为可丢弃的演示值：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: upstream-credential
  namespace: varmor-networkproxy-demo
type: Opaque
stringData:
  authorization: "Bearer demonstration-only"
```

在 `spec.policy.networkProxyConfig.mitm` 下、与 domains 同级添加：

```yaml
headerMutations:
- domain: api.example.com
  headers:
  - name: Authorization
    secretRef:
      name: upstream-credential
      key: authorization
```

mutation 的 domain 必须与 domains 中一项完全一致，包括大小写；不展开通配符，也不将 IP/CIDR 当作同一个引用。value 和 secretRef 必须二选一。值按原样注入，包括 `Bearer ` 前缀，并替换已有同名头。避免凭据文件末尾换行；空值或不安全字符会导致配置生成失败。

**引用 Secret 不会让凭据从 Envoy 配置中消失。** Manager 在调和时读取并将值写入 LDS。能读取生成配置 Secret、sidecar 配置或敏感代理诊断信息的主体也能访问凭据。业务容器不必挂载源 Secret，但允许的上游若回显请求头，或应用具有过大的 Kubernetes 权限，仍可暴露凭据。这些路径与源 Secret 都需要保护。

## 轮换与验证 {#rotate-and-verify}

1. 按凭据管理流程更新源 Secret。
2. 执行真正有效的策略 **spec** 更新。当前不监听源 Secret，任意 annotation 不是受支持的强制同步入口。可修改一条规则的 description 以触发 spec 更新而不改变授权条件，并检查 generation/status。
3. 检查调和错误，等待配置投影和实际代理加载。通过自有后端的非敏感指标确认新请求使用了更新值，不打印凭据。
4. 复核允许/拒绝行为，在验证完成及必要的重叠期后撤销旧凭据。

Secret/key 缺失、空值或不安全值可能导致 `phase: Error`、`ready: false`。更新失败时，该命名空间保留上一份有效配置，意味着请求的收紧和轮换**尚未生效**。修复依赖后再次执行合法 spec 更新。集群策略不提供跨命名空间原子发布或回滚。

这些操作不保证立即撤销已有连接，也不保证多个应用之间的 CA 原子替换，详见[生命周期与升级](lifecycle-and-upgrades.md)。
