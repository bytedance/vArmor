---
sidebar_position: 7
---

# 故障排查 {#troubleshooting}

根据下表定位问题，结合策略状态、Pod 事件和代理日志检查原因。处理后发送允许和拒绝请求，确认结果符合预期。

## 按现象检查 {#symptom-checklist}

| 现象 | 检查 | 恢复 |
| --- | --- | --- |
| 无 sidecar | 启用标签、target kind/name/labels、namespace、集群策略优先级 | 修正选择，检查控制器并创建新测试 Pod |
| init 反复失败 | init 日志中的权限或 iptables 错误 | 修复权限或网络配置错误，再重建 Pod；不要忽略 iptables 错误 |
| 连接失败或代理 OOM | Pod 事件、代理日志、后端可用性和资源使用情况 | 根据错误恢复后端连通性或调整资源 |
| HTTPS 路径限制无效 | TLS 透传还是 MITM、是否有宽泛 L4 allow | 配置拦截/信任，去掉意外的替代授权 |
| MITM 404 | HTTP Host 是否属于相应 MITM 目标范围，IPv6 写法是否一致 | 按[目标范围规则](policy-semantics.md#domain-fronting-boundary)核对 MITM 配置和客户端请求 |
| TLS 验证失败 | 分别检查应用 CA、上游 CA/身份、旧信任缓存 | 修正相应信任，等待证书文件更新并重载相关进程 |
| 更新后允许请求返回 503 | 代理配置加载、证书更新和后端连通性 | 修复代理或后端错误，等待代理就绪后重试请求 |
| policy Ready 但行为仍旧 | 配置被拒绝、文件更新延迟或启动配置 | 修正策略配置，确认更新成功后验证请求 |
| Secret 更新但头仍旧 | 策略 generation 及处理状态 | 按[凭据轮换](tls-and-credentials.md#rotate-and-verify)执行真实 spec 更新 |
| 凭据更新后 policy Error | Secret/key 缺失、空/不安全值、配置体积 | 修复引用的 Secret 或配置，并更新策略；旧有效配置仍生效 |
| 无审计 | 矩阵预期、节点/sidecar 路径、Agent/代理版本兼容性 | 检查[可观测性](observability.md)及[升级说明](lifecycle-and-upgrades.md#upgrade-varmor-and-its-proxy-together) |

## 检查实际进程身份 {#confirm-process-identity-not-only-the-pod-specification}

sidecar 从 root 启动，入口将 Envoy 降权为策略 UID。`kubectl exec ... id` 描述的是新辅助进程，不一定代表正在运行的 Envoy。检查 `/proc/<envoy-pid>/status` 的 UID。读取前先确认 Envoy 的进程 ID。

## 恢复边界 {#recovery-boundaries}

- 新配置被拒绝时 Envoy 可保留旧配置；应检查代理日志，确认新规则已加载。
- 读取已有 MITM Secret 失败目前可能导致新 CA 生成。遇到意外 CA 变化，检查 Manager/API 错误、确认新 bundle 并重载缓存旧 CA 的应用。
- 如果初始化在创建部分重定向规则后失败，请先修复权限或网络后端错误，再重建 Pod，以使用干净的网络命名空间。
- 集群策略向新 namespace 发布配置可能因源 Secret 缺失失败。修复后执行合法 policy spec 更新。
- 生成 Secret 数据超过 700 KiB 告警，超过 900 KiB 拒绝。host、port、path、method 的组合会展开配置；应减少规则/域名/头注入规模，不要绕过检查。

## 提交问题时 {#when-reporting-a-problem}

提供 vArmor revision、运行时、Kubernetes 版本、代理 imageID、脱敏策略、目标 kind、策略状态、容器状态和可复现允许/拒绝对照。说明初始注入是否启用 MITM、失败前做了什么变更，并提供后端命中与相应审计证据。不要附凭据、私钥或完整生成配置。
