---
sidebar_position: 7
---

# 故障排查 {#troubleshooting}

从自有目标和一组允许/拒绝对照开始。保留第一次失败的证据，不能把反复重试直到成功视为配置正确的证明。

## 按现象检查 {#symptom-checklist}

| 现象 | 检查 | 恢复 |
| --- | --- | --- |
| 无 sidecar | 启用标签、target kind/name/labels、namespace、集群策略优先级 | 修正选择，检查控制器并创建新测试 Pod |
| 非 root 继承导致 CreateContainerConfigError | 存储模板中的注入容器字段 | 按[旧模板修复](lifecycle-and-upgrades.md#recover-an-old-non-root-template)处理 |
| init 反复失败 | 权限、netfilter backend、部分已创建链 | 修复持续原因，再重建 Pod/网络命名空间；不要忽略 iptables 错误 |
| EOF、拒绝连接或代理反复 OOM | 实际 Envoy UID、proxyUID、imageID、入口 | 使用配套自定义镜像和新 Pod；增加内存不是修复证明 |
| HTTPS 路径限制无效 | TLS 透传还是 MITM、是否有宽泛 L4 allow | 配置拦截/信任，去掉意外的替代授权 |
| MITM 404 | authority 是否属于该链虚拟主机，包括 IPv6 文本差异 | 对齐身份和 Host，不能盲目增加 catch-all |
| TLS 验证失败 | 分别检查应用 CA、上游 CA/身份、旧信任缓存 | 修正相应信任，等待投影并重载相关进程 |
| 更新后允许请求返回 503 | LDS/CDS/validation SDS 收敛及上游连通 | 检查代理错误和后端，再做有界 readiness 检查 |
| policy Ready 但行为仍旧 | 配置拒绝、旧投影、静态 bootstrap | 修正输入、调和并验证加载及真实请求 |
| Secret 更新但头仍旧 | generation 和成功调和 | 按[凭据轮换](tls-and-credentials.md#rotate-and-verify)执行真实 spec 更新 |
| 凭据更新后 policy Error | Secret/key 缺失、空/不安全值、配置体积 | 修复依赖并调和；旧有效配置仍生效 |
| 无审计 | 矩阵预期、节点/sidecar 路径、ALS 接收器兼容 | 检查[可观测性](observability.md)及先接收端后生成端升级顺序 |

## 检查实际进程身份 {#confirm-process-identity-not-only-the-pod-specification}

sidecar 从 root 启动，入口将 Envoy 降权为策略 UID。`kubectl exec ... id` 描述的是新辅助进程，不一定代表正在运行的 Envoy。应使用获授权的诊断方式检查 `/proc/<envoy-pid>/status` 的 UID。微虚机模式下 PID1 可能是 supervisor，不能总假定 `/proc/1` 属于 Envoy。

不兼容缓存镜像即使标签和环境变量看似正确，也可能使用其他入口/UID。对比 imageID 和实际入口行为；修复后验证允许/拒绝及重启是否停止。

## 恢复边界 {#recovery-boundaries}

- 新配置被拒绝时 Envoy 可保留旧配置；Ready 不是按策略版本关联的代理确认。
- 读取已有 MITM Secret 失败目前可能导致新 CA 生成。遇到意外 CA 变化，检查 Manager/API 错误、确认新 bundle 并重载缓存旧 CA 的应用；不能承诺临时读取失败时自动保留 CA。
- init 部分执行后，在同一网络命名空间重试不保证安全幂等；修复权限/backend 后重建 Pod。
- 集群策略向新 namespace 发布配置可能因源 Secret 缺失失败。修复后执行合法 policy spec 更新，不能依赖未文档化强制同步 annotation 或保证存在的自动重试。
- 生成 Secret 数据超过 700 KiB 告警，超过 900 KiB 拒绝。host、port、path、method 的组合会展开配置；应减少规则/域名/头注入规模，不要绕过检查。

这些是当前实现的运行边界，未来恢复方案不代表已有保障。

## 提交问题时 {#when-reporting-a-problem}

提供 vArmor revision、运行时、Kubernetes 版本、代理 imageID、脱敏策略、目标 kind、策略状态、容器状态和可复现允许/拒绝对照。说明初始注入是否启用 MITM、失败前做了什么变更，并提供后端命中与相应审计证据。不要附凭据、私钥或完整生成配置。
