---
sidebar_position: 5
---

# 生命周期与升级 {#lifecycle-and-upgrades}

区分策略调和、投影的 Envoy 配置和 Kubernetes Pod 模板；其中一项变化不代表其他项已收敛。

## 变更矩阵 {#change-matrix}

| 变更 | 检查与动作 |
| --- | --- |
| 已注入 Pod 的 HTTP/L4 规则 | 调和、等待动态配置、验证新请求；不承诺切换零错误 |
| 头注入源 Secret | 更新后执行合法 policy spec 更新，以不打印凭据的方式验证 |
| 已具备 MITM 挂载的 Pod 增删身份 | 检查 LDS/CDS、证书和 validation SDS、信任及新请求 |
| 原本缺少 TLS volume 的 Pod 首次启用 MITM | 更新/重建工作负载模板，确认新 Pod 获得挂载和 CA 配置 |
| 更换 CA 或信任 bundle | 检查代理和应用文件，重载或重启缓存 CA 的应用 |
| 静态 bootstrap 变化 | 先确认生成内容更新，再重启 Envoy 或重建 Pod |
| 镜像或资源设置变化 | 检查/更新已注入模板并滚动替换；默认值变化不会修改已有容器 |
| UID 或代理/管理端口变化 | 字段不可变，规划替代策略/工作负载迁移并验证新重定向 |
| 修复已注入旧模板 | 显式修复存储的模板，普通规则更新不等于模板修复 |

同 Pod 动态更新回归是在检查投影及真实行为后测试新请求，不承诺立即撤销已有连接、多文件原子更新或收敛期间始终可用。暂时的 503 可能表示上游 cluster 或信任依赖尚未就绪。

## 配套升级 vArmor 和代理 {#upgrade-varmor-and-its-proxy-together}

镜像内容变化使用新标签或不可变 digest。IfNotPresent 可配合不可变标签使用；重复使用标签可能让节点运行不同二进制。应检查 Manager/Agent revision、注入 image 与实际 imageID，不能只看 Helm app version。

引入 `varmor_np_event` 审计流的升级遵循接收端先于生成端：

1. 旧 Manager 继续产生兼容配置时，先升级节点 Agent。
2. 升级微虚机 sidecar 内嵌接收器，包括已有模板和 Pod。
3. 再升级 Manager，通过调和重新生成配置，检查代理加载和日志交付。

不能将新流名发给旧接收器。默认镜像变化不会替换旧内嵌接收器；Manager 升级也不能证明所有已有 Secret 已重新生成。

自定义 HTTP 方法处理同时依赖静态 bootstrap runtime 设置和 LDS 选项。升级后先确认生成 bootstrap 已刷新，再重建代理，之后才能依赖该能力。v0.10.5 方法 token 区分大小写；标准 GET 应写为 GET，而不是依赖旧实现转大写的 get。

## 修复旧的非 root 模板 {#recover-an-old-non-root-template}

修复后的注入路径为两个注入容器显式设置 `runAsUser: 0`、`runAsNonRoot: false`，保留业务上下文。旧模板可能仍缺少字段，已有注入 annotation 会影响 webhook 重新注入。

集群实测中，普通 HTTP 规则更新**没有**修复这种 Deployment 模板。因此只升级 Manager，或从未修正模板重启，不足以恢复。

对受影响 Deployment，可审查下面的定向 strategic-merge patch 并替换名称。它保留其他容器字段：

```bash
kubectl patch deployment YOUR_DEPLOYMENT -n YOUR_NAMESPACE --type=strategic -p '
{"spec":{"template":{"spec":{
  "initContainers":[{"name":"varmor-network-proxy-init","securityContext":{"runAsUser":0,"runAsNonRoot":false}}],
  "containers":[{"name":"varmor-network-proxy","securityContext":{"runAsUser":0,"runAsNonRoot":false}}]
}}}}'
kubectl rollout status deployment/YOUR_DEPLOYMENT -n YOUR_NAMESPACE
```

仅当这两个注入容器名称已存在时使用。检查模板和新 Pod，验证业务身份、Envoy 实际 UID 和允许/拒绝请求，再确认后续重建同样正常。该集群恢复实测覆盖 Deployment，不能宣称已实测所有控制器类型。

## 有计划地撤销策略 {#remove-a-policy-deliberately}

updateExistingWorkloads 影响创建/删除策略时的控制器工作负载更新，使用前阅读[使用说明](../../../getting_started/usage_instructions.md)和[API](../../../getting_started/interface_specification.md)。检查模板及替代 Pod，确认 sidecar、挂载和路由按预期移除。

删除策略本身不能证明已有连接或已注入的独立 Pod 已重置。隔离教程直接删除专属 namespace；生产撤防应规划并验证替代 Pod 和连通性。
