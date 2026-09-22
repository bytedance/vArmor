---
sidebar_position: 5
---

# 生命周期与升级 {#lifecycle-and-upgrades}

规则修改可以在已有代理中动态生效。容器镜像、资源或 TLS 挂载的变化需要更新工作负载配置并替换 Pod。可按下表安排变更。

## 变更矩阵 {#change-matrix}

| 变更 | 操作 |
| --- | --- |
| HTTP/L4 规则 | 更新策略，等待代理加载，再验证新请求 |
| 头注入源 Secret 的值 | 更新 Secret 后，执行一次合法的策略 spec 更新，见[凭据轮换](tls-and-credentials.md#rotate-and-verify) |
| 已启用 MITM 的 Pod 增删域名 | 等待代理配置和证书更新，再验证 HTTPS 请求 |
| 首次启用 MITM | 重建受影响的 Pod，使其获得 TLS 挂载和应用 CA 配置 |
| 更换 CA 或信任 bundle | 重载或重启缓存 CA bundle 的应用，再验证 TLS 连接 |
| 修改代理镜像或资源配置 | 更新工作负载模板并滚动替换 Pod |
| 修改代理 UID 或监听端口 | 创建替代策略；已有策略的这些字段不可修改 |

动态配置需要一定时间才能到达各个 Pod。更新过程中，代理加载所需配置时，新请求可能短暂失败。规则变化不一定关闭已有连接；如果需要终止已有会话，应在发布计划中安排连接排空或 Pod 替换。

## 配套升级 vArmor 和代理 {#upgrade-varmor-and-its-proxy-together}

使用同一发行版本配套的 Manager、Agent 和代理镜像，并按发布说明确认升级要求。

如果升级涉及审计日志兼容性变化，按以下顺序操作，以保持审计采集正常：

1. 升级节点 Agent。
2. 对微虚机工作负载，更新工作负载模板中的代理镜像并滚动替换 Pod，因为这类 Pod 在内部采集审计日志。
3. 升级 Manager，再检查受影响策略的状态、代理就绪状态和审计日志。

修改安装配置中的默认代理镜像不会更新已运行的容器。升级时应同时处理受影响的工作负载模板和 Pod。如果版本涉及代理启动配置变化，应在配置更新后重建受影响的 Pod。

升级后验证一条允许请求、一条拒绝请求及其预期审计记录。HTTP 方法区分大小写，标准 GET 请求应使用 `GET`。

## 有计划地撤销策略 {#remove-a-policy-deliberately}

`updateExistingWorkloads` 控制创建或删除策略时是否更新控制器管理的工作负载。撤销防护前，请阅读[使用说明](../../../getting_started/usage_instructions.md)和[API](../../../getting_started/interface_specification.md)。

检查更新后的工作负载模板和替代 Pod，确认代理容器与挂载已移除。按需重建独立 Pod，再验证网络连通性。快速开始示例可直接按教程删除专属命名空间。
