---
slug: varmor-0.10.4-new-features-overview
title: "vArmor v0.10.4: NetworkProxy 审计落地、微虚机(Kata)兼容与生产化运维增强"
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes, AIAgent, NetworkProxy]
date: 2026-08-04T00:00
---

在 vArmor v0.10.0 中，我们引入了 [NetworkProxy enforcer](/zh-cn/blog/varmor-0.10.0-new-features-overview/)，以 Sidecar 代理架构为 Kubernetes 工作负载带来了 L4/L7 网络访问控制能力；在 [v0.10.1](/zh-cn/blog/varmor-0.10.1-new-features-overview/) 中，我们完成了第二阶段的 TLS 中间人（MITM）能力，将其升级为覆盖加密流量的深度包检测引擎。

vArmor v0.10.4 是一次面向 **生产化** 的发版。我们把重心放在：让 NetworkProxy 的 **审计能力真正落地**——审计日志可持久化、可关联工作负载身份；让 vArmor 在 **微虚机（Kata / Serverless 沙箱）** 等非标准运行时环境中稳定工作；并通过 **集群级 Sidecar 资源配额管理** 和 **iptables 后端自适应** 降低大规模部署的运维成本。此外，policy-advisor 的冲突检测也更加精准。

<!--truncate-->

## 为什么聚焦"审计落地"与"运行时兼容"？

NetworkProxy enforcer 在前两个版本解决了"能不能管控"的问题——从域名级守门到加密流量的深度检测。但当用户把它部署到真实的生产集群，尤其是运行 AI Agent 的多租户环境时，新的工程问题浮现出来：

- **审计日志去哪了？** enforcer 支持 `audit` 限定符，但被审计的出口流量记录需要一个稳定、可采集的落盘位置，并且要能关联到具体是哪个 Pod、哪个工作负载产生的。
- **微虚机场景怎么办？** 越来越多的 AI Agent 工作负载运行在 Kata Containers 或云厂商 Serverless（如火山引擎 VCI、阿里云 ECI）之上。这类微虚机运行时的网络命名空间和挂载边界与 runc 不同，原有的审计采集路径和 iptables 注入方式会失效甚至导致流量被静默丢弃。
- **大规模部署的资源怎么统一管？** MITM Sidecar 比直通代理更消耗资源，逐条策略配置资源配额在集群规模上并不现实。

v0.10.4 正是围绕这三个问题展开。

## NetworkProxy 出口审计日志持久化

NetworkProxy enforcer 通过其 Envoy Sidecar 上报出口流量的违规审计事件。v0.10.4 完成了这条审计链路的持久化落地：

- **统一落盘路径**：所有被审计的出口流量记录最终写入容器可见的 `/var/log/varmor/violations.log`，格式为归一化的结构化记录，便于日志采集系统统一消费。
- **节点级采集（runc）**：在 runc 运行时下，Envoy Sidecar 通过节点级的 hostPath Unix Domain Socket，将审计记录以 gRPC ALS（Access Log Service）方式流式发送到节点上的 `varmor-agent` DaemonSet，由 agent 负责写入日志文件。这样审计数据的写入与采集解耦，不占用应用容器的资源与权限。
- **Pod 级身份关联**：由于这些事件由代理在 Pod 粒度上产生，每条记录都携带 Pod 级别的身份信息（`nodeName`、`podName`、`podNamespace`、`podUID`），安全团队可以据此把每一次网络访问精确关联到具体工作负载，而不再是一条脱离上下文的孤立日志。

这使得 NetworkProxy 的审计模式从"能记录"进化为"能被生产级日志体系采集、能被关联溯源"。

## 微虚机（Kata / Serverless）审计与流量重定向兼容

这是 v0.10.4 面向真实 AI Agent 部署环境的核心改进。微虚机运行时（Kata、Serverless 沙箱）的边界与 runc 截然不同，vArmor 在两条关键路径上做了自适应处理。

### 审计采集：Sidecar 内置 ALS Sink

在微虚机运行时下，Sidecar 运行在微虚机内部，前述的节点级 hostPath Socket **无法跨越虚机边界**（部分 Serverless 厂商甚至会在准入阶段直接拒绝这类 hostPath 挂载）。为此，vArmor 对被识别为微虚机的工作负载：

- **省略 hostPath 卷与挂载**，避免因挂载被拒导致 Pod 无法调度；
- **启动一个 Sidecar 内置的审计 Sink**，将 Socket 绑定在容器自身的 rootfs 中，直接写入容器本地的 `/var/log/varmor/violations.log`。

无论 runc 还是微虚机，最终产出的审计记录 **逐字节一致**，上层采集与分析逻辑无需区分运行时。

### 微虚机识别：`microVMDetection`

vArmor 通过 `microVMDetection` 配置来判断哪些工作负载运行在微虚机运行时下。判定逻辑为：工作负载的 `runtimeClassName` 命中列表 **或** 任一 annotation 规则命中 **或** 任一 label 规则命中（对 annotation/label 规则，空值表示仅按键是否存在匹配，非空值则必须精确匹配）。内置默认值已覆盖上游 Kata 及主流云厂商的 Serverless 运行时：

| 维度 | 内置默认值 |
|------|-----------|
| `runtimeClassNames` | `kata`、`kata-qemu`、`kata-clh` |
| annotation | `vke.volcengine.com/burst-to-vci=enforce`（火山引擎 VKE burst-to-VCI） |
| label | `alibabacloud.com/eci=true`（阿里云 ECI） |

如需为自定义的微虚机运行时扩展识别规则，可编辑 `varmor-config` ConfigMap，或在安装时设置 `dynamicConfig.microVMDetection` 的取值，**无需重启即可热加载**。

### 流量重定向：iptables 后端自适应

NetworkProxy enforcer 通过 init 容器注入 iptables 规则来透明地重定向出口流量。不同运行时和不同基础设施（如某些 PaaS mesh）使用的 iptables 后端并不一致（`legacy` 与 `nft`），硬编码某一种后端可能导致流量被静默丢弃——例如一个 Kata Pod 的网络命名空间同时被使用 `legacy` 后端的 PaaS mesh init 编程时。

从 `proxyinit:v0.2` 镜像开始，vArmor **自动探测目标网络命名空间中已在使用的 iptables 后端并驱动匹配的后端**：

- 在全新的网络命名空间上默认使用 `nft`（与既有行为保持一致）；
- 若检测到两种后端都已存在规则，则以 `CONFLICT` 显式中止，而非盲目猜测导致隐蔽故障。

该能力完全自动、无需任何配置开关，只需确保 Chart 拉取 `proxyinit:v0.2` 或更新版本即可。

## 集群级 Sidecar 资源配额管理

在 [v0.10.1 的未来规划](/zh-cn/blog/varmor-0.10.1-new-features-overview/)中，我们提出要提供集群级的 Sidecar 资源默认值管理。v0.10.4 兑现了这一承诺。

vArmor 新增了一份运行时可热加载的动态配置，承载于 vArmor 所在命名空间下的 `varmor-config` ConfigMap 中。Manager 通过 informer 监听该 ConfigMap，变更时 **无需重启** 即可热加载；若 ConfigMap 缺失或格式非法，则回退到与 Chart 随附取值完全一致的内置默认值。

管理员从此只需 **配置一次**，即可为整个集群注入的 NetworkProxy Sidecar 设置默认资源 requests/limits，而不必在每条策略上单独设置 `.spec.policy.networkProxy.resources`。注入器采用 **三层、字段级的合并链** 解析最终资源，每个叶子字段（`requests.cpu`/`requests.memory`/`limits.cpu`/`limits.memory`）独立回退：

> 策略级覆盖 > 集群级全局配置（`varmor-config`） > 内置默认值

考虑到 MITM Sidecar 负载更重（双向 TLS 握手），配置区分为两个相互独立的层级——MITM Sidecar 只读取 `mitm` 层，非 MITM Sidecar 只读取 `nonMitm` 层，两层之间不相互继承。内置默认值如下：

| 层级 | CPU requests | 内存 requests | CPU limits | 内存 limits |
|------|-------------|---------------|-----------|-------------|
| `nonMitm` | 50m | 64Mi | 500m | 256Mi |
| `mitm` | 100m | 128Mi | 1000m | 512Mi |

```bash
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.cpu="50m" \
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.memory="64Mi" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.cpu="1000m" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.memory="512Mi"
```

使用时需注意：资源数量务必以字符串形式加引号（如 `"500m"`、`"256Mi"`），未加引号的裸数字会被解析为整数（`memory: 100` 表示 100 字节而非 100Mi）；层级键名必须严格拼写为 `nonMitm` 和 `mitm`，拼写错误会被静默忽略并回退到内置默认值；非法条目（未知资源名、无法解析的数量、非正值，或同层内 limit 低于 request）会被忽略并在 Manager 加载时记录日志。

## policy-advisor：更精准的 shell 使用冲突检测

policy-advisor 支持基于行为数据过滤掉与之冲突的内置规则，使生成的策略模板更加精准。v0.10.4 增强了 `disable-shell` 等规则的匹配能力：advisor 在匹配时会 **同时依据可执行文件的 basename 及其文件扩展名** 进行判断。

因此，即使某个 shell 仅以脚本路径的形式出现在行为数据中（例如 `/var/lib/cilium/bpf/init.sh`，而没有独立的 `sh`/`bash`/`dash` 二进制执行记录），也能通过其 `.sh` 扩展名被正确识别为冲突，从而过滤掉相应的冲突规则，避免生成误伤业务的策略。

## 升级说明

- NetworkProxy 的 init 容器镜像需为 `proxyinit:v0.2` 或更新版本，以启用 iptables 后端自适应能力。
- 微虚机识别与 Sidecar 资源默认值均通过 `varmor-config` ConfigMap 的 `dynamicConfig` 承载，支持安装时初始化，也支持安装后热更新，变更无需重启。

## 总结

如果说 v0.10.0 和 v0.10.1 回答了"vArmor 能否管控 AI Agent 的网络行为"，那么 v0.10.4 回答的是"vArmor 能否在真实的生产集群里稳定、可观测、低运维成本地做到这一点"。通过审计日志的持久化与 Pod 级身份关联、对微虚机（Kata / Serverless）运行时在审计采集与流量重定向两条路径上的自适应兼容、集群级 Sidecar 资源配额的统一管理，以及 policy-advisor 更精准的冲突检测，本次发版让 NetworkProxy enforcer 更加贴近大规模、多运行时、多租户的真实部署环境。

欢迎升级体验 vArmor v0.10.4，并通过 [GitHub](https://github.com/bytedance/vArmor) 向我们反馈使用体验！完整详情请参阅 [Release Notes](https://github.com/bytedance/vArmor/releases/tag/v0.10.4)。
