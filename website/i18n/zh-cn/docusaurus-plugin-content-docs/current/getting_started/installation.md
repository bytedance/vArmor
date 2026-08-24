---
sidebar_position: 1
description: 了解如何安装、配置、更新和卸载 vArmor。
---
# 安装指引

## 前置条件

不同 Enforcer 所需要的前置条件如下表所示。

|强制访问控制器|要求|推荐|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15+<br />2. 系统需开启 AppArmor LSM|GKE with Container-Optimized OS<br />AKS with Ubuntu<br />[VKE](https://www.volcengine.com/product/vke) with veLinux<br />Debian 10 及以上版本<br />Ubuntu 18.04.0 LTS 及以上版本<br />[veLinux](https://www.volcengine.com/docs/6396/74967) 等
|BPF         |1. Linux Kernel 5.10+ (x86_64) 或 6.6+ (arm64)<br />2. containerd v1.6.0+<br />3. 系统需开启 BPF LSM|EKS with Amazon Linux 2<br />GKE with Container-Optimized OS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux (with 5.10 kernel)<br />AKS with Ubuntu 22.04 LTS <sup>\*</sup><br />ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br />OpenSUSE 15.4  <sup>\*</sup><br />Debian 11 <sup>\*</sup><br />Fedora 37<br />[veLinux (with 5.10 kernel)](https://www.volcengine.com/docs/6396/74967) 等<br /><br />* *需手动启用节点的 BPF LSM*
|Seccomp     |1. Kubernetes v1.19+|所有 Linux 发行版
|NetworkProxy|-|所有 Linux 发行版

## 安装

vArmor 推荐使用 Helm chart 进行部署。通过 Helm 安装前，请先拉取 chart 包。

```
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.10.4
```

然后使用 helm 命令及[配置选项](#配置选项)进行安装和配置。

```
helm install varmor varmor-0.10.4.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-cn-beijing.cr.volces.com"
```

*您可以在非中国地区使用 elkeid-ap-southeast-1.cr.volces.com 域名*

## 配置选项

您可以使用以下选项，在安装或更新时配置 vArmor 的功能。

### 通用选项

#### 关闭 AppArmor enforcer
当宿主机不支持 AppArmor LSM 时，应当主动关闭 AppArmor enforcer。默认值：开启。

```bash
--set appArmorLsmEnforcer.enabled=false
```

#### 开启 BPF enforcer
当宿主机支持 BPF LSM 时，可以开启 BPF enforcer。默认值：关闭。

```bash
--set bpfLsmEnforcer.enabled=true
```

#### 开启 BehaviorModeling 模式
这是一个实验性质的功能。当前只有 AppArmor 和 Seccomp enforcer 支持 BehaviorModeling 模式。请参考  [BehaviorModeling Mode](../guides/policies_and_rules/policy_modes/behavior_modeling.md) 了解更多细节。默认值：关闭。

```bash
--set behaviorModeling.enabled=true
```

#### 配置系统审计日志的搜索列表
vArmor 顺序检查系统的审计日志是否存在，并通过监控第一个有效的文件来获取 AppArmor 和 Seccomp 的审计事件，从而用于违规审计和行为建模功能。当您使用 *auditd* 时，AppArmor 和 Seccomp 的审计事件会默认保存在 `/var/log/audit/audit.log` 文件中。否则，他们通常会被保存在 `/var/log/kern.log` 文件中。

你可以使用这个选项来配置审计日志、文件搜索顺序。请使用`|`来分割文件。默认值：`/var/log/audit/audit.log|/var/log/kern.log`。

```bash
--set "agent.args={--auditLogPaths=FILE_PATH|FILE_PATH}"
```

#### 配置监控指标
您可以开启指标来监控 vArmor。指标将在所有 Manager 实例 `8081` 端口上的 `/metric` 路径对外暴露。默认值：关闭。

```bash
--set metrics.enabled=true
```

如果您的集群支持 `monitoring.coreos.com/v1` API，vArmor 会在部署时自动创建一个 `ServiceMonitor` 对象，用于与 Prometheus 集成。

#### 设置日志格式为 JSON
Agent 和 Manager 的日志格式默认为文本格式，您可以使用下面的选项将其设置为 JSON 格式。

```bash
--set jsonLogFormat.enabled=true
```

#### 注入元数据到违规事件
此功能使您能够将自定义元数据注入到违规事件。它通过将违规事件与特定于环境的上下文相关联来增强 vArmor 审计日志的可观测性。默认值为空。

您可以使用类似下面的选项来添加元数据的键值对。

```bash
--set auditEventMetadata.clusterID="ID" \ 
--set auditEventMetadata.clusterName="NAME" \  
--set auditEventMetadata.region="REGION"  
```

### 高级选项

#### 设置 Webhook 的匹配标签
vArmor 只会对包含此 label 的 Workloads 开启沙箱防护。你可以使用此选项配置所需的 label，或者使用 `--set 'manager.args={--webhookMatchLabel=}'` 关闭此特性。默认值：`sandbox.varmor.org/enable=true`。

```bash
--set "manager.args={--webhookMatchLabel=KEY=VALUE}"
```

#### 禁止重启存在的工作负载
在创建、删除策略时，vArmor 允许用户通过策略的 `.spec.updateExistingWorkloads` 字段来决定是否对目标工作负载进行滚动更新。你可以通过此选项来关闭此特性。默认值：开启。

```bash
--set restartExistWorkloads.enabled=false
```

#### 开启 Pod 出口控制
此功能扩展了网络访问控制，以限制容器对特定 Pod IPs 的访问。您可以使用下面的选项关闭它。默认值：关闭。

```bash
--set podEgressControl.enabled=false
```

当前仅 BPF enforcer 支持此功能。开启此功能时，您可能需要为 manager 设置更多内存，以便其 watch pods 变化。不建议在大规模集群（如 10k+ 节点）中启用此功能。

#### 在宿主机网络命名空间中运行 Agent
vArmor 的 Agent 默认运行在独立的网络命名空间中，并在端口 `9580` 暴露就绪探针。如果您想将其部署在宿主网络命名空间中，那么可以使用下面的选项进行配置。

```bash
--set agent.network.hostNetwork=true \
--set agent.network.readinessPort=HOSTPORT
```

#### 开启 BPF enforcer 的独占模式
如果您的系统支持 AppArmor LSM，那么容器运行时会为没有显式配置 AppAmor 的工作负载应用其默认的 AppArmor profile。
您可以使用这个选项开启 BPF enforcer 的独占模式，即为那些启用 BPF enforcer 防护的工作负载禁用 AppArmor profile。

```bash
--set bpfExclusiveMode.enabled=true
```

#### 卸载所有 AppArmor 配置文件
当 Agent 退出或 vArmor 被卸载时，所有被 vArmor 管理的 AppArmor profile 都不会被自动卸载。
您可以使用下面的选项来改变此行为。默认值：关闭。

```bash
--set unloadAllAaProfiles.enabled=true
```

#### 移除所有 Seccomp 配置文件
当 Agent 退出或 vArmor 被卸载时，所有被 vArmor 管理的 Seccomp profile 都不会被自动移除。
您可以使用下面的选项来改变此行为。默认值：关闭。

```bash
--set removeAllSeccompProfiles.enabled=true
```

### 动态配置

除了上述安装时的 Helm 选项外，vArmor 还提供一份运行时可热加载的配置，承载于 vArmor 所在命名空间下的 `varmor-config` ConfigMap 中。Manager 通过 informer 监听该 ConfigMap，并在变更时**无需重启**即可热加载。如果该 ConfigMap 缺失或格式非法，Manager 会回退到内置默认值（与 Chart 随附的取值完全一致）。你可以在安装时通过 `dynamicConfig` value 设置其初始内容，也可以在安装后直接编辑该 ConfigMap。

```bash
kubectl -n varmor edit configmap varmor-config
```

#### NetworkProxy Sidecar 的默认资源
你可以为注入的 NetworkProxy(Envoy) sidecar 设置集群级的默认资源 requests/limits，这样管理员只需配置一次，而不必在每个策略上单独设置 `.spec.policy.networkProxyConfig.resources`。

注入器采用三层、字段级的合并链来解析最终资源，其中每个叶子字段(`requests.cpu`/`requests.memory`/`limits.cpu`/`limits.memory`)独立回退：

> 策略级覆盖(`.spec.policy.networkProxyConfig.resources`) > 本集群级全局配置 > 内置默认值

由于 MITM sidecar 负载更重(双向 TLS 握手)，配置分为两个相互独立且区分 MITM 的层级。MITM sidecar **只**读取 `mitm` 层，非 MITM sidecar **只**读取 `nonMitm` 层——两层之间**不会**相互继承。内置默认值如下：

| 层级 | CPU requests | 内存 requests | CPU limits | 内存 limits |
|------|-------------|----------------|-----------|--------------|
| `nonMitm` | 50m | 64Mi | 500m | 256Mi |
| `mitm` | 100m | 128Mi | 1000m | 512Mi |

```bash
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.cpu="50m" \
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.memory="64Mi" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.cpu="1000m" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.memory="512Mi"
```

注意事项：
* 资源数量务必以字符串形式加引号(如 `"500m"`、`"256Mi"`)。未加引号的裸数字会被解析为整数，因此 `memory: 100` 表示 **100 字节**，而非 100Mi。
* 层级键名必须严格拼写为 `nonMitm` 和 `mitm`。拼写错误的层级键会被静默忽略，该层级将回退到内置默认值。
* 非法条目(未知资源名、无法解析的数量、非正值，或同一层级内 limit 低于 request)会被忽略，并在 Manager 加载时记录日志；该字段将回退到其内置默认值。

#### NetworkProxy 审计的微虚机(Kata)识别
NetworkProxy enforcer 通过其 Envoy sidecar 持久化出口流量的违规审计日志。在 runc 运行时下，Envoy 通过节点级的 hostPath Unix socket 将记录流式发送到 `varmor-agent` DaemonSet。而在微虚机运行时(kata / Serverless 沙箱)下，sidecar 运行在微虚机内部，该 hostPath socket 无法跨越虚机边界(且部分 Serverless 厂商会在准入阶段拒绝挂载)。对于此类工作负载，vArmor 会省略 hostPath 卷/挂载，并启动一个 sidecar 内置的审计 sink，将 socket 绑定在容器自身 rootfs 中，写入容器本地的 `/var/log/varmor/violations.log`——产出与 runc 路径逐字节一致的归一化记录。

`microVMDetection` 配置用于告知注入器哪些工作负载运行在微虚机运行时下。当工作负载的 `runtimeClassName` 命中列表**或**任一 annotation 规则命中**或**任一 label 规则命中时，即判定为微虚机(对于 annotation/label 规则，空值表示仅按键是否存在匹配，非空值则必须精确匹配)。内置默认值已覆盖上游 kata 及主流云厂商的 Serverless 运行时：

* `runtimeClassNames`：`kata`、`kata-qemu`、`kata-clh`
* annotation：`vke.volcengine.com/burst-to-vci=enforce`(火山引擎 VKE burst-to-VCI)
* label：`alibabacloud.com/eci=true`(阿里云 ECI)

如需为自定义的微虚机运行时扩展识别规则，可编辑 `varmor-config` ConfigMap，或在安装时设置 `dynamicConfig.microVMDetection` 的取值。

#### NetworkProxy 流量重定向的 iptables 后端
NetworkProxy enforcer 通过 init 容器注入 iptables 规则来透明地重定向流量。从 `proxyinit:v0.2` 镜像开始，vArmor 会自动探测目标网络命名空间中已在使用的 iptables 后端(`legacy` 与 `nft`)并驱动匹配的后端，而不再硬编码某一种。这可以避免在共享 netns 的场景下流量被静默丢弃——例如某个 kata Pod 的 netns 同时被使用 `legacy` 后端的 PaaS mesh init 编程。在全新的 netns 上默认使用 `nft`(与既有行为一致);若两种后端都已存在规则，则会以 `CONFLICT` 中止而非盲目猜测。该能力完全自动、无需配置，只需确保 Chart 拉取 `proxyinit:v0.2` 或更新版本即可。


## 更新

你可以使用 helm 命令进行升级、回滚等操作。

```bash
helm upgrade varmor varmor-0.10.4.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-ap-southeast-1.cr.volces.com" \
    --set bpfLsmEnforcer.enabled=true \
    --set appArmorLsmEnforcer.enabled=false
```
```bash
helm rollback varmor -n varmor
```

## 卸载

可以使用以下命令卸载 vArmor。

```bash
helm uninstall varmor -n varmor
```

若使用了 AppArmor 和 Seccomp enforcer，请按照以下步骤卸载 vArmor
* 筛选出所有使用 AppArmor 或 Seccomp enforcer 的 VarmorPolicy/VarmorClusterPolicy（`.spec.policy.enforcer` 中包含 AppArmor 或 Seccomp）
* 逐个处理 VarmorPolicy/VarmorClusterPolicy 和对应的工作负载
  * 删除 VarmorPolicy/VarmorClusterPolicy 对象
  * 当防护目标的类型为 Deployment, StatusfulSet, DaemonSet 时
    * 若 `.spec.updateExistingWorkloads` 为 `true`，那么你无需其他额外工作
    * 若 `.spec.updateExistingWorkloads` 为 `false`，你需要手动删除被 vArmor 添加的 annotations、appArmorProfiles、seccompProfiles
  * 当防护目标的类型为 Pod 时，您需要重新创建 Pod（确保 Pod 中没有被 vArmor 添加的 annotations、appArmorProfiles、seccompProfiles）
* 通过 helm 卸载 vArmor
