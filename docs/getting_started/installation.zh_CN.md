# 安装指引
[English](installation.md) | 简体中文

## 前置条件

不同 Enforcer 所需要的前置条件如下表所示。

|强制访问控制器|要求|推荐|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15 及以上版本<br />2. 系统需开启 AppArmor LSM|GKE with Container-Optimized OS<br />AKS with Ubuntu 22.04 LTS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0<br />Debian 10 及以上版本<br />Ubuntu 18.04.0 LTS 及以上版本<br />[veLinux 1.0](https://www.volcengine.com/docs/6396/74967) 等
|BPF         |1. Linux Kernel 5.10 及以上版本 (x86_64)<br />2. containerd v1.6.0 及以上版本<br />3. 系统需开启 BPF LSM|EKS with Amazon Linux 2<br />GKE with Container-Optimized OS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0 (with 5.10 kernel)<br />AKS with Ubuntu 22.04 LTS <sup>\*</sup><br />ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br />OpenSUSE 15.4  <sup>\*</sup><br />Debian 11 <sup>\*</sup><br />Fedora 37<br />[veLinux 1.0 with 5.10 kernel](https://www.volcengine.com/docs/6396/74967) 等<br /><br />* *需手动启用节点的 BPF LSM*
|Seccomp     |1. Kubernetes v1.19 及以上版本|所有 Linux 发行版

## 安装

vArmor 推荐使用 Helm chart 进行部署。通过 Helm 安装前，请先拉取 chart 包。

```
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.7.1
```

然后使用 helm 命令及[配置选项](#配置选项)进行安装和配置。

```
helm install varmor varmor-0.7.1.tgz \
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

#### 开启 Pod 和 Service 出口控制
此功能扩展了网络访问控制，以限制容器对特定 Pod 和 Service 的访问。默认值：关闭。

```bash
--set podServiceEgressControl.enabled=true
```

当前仅 BPF enforcer 支持此功能，并且需要 Kubernetes v1.21 及以上版本。

#### 开启 BehaviorModeling 模式
这是一个实验性质的功能。当前只有 AppArmor 和 Seccomp enforcer 支持 BehaviorModeling 模式。请参考  [BehaviorModeling Mode](../guides/policies_and_rules/policy_modes/behavior_modeling.zh_CN.md) 了解更多细节。默认值：关闭。

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

您可以使用下面的选项在 vArmor 所在命名空间中创建 `ServiceMonitor` 对象，用于与 Prometheus 集成。默认值：关闭。

```bash
--set metrics.serviceMonitorEnabled=true
```

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

#### 在宿主机网络命名空间中运行 Agent
vArmor 的 Agent 默认运行在独立的网络命名空间中，并在端口 `6080` 暴露就绪探针。如果您想将其部署在宿主网络命名空间中，那么可以使用下面的选项进行配置。

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

## 更新

你可以使用 helm 命令进行升级、回滚等操作。
```bash
helm upgrade varmor varmor-0.7.1.tgz \
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
