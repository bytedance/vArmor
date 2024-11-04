# 安装指引
[English](installation.md) | 简体中文

## 前置条件

不同 enforcers 所需要的前置条件如下表所示。

|强制访问控制器|要求|推荐|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15 及以上版本<br>2. 系统需开启 AppArmor LSM|GKE with Container-Optimized OS<br>AKS with Ubuntu 22.04 LTS<br>[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0<br>Debian 10 及以上版本<br>Ubuntu 18.04.0 LTS 及以上版本<br>[veLinux 1.0](https://www.volcengine.com/docs/6396/74967) 等
|BPF         |1. Linux Kernel 5.10 及以上版本 (x86_64)<br>2. containerd v1.6.0 及以上版本<br>3. 系统需开启 BPF LSM|EKS with Amazon Linux 2<br>GKE with Container-Optimized OS<br>[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0 (with 5.10 kernel)<br>AKS with Ubuntu 22.04 LTS <sup>\*</sup><br>ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br>OpenSUSE 15.4  <sup>\*</sup><br>Debian 11 <sup>\*</sup><br>Fedora 37<br>[veLinux 1.0 with 5.10 kernel](https://www.volcengine.com/docs/6396/74967) 等<br><br>* *需手动启用节点的 BPF LSM*
|Seccomp     |1. Kubernetes v1.19 及以上版本|所有 Linux 发行版

## 安装

vArmor 推荐使用 Helm chart 进行部署。通过 Helm 安装前，请先拉取 chart 包。

```
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.5.11
```

然后使用 helm 命令及[配置选项](installation.zh_CN.md#配置选项)进行安装和配置。

```
helm install varmor varmor-0.5.11.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-cn-beijing.cr.volces.com"
```

*您可以在非中国地区使用 elkeid-ap-southeast-1.cr.volces.com 域名*

## 配置选项

|helm 参数|描述|
|--------|----|
| `--set appArmorLsmEnforcer.enabled=false` | 默认开启；当系统不支持 AppArmor LSM 时可通过此参数关闭。
| `--set bpfLsmEnforcer.enabled=true` | 默认关闭；当系统支持 BPF LSM 时可通过此参数开启。
| `--set bpfExclusiveMode.enabled=true` | 默认关闭；开启后当 VarmorPolicy 使用 BPF enforcer 时，将禁用目标工作负载的 AppArmor 防护。
| `--set restartExistWorkloads.enabled=false` | 默认开启；关闭后，将禁止用户通过 VarmorPolicy/VarmorClusterPolicy 中的 `.spec.updateExistingWorkloads` 字段来控制是否对符合条件的 Workloads (Deployments, DaemonSet, StatefulSet) 进行滚动更新，从而在策略创建或删除时，对目标开启或关闭防护。
| `--set unloadAllAaProfiles.enabled=true` | 默认关闭；开启后，Agent 退出时，将会卸载所有由 vArmor 加载的 AppArmor Profile。
| `--set removeAllSeccompProfiles.enabled=true` | 默认关闭；开启后，Agent 退出时，将会删除所有由 vArmor 创建的 Seccomp Profile。
| `--set "manager.args={--webhookMatchLabel=KEY=VALUE}"` | 默认值为：`sandbox.varmor.org/enable=true`。vArmor 只会对包含此 label 的 Workloads 开启沙箱防护。你可以使用 `--set 'manager.args={--webhookMatchLabel=}'` 关闭此特性。
| `--set behaviorModeling.enabled=true` | 默认关闭；此为实验功能，仅 AppArmor/Seccomp enforcer 支持 BehaviorModeling 模式。请参见 [The BehaviorModeling Mode](behavior_modeling.md)。

## 更新

你可以使用 helm 命令进行升级、回滚等操作。
```
helm upgrade varmor varmor-0.5.11.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-ap-southeast-1.cr.volces.com" \
    --set bpfLsmEnforcer.enabled=true \
    --set appArmorLsmEnforcer.enabled=false
```
```
helm rollback varmor -n varmor
```

## 卸载

可以使用以下命令卸载 vArmor。

```
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
