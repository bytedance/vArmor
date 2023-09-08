# Usage Instructions
[English](usage_instructions.md) | 简体中文

## 配置选项
vArmor 支持在安装时，通过 helm 命令对它的功能进行配置。

|功能|helm 参数|备注|
|---|--------|----|
| 关闭 AppArmor enforcer | --set appArmorLsmEnforcer.enabled=false | 默认开启；当系统不支持 AppArmor LSM 时可通过此参数关闭
| 开启 BPF enforcer | --set bpfLsmEnforcer.enabled=true | 默认关闭；当系统支持 BPF LSM 时可通过此参数开启
| 开启 BPF enforcer 独占模式 | --set bpfExclusiveMode.enabled=true | 默认关闭；开启后当 VarmorPolicy 使用 BPF enforcer 时，将禁用目标工作负载的 AppArmor 防护
| 允许对工作负载进行滚动重启 | --set restartExistWorkloads.enabled=true | 默认关闭；开启后，当创建或删除 VarmorPolicy 时，vArmor 会对符合条件的 Workloads (Deployments, DaemonSet, StatefulSet) 进行滚动重启，从而开启或关闭防护
| 退出时卸载所有 AppArmor Profile | --set unloadAllAaProfile.enabled=true | 默认关闭；开启后，Agent 退出时，将会卸载所有已加载的 AppArmor Profile
| 设置 Webhook MatchLabel | --set "manager.args={--webhookMatchLabel=KEY=VALUE}" | 默认值为：sandbox.varmor.org/enable=true。vArmor 只会对包含此 label 的 Workloads 开启沙箱防护。You can disable this feature by using `--set 'manager.args={--webhookMatchLabel=}'`
| 开启 DefenseInDepth 支持 [实验功能] | --set defenseInDepth.enabled=true | 默认关闭；此为实验功能，仅 AppArmor enforcer 支持 DefenseInDepth 模式


## 使用说明
### 接口操作
* vArmor 的 API 接口是 VarmorPolicy CR，它是命名空间类型的资源。用户可通过在集群中创建、修改、删除 VarmorPolicy 对象来对同一命名空间中的 Workloads 进行防护。
* 防护目标必须具有 `sandbox.varmor.org/enable="true"` 标签，从而在创建、更新时被 vArmor （的 webhook server）处理。若其满足某个 VarmorPolicy 对象的 `spec.target` 匹配条件，vArmor 将会对其开启沙箱防护。
* 创建或删除 VarmorPolicy 对象时，vArmor 支持对满足匹配条件的存量工作负载进行滚动重启，从而为其开启或关闭防护。
* 创建 VarmorPolicy 对象后，其 `spec.target` 不可更改。请通过新建 VarmorPolicy 来更改匹配目标。
* 创建 VarmorPolicy 对象后，可通过更新 `spec.policy` 来动态切换防护模式、更新防护规则。但不支持从 DefenseInDepth 模式切换为其他模式，反之亦然（注：切换防护模式、更新防护规则时，无需触发工作负载的滚动重启）。
### 状态管理
* 可通过查看 VarmorPolicy/Status 获取对象的处理阶段、错误信息、AppArmor/BPF Profile 的处理状态等。
* 可通过查看 VarmorPolicy/Status 获取 Profile Name。随后可查看相同命名空间下的同名 ArmorProfile 对象，从而获取 Agent 在处理 Profile 时的状态和错误信息。例如：哪个节点处理失败及其原因等。
### 日志管理
* 当前 vArmor 的 manager & agent 组件仅通过标准输出记录日志。
* 可以借助日志组件采集并配置告警，例如：`\* | select count(*) as ErrCount where __content__ LIKE 'E0%'`
### 卸载指南
若使用了 AppArmor enforcer，需按照以下步骤卸载 vArmor
* 筛选出所有使用 AppArmor enforcer 的 VarmorPolicy（`.spec.policy.enforcer` 为 AppArmor）
  ```
  kubectl get VarmorPolicy -A -o wide | grep AppArmor
  ```
* 逐个处理 VarmorPolicy 和对应的工作负载
  * 删除 VarmorPolicy 对象
  * 当防护目标的类型为 Deployment, StatusfulSet, DaemonSet 时
    * 若开启了 --restartExistWorkloads，那么你无需其他额外工作
    * 若未开启 --restartExistWorkloads，你需要手动删除对应工作负载中 key 为 container.apparmor.security.beta.kubernetes.io/[CONTAINER_NAME] 的 annotation
  * 当防护目标的类型为 Pod 时，需要重新创建 Pod（确保 Pod 的 annotations 中不存在名为 container.apparmor.security.beta.kubernetes.io/[CONTAINER_NAME] 的 key）
* 通过 helm 卸载 vArmor


## 系统接口
### VarmorPolicy
* 命名空间类型资源，与防护对象的命名空间一致
* 通过创建、更新、删除 VarmorPolicy 对象来使用 vArmor
* VarmorPolicy 接口描述详见 [Interface Instructions](interface_instructions.zh_CN.md)
* VarmorPolicy 定义详见 [VarmorPolicy CRD](../config/crds/crd.varmor.org_varmorpolicies.yaml)
* VarmorPolicy/Status 说明

  |字段|值|含义|
  |---|--|---|
  |Phase|Pending|已经创建了 ArmorProfile，待 Agent 组件响应
  |     |Protecting|正在对目标工作负载的容器进行强制访问控制
  |     |Modeling|正在为目标应用进行行为建模
  |     |Completed|已完成目标应用的行为建模
  |     |Error|处理出错，请查看 Conditions 相关信息获取错误原因
  |Conditions|Type=Created<br>Status=True|VarmorPolicy 的创建事件已经被 controller 响应，且处理成功
  |          |Type=Created<br>Status=False<br>Reason=XXX<br>Message=YYY|VarmorPolicy 的创建事件已经被 controller 响应，但处理失败。包含失败的原因及错误信息
  |          |Type=Updated<br>Status=True|VarmorPolicy 的更新事件已经被 controller 响应，且处理成功
  |          |Type=Updated<br>Status=False<br>Reason=XXX<br>Message=YYY|VarmorPolicy 的更新事件已经被 controller 响应，但处理失败。包含失败的原因及错误信息
  |Ready|True|Profile 已经被所有的 Agents 处理和加载
  |     |False|Profile 还未被所有的 Agents 处理和加载

### ArmorProfile
* 命名空间类型资源，与防护对象的命名空间一致
* 内部接口，仅由 vArmor 内部使用
* CRD 定义详见 [ArmorProfile CRD](../config/crds/crd.varmor.org_armorprofiles.yaml)
* ArmorProfile/Status 说明

    |字段|值|含义|
    |---|--|---|
    |DesiredNumberLoaded|int|期望处理并响应的 Agent 数量
    |CurrentNumberLoaded|int|已经处理并响应的 Agent 数量
    |Conditions|type=Read<br>Status=False<br>NodeName=XXX<br>Message=YYY|处理失败的节点，以及错误信息


## 示例 1
以下策略为 default 命名空间中（拥有 `sandbox.varmor.org/enable="true"` 和 `app=nginx` 标签，且 `environment` 标签的值为 `dev` 或 `qa` ）的 Deployment 开启增强沙箱防护（EnhanceProtect Mode），使用的沙箱规则如下所示：
- 禁用所有的特权能力（即直接导致容器逃逸的 capabilities）
- 禁用 cap_net_raw（即使用 AF_PACKET 协议族创建套接字，构造链路层数据包、进行网络嗅探等敏感行为的能力）
- 禁止写入 /etc 目录
- 禁止 shell 及其子进程访问容器的 ServiceAccount
```
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: deployment-policy
  namespace: default
spec:
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: nginx
      matchExpressions:
      - key: environment
        operator: In
        values: [dev, qa]
  policy:
    enforcer: AppArmor
    mode: EnhanceProtect
    enhanceProtect:
      hardeningRules:
      - disable_cap_privileged
      - disable_cap_net_raw
      attackProtectionRules:
      - rules: 
        - disable-write-etc
      - rules:
        - mitigate-sa-leak
        targets:
        - "/bin/sh"
        - "/usr/bin/sh"
        - "/bin/dash"
        - "/usr/bin/dash"
        - "/bin/bash"
        - "/usr/bin/bash"
        - "/bin/busybox"
        - "/usr/bin/busybox"
```


## 示例 2
以下策略为 test 命名空间中拥有 `sandbox.varmor.org/enable="true"` 和 `app=custom-controller-pod` 标签的 Pod 开启增强沙箱防护（EnhanceProtect Mode），对所有符合条件的 Pod 开启以下防护规则：
- 禁用所有的特权能力（禁用直接导致容器逃逸的 capabilities）
- 禁用 cap_net_raw（禁用 AF_PACKET 协议族创建套接字，从而构造链路层数据包、进行网络嗅探等敏感行为）
- 禁止写入 /etc 目录
- 禁止 shell 进程及其子进程访问容器的 ServiceAccount（限制应用服务被攻击者 RCE 反弹 shell 后的行为）
```
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: pod-policy
  namespace: test
spec:
  target:
    kind: Pod
    selector:
      matchLabels:
        app: custom-controller-pod
  policy:
    enforcer: AppArmor
    mode: EnhanceProtect
    enhanceProtect:
      hardeningRules:
      - disable_cap_privileged
      - disable_cap_net_raw
      attackProtectionRules:
      - rules: 
        - disable-write-etc
        - mitigate-host-ip-leak
      - rules:
        - mitigate-sa-leak
        targets:
        - "/bin/sh"
        - "/usr/bin/sh"
        - "/bin/dash"
        - "/usr/bin/dash"
        - "/bin/bash"
        - "/usr/bin/bash"
        - "/bin/busybox"
        - "/usr/bin/busybox"
```
