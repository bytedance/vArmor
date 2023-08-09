# Usage Instructions
[English](usage_instructions.md) | 简体中文

## 配置选项
vArmor 支持基于 AppArmor 和 BPF 两种 LSM 对 Kubernetes 中的工作负载进行沙箱加固。由于不同的系统环境所支持的 LSM 不同，因此 vArmor 支持在安装时，通过 helm 命令行参数对它的功能进行配置。目前支持以下功能的配置

|功能|helm 参数|备注|
|---|--------|----|
| 关闭 AppArmor enforcer | --set appArmorLsmEnforcer.enabled=false | 默认开启；当系统不支持 AppArmor LSM 时可通过此参数关闭
| 开启 BPF enforcer | --set bpfLsmEnforcer.enabled=true | 默认关闭；当系统支持 BPF LSM 时可通过此参数开启
| 允许 vArmor 对工作负载进行滚动重启 | --set restartExistWorkloads.enabled=true | 默认关闭；开启后，当创建或删除 VarmorPolicy 时，vArmor 会对符合条件的 Workloads (Deployments, DaemonSet, StatefulSet) 进行滚动重启，从而开启或关闭防护
| 退出时卸载所有 AppArmor Profile | --set unloadAllAaProfile.enabled=true | 默认关闭；开启后，Agent 退出时，将会卸载所有已加载的 AppArmor Profile
| 设置 webhook MatchLabel | --set "manager.args={--webhookMatchLabel=KEY=VALUE}" | 默认为 sandbox.varmor.org/enable=true，即只有当包含此 label 的 Workloads 被创建时，才会被 vArmor 判断是否需要开启沙箱防护（注：只允许设置一个 label）
| 开启深度防护功能 [实验功能] | --set defenseInDepth.enabled=true | 默认关闭；当需要对工作负载进行动态建模，生成 VarmorPolicy 时开启。当前只支持 AppArmor enforcer


## 使用说明
### 接口操作
* 使用 vArmor 的唯一接口是 VarmorPolicy CR，它是命名空间类型的资源。用户可通过在集群中创建、修改、删除 VarmorPolicy 对象来对同一命名空间中的 Workloads 进行防护。
* 防护目标必须具有 **sandbox.varmor.org/enable="true"** 标签，从而在创建、更新时被 vArmor 识别并处理。用户创建、更新工作负载时，若工作负载满足任意 VarmorPolicy 对象的 spec.target 条件，则会对其开启防护。
* 创建或删除 VarmorPolicy 对象时，若当前集群中存在满足条件的工作负载，vArmor 可以对目标工作负载进行滚动重启，从而为其开启或关闭防护。
* 创建 VarmorPolicy 对象后，其 spec.target 不可更改，若要修改防护目标请删除并创建新的 VarmorPolicy。
* 创建 VarmorPolicy 对象后，可通过更新 spec.policy 来动态切换防护模式、修改防护策略。但不支持从 DefenseInDepth 模式切换为其他模式，反之亦然（注：切换防护模式、修改防护策略时，无需触发工作负载的滚动重启）。
### 状态管理
* 可通过查看 VarmorPolicy/Status 获取对象的处理阶段、错误信息、AppArmor/BPF Profile 的处理状态等。
* 可通过查看 VarmorPolicy/Status 获取 Profile Name。随后可查看同一命名空间下的同名 ArmorProfile 对象，从而获取 vArmor Agent 在处理 ArmorProfile 时的状态和错误信息。例如：哪个节点处理失败及其原因等。
### 日志管理
* 当前 manager & agent 组件仅通过标准输出打印运行日志
* 可以借助云服务的日志组件采集并配置告警，例如：`\* | select count(*) as ErrCount where __content__ LIKE 'E0%'`
### 卸载指南
若使用了 AppArmor enforcer，需按照以下步骤卸载 vArmor
* 筛选出所有使用 AppArmor enforcer 的 VarmorPolicy（.spec.enforcer 为 AppArmor）
  ```
  kubectl get VarmorPolicy -A -o wide | grep AppArmor
  ```
* 逐个处理 VarmorPolicy 和对应的工作负载
  * 删除 VarmorPolicy 对象
  * 当防护目标的类型为 Deployment, StatusfulSet, DaemonSet 时
    * 若开启了 --restartExistWorkloads，那么你无需其他额外工作
    * 若未开启 --restartExistWorkloads，你需要手动删除对应工作负载中 key 为 container.apparmor.security.beta.kubernetes.io/[CONTAINER_NAME] 的 annotation，并触发滚动更新。
  * 当防护目标的类型为 Pod 时，需要重新创建 Pod（确保 Pod 的 annotations 中不存在名为 container.apparmor.security.beta.kubernetes.io/[CONTAINER_NAME] 的 key）
* 通过 helm 卸载 vArmor


## 系统接口
### VarmorPolicy
* 命名空间类型资源
* High Level CR
  * 与保护对象的命名空间一致
  * 用户可创建、更新、删除，从而实现对防护的配置
  * 控制面可以在前端提供更加易用的界面、API 接口
* CRD 定义详见 [VarmorPolicy CRD](../config/crds/crd.varmor.org_varmorpolicies.yaml)
  * VarmorPolicySpec 说明

    |字段|子字段|子字段|类型|值|描述|
    |---|-----|-------|---|--|---|
    |Target|Kind|-|string（必选）|Deployment<br>StatefulSet<br>DaemonSet<br>Pod|用于指定防护目标的 Workloads 类型
    |      |Name|-|string（可选）|任意值|用于指定防护目标的对象名称
    |      |Containers|-|[]string（可选）|任意值|用于指定防护目标的容器名，如果为空默认对 Workloads 中的所有容器开启沙箱防护（注：不含 initContainers, ephemeralContainers）
    |      |Selector|-|LabelSelector（可选）|任意值|用于根据标签选择器识别防护目标，并开启沙箱防护
    |Policy|Enforcer|-|string（必选）|AppArmor<br>BPF|指定要使用的 LSM
    |      |Mode|-|string（必选）|AlwaysAllow<br>RuntimeDefault<br>EnhanceProtect<br>CustomPolicy<br>DefenseInDepth|指定防护模式，不同模式的含义详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
    |      |EnhanceProtect|HardeningRules|[]string（可选）||可使用的内置规则列表详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
    |      ||AttackProtectionRules|[]AttackProtectionRules（可选）||可使用的内置规则列表详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
    |      ||VulMitigationRules|[]string（可选）||可使用的内置规则列表详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
    |      ||AppArmorRawRules|[]string（可选）||支持用户设置原始的 AppArmor rules
    |      ||BpfRawRules|BpfRawRules（可选）||支持用户设置原始的 BPF rules
    |      |DefenseInDepth|ModelingDuration|int（必选）|任意值|动态建模的时间（单位：分钟）
    |      ||AutoEnable|bool（可选）|true<br>false|建模完成后是否自动开启防护（默认值：false）
    |      |Privileged||bool（可选）|true<br>false|若要使用 AppArmor enforcer 对特权容器进行防护，请务必将此值设置为 true（默认值：false）

  * AttackProtectionRules 说明

    |字段|类型|值|描述|
    |---|---|--|----|
    |Rules|[]string（必选）||可使用的内置规则列表详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
    |Targets|[]string（必选）|任意可执行文件的全路径|对目标可执行文件开启 Rules 中指定的沙箱规则，仅支持 AppArmor enforcer

  * BpfRawRules 说明

    |字段|子字段|子字段|类型|值|描述|
    |---|-----|-----|---|--|---|
    |Files|FileRule|Pattern|string（必选）|任意符合策略语法的字符串（最大长度 64 bytes）|用于匹配文件路径、文件名称。语法参见
    |     |        |Permissions|[]string（必选）|read 或 r<br>write 或 w<br>exec 或 e|禁止使用的权限，write 权限隐式包含 link, rename 等权限
    |Processes|FileRule|-|-|-|-
    |Network|Egresses|-|[]NetworkEgressRule（可选）|-|对外联请求进行访问控制（仅支持 connect 行为，不支持已建立链接的 socket）

  * NetworkEgressRule
  
    |字段|类型|值|描述|
    |---|---|--|----|
    |IPBlock|string（可选）|任意标准的 CIDR，支持 IPv6|用于对指定 CIDR 范围内的 IP 地址进行外联限制，例如<br>* 192.168.1.1/24 代表 192.168.1.0 ~ 192.168.1.255 范围内的 IP 地址<br>* 2001:db8::/32 代表 2001:db8:: ~ 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 范围内的 IP 地址<br>（注：同一个 NetworkEgressRule 中，IPBlock 和 IP 字段互斥，不能同时出现）
    |IP|string（可选）|任意标准的 IP 地址，支持 IPv6|用于对特定的 IP 地址进行外联限制
    |Port|int（可选）|1~65535|用于对指定的端口进行外联限制，当为空时，默认对（匹配 IP 地址的）所有端口进行外联限制。否则仅对特定端口进行控制

  * VarmorPolicyStatus

    |字段|值|含义|
    |---|--|---|
    |Phase|Pending|已经创建了 ArmorProfile，待 Agent 组件响应
    |     |Protecting|防护中，正在进行强制访问控制
    |     |Modeling|正在为目标应用进行行为建模
    |     |Completed|已完成应用服务的行为建模
    |     |Error|处理出错，请查看 Conditions 相关信息获取错误原因
    |Conditions|Type=Created<br>Status=True|VarmorPolicy 的创建事件已经被 controller 响应，且处理成功
    |          |Type=Created<br>Status=False<br>Reason=XXX<br>Message=YYY|VarmorPolicy 的创建事件已经被 controller 响应，但处理失败。包含失败的原因及错误信息
    |          |Type=Updated<br>Status=True|VarmorPolicy 的更新事件已经被 controller 响应，且处理成功
    |          |Type=Updated<br>Status=False<br>Reason=XXX<br>Message=YYY|VarmorPolicy 的更新事件已经被 controller 响应，但处理失败。包含失败的原因及错误信息
    |Ready|True|Profile 已经被所有的 Agents 处理和加载
    |     |False|Profile 还未被所有的 Agents 处理和加载

### ArmorProfile
* 命名空间类型资源
* Low Level CR
  * 与保护对象的命名空间一致
  * 向用户屏蔽底层逻辑，仅由 vArmor 内部使用
* CRD 定义详见 [ArmorProfile CRD](../config/crds/crd.varmor.org_armorprofiles.yaml)
  * ArmorProfileStatus 说明

    |字段|值|含义|
    |---|--|---|
    |DesiredNumberLoaded|任意数值|期望处理并响应的 Agent 数量
    |CurrentNumberLoaded|任意数值|已经处理并响应的 Agent 数量
    |Conditions|type=Read<br>Status=False<br>NodeName=XXX<br>Message=YYY|处理失败的 Agent 所在节点，以及错误信息


## 示例 1
以下策略为 default 命名空间中“拥有 sandbox.varmor.org/enable="true" 和 app=nginx 标签，且 environment 标签的值为 dev 或 qa”的 Deployment 开启增强沙箱防护（EnhanceProtect Mode），对所有符合条件的 Deployment 开启以下防护规则：
- 禁用所有的特权能力（即直接导致容器逃逸的 capabilities）
- 禁用 cap_net_raw（即使用 AF_PACKET 协议族创建套接字，构造链路层数据包、进行网络嗅探等敏感行为的能力）
- 禁止写入 /etc 目录
- 禁止 shell 及其子进程访问容器的 ServiceAccount（限制应用服务被攻击者 RCE 反弹 shell 后的行为）
```
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: default
  namespace: demo
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
以下策略为 default 命名空间中拥有 sandbox.varmor.org/enable="true" 和 app=custom-controller-pod 标签的 Pod 开启增强沙箱防护（EnhanceProtect Mode），对所有符合条件的 Pod 开启以下防护规则：
- 禁用所有的特权能力（即直接导致容器逃逸的 capabilities）
- 禁用 cap_net_raw（即使用 AF_PACKET 协议族创建套接字，构造链路层数据包、进行网络嗅探等敏感行为的能力）
- 禁止写入 /etc 目录
- 禁止 shell 进程及其子进程访问容器的 ServiceAccount（限制应用服务被攻击者 RCE 反弹 shell 后的行为）
```
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: 4-test
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
