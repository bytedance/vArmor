---
sidebar_position: 2
description: 了解如何使用 vArmor。
---
# 使用说明

## 接口操作

vArmor 通过 [VarmorPolicy](#varmorpolicy) 和 [VarmorClusterPolicy](#varmorclusterpolicy) CR 提供 API 接口，它们分别是 namespace-scoped 和 cluster-scoped 类型的资源。VarmorClusterPolicy 的优先级高于 VarmorPolicy，即优先使用 VarmorClusterPolicy 对象对匹配的 Workloads 进行防护。你可通过创建、修改、删除 VarmorPolicy/VarmorClusterPolicy 对象来对指定的 Workloads 进行防护。

vArmor 支持在创建或删除 VarmorPolicy/VarmorClusterPolicy 对象时，对满足匹配条件的存量工作负载进行滚动重启，从而为其开启或关闭防护。

您还需要遵守以下限制和使用要求：
* 防护目标必须具有 **`sandbox.varmor.org/enable="true"`** 标签，从而在创建、更新时被 webhook server 处理。若其满足某个 VarmorPolicy/VarmorClusterPolicy 对象的 `spec.target` 匹配条件，vArmor 将会对其开启沙箱防护。
* 创建 VarmorPolicy/VarmorClusterPolicy 对象后，其 `spec.target` 不可更改。请通过新建策略来更改匹配目标。
* 创建 VarmorPolicy/VarmorClusterPolicy 对象后，可通过更新 `spec.policy` 来动态新增 enforcer、切换防护模式、更新防护规则。但不支持动态移除 enforcer，以及不支持从 **BehaviorModeling 模式**切换为其他模式，反之亦然（注：切换防护模式、更新防护规则时，无需触发工作负载的滚动重启）。

## 状态管理

您可通过查看 VarmorPolicy/VarmorClusterPolicy 对象的 Status 获取处理阶段、错误信息、AppArmor/BPF Profile 的处理状态等。

您可通过查看 VarmorPolicy/VarmorClusterPolicy 对象的 Status 获取 `profileName` 字段。随后可查看相同命名空间下的同名 ArmorProfile 对象，从而获取 Agent 在处理 Profile 时的状态和错误信息。例如：哪个节点处理失败及其原因等。

## 日志管理

当前 vArmor 的 manager & agent 组件仅通过标准输出记录日志。

您可以借助日志组件采集并配置告警，例如：`\* | select count(*) as ErrCount where __content__ LIKE 'E%'`

## 系统接口

### VarmorPolicy
* 命名空间类型资源，与防护对象的命名空间一致
* 接口描述详见 [Interface Specification](interface_specification.md)
* 接口定义详见 [VarmorPolicy CRD](https://github.com/bytedance/vArmor/tree/main/config/crds/crd.varmor.org_varmorpolicies.yaml)
* `VarmorPolicy/Status` 说明

  |字段|值|含义|
  |---|--|---|
  |Phase|Pending|已经创建了 ArmorProfile，待 Agent 组件响应
  |     |Protecting|正在对目标工作负载的容器进行强制访问控制
  |     |Modeling|正在对目标应用行为建模
  |     |Completed|已完成目标应用的行为建模
  |     |Error|处理出错，请查看 Conditions 相关信息获取错误原因
  |Conditions|Type=Created<br />Status=True|VarmorPolicy 的创建事件已经被 controller 响应，且处理成功
  |          |Type=Created<br />Status=False<br />Reason=XXX<br />Message=YYY|VarmorPolicy 的创建事件已经被 controller 响应，但处理失败。包含失败的原因及错误信息
  |          |Type=Updated<br />Status=True|VarmorPolicy 的更新事件已经被 controller 响应，且处理成功
  |          |Type=Updated<br />Status=False<br />Reason=XXX<br />Message=YYY|VarmorPolicy 的更新事件已经被 controller 响应，但处理失败。包含失败的原因及错误信息
  |Ready|True|Profile 已经被所有的 Agents 处理和加载
  |     |False|Profile 还未被所有的 Agents 处理和加载


### VarmorClusterPolicy
* 集群范围资源
* 接口描述详见 [Interface Specification](interface_specification.md)
* 接口定义详见 [VarmorClusterPolicy CRD](https://github.com/bytedance/vArmor/tree/main/config/crds/crd.varmor.org_varmorclusterpolicies.yaml)
* `VarmorClusterPolicy/Status` 与 `VarmorPolicy/Status` 一致

### ArmorProfile
* 命名空间类型资源，与防护对象或 vArmor 组件的命名空间一致
* 内部接口，仅由 vArmor 内部使用
* 接口定义详见 [ArmorProfile CRD](https://github.com/bytedance/vArmor/tree/main/config/crds/crd.varmor.org_armorprofiles.yaml)
* `ArmorProfile/Status` 说明

    |字段|值|含义|
    |---|--|---|
    |DesiredNumberLoaded|int|期望处理并响应的 Agent 数量
    |CurrentNumberLoaded|int|已经处理并响应的 Agent 数量
    |Conditions|type=Read<br />Status=False<br />NodeName=XXX<br />Message=YYY|处理失败的节点，以及错误信息

## 示例

下面的示例仅用于演示功能和效果，不作为推荐策略。

```yaml
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

以上策略为 default 命名空间中（拥有 `sandbox.varmor.org/enable="true"` 和 `app=nginx` 标签，且 `environment` 标签的值为 `dev` 或 `qa` ）的 Deployment 开启增强沙箱防护（EnhanceProtect Mode），使用的沙箱规则如下所示：
- 禁用所有的特权能力（即直接导致容器逃逸的 capabilities）
- 禁用 cap_net_raw（即使用 AF_PACKET 协议族创建套接字，构造链路层数据包、进行网络嗅探等敏感行为的能力）
- 禁止写入 /etc 目录
- 禁止 shell 及其子进程访问容器的 ServiceAccount

## 案例

这里有一些[案例](https://github.com/bytedance/vArmor/tree/main/test/demos)演示了如何使用 vArmor 缓解漏洞、加固具有特权能力的容器。
