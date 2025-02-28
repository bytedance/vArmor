# 使用说明
[English](usage_instructions.md) | 简体中文

## 接口操作

vArmor 通过 [VarmorPolicy](#varmorpolicy) 和 [VarmorClusterPolicy](#varmorclusterpolicy) CR 提供 API 接口，它们分别是 namespace-scoped 和 cluster-scoped 类型的资源。VarmorClusterPolicy 的优先级高于 VarmorPolicy，即优先使用 VarmorClusterPolicy 对象对匹配的 Workloads 进行防护。你可通过创建、修改、删除 VarmorPolicy/VarmorClusterPolicy 对象来对指定的 Workloads 进行防护。

vArmor 支持在创建或删除 VarmorPolicy/VarmorClusterPolicy 对象时，对满足匹配条件的存量工作负载进行滚动重启，从而为其开启或关闭防护。

您还需要遵守以下限制和使用要求：
* 防护目标必须具有 **`sandbox.varmor.org/enable="true"`** 标签，从而在创建、更新时被 webhook server 处理。若其满足某个 VarmorPolicy/VarmorClusterPolicy 对象的 `spec.target` 匹配条件，vArmor 将会对其开启沙箱防护。
* 创建 VarmorPolicy/VarmorClusterPolicy 对象后，其 `spec.target` 不可更改。请通过新建策略来更改匹配目标。
* 创建 VarmorPolicy/VarmorClusterPolicy 对象后，可通过更新 `spec.policy` 来动态切换防护模式、更新防护规则。但不支持从 **BehaviorModeling 模式**切换为其他模式，反之亦然（注：切换防护模式、更新防护规则时，无需触发工作负载的滚动重启）。

## 状态管理

您可通过查看 VarmorPolicy/VarmorClusterPolicy 对象的 Status 获取处理阶段、错误信息、AppArmor/BPF Profile 的处理状态等。

您可通过查看 VarmorPolicy/VarmorClusterPolicy 对象的 Status 获取 `profileName` 字段。随后可查看相同命名空间下的同名 ArmorProfile 对象，从而获取 Agent 在处理 Profile 时的状态和错误信息。例如：哪个节点处理失败及其原因等。

## 日志管理

### 组件日志
Manager 和 Agent 组件会通过标准输出记录日志。默认为 TEXT 格式，您可以通过[安装选项](../getting_started/installation.md#设置日志格式为-json)将其切换为 JSON 格式。

### 审计日志
vArmor 支持将策略对象配置为仅告警不拦截（观察模式）、拦截并告警模式。您可以通过策略对象的 `auditViolations` 和 `allowViolations` 字段来实现此功能，常见用法请参考[此文档](../practices/index.md#常见用法)。所有违规事件都将以 JSON 格式记录到宿主机的 `/var/log/varmor/violations.log` 文件中（文件大小上限为 10MB，并最多保留 3 个旧文件）。

违规事件格式如下所示，其中被拦截并告警的行为将生成 `warn` 级别的事件，仅告警不拦截的行为将生成 `debug` 级别的事件。

* 当前仅 AppArmor 和 BPF enforcer 支持违规审计。
* 受限于 Seccomp 的原理和性能影响，您只能组合使用 `auditViolations=true` 和 `allowViolations=true`，在没有策略处于 BehaviorModeling 模式时，为 Seccomp enforcer 实现仅告警不拦截模式（观察模式）。
* 受限于 AppArmor LSM 的原理，使用 AppArmor enforcer 时，在某些情况下无法匹配出对应的容器和 Pod 信息。

```json
{
  "level": "warn",
  "nodeName": "192.168.0.24",
  "containerID": "fd808d9394a76680bd9f4de84413e6521cfc4e4c5097e0c6904b0f58e5f564cc",
  "containerName": "c1",
  "podName": "demo-2-57cd6498bb-472vk",
  "podNamespace": "demo",
  "podUID": "be8ea9dd-28c0-4401-b1e5-09fa06b14761",
  "pid": 887808,
  "mntNsID": 4026532637,
  "eventTimestamp": 1740381264,
  "eventType": "BPF",
  "event": {
    "permissions": [
      "read"
    ],
    "path": "/run/secrets/kubernetes.io/serviceaccount/..2025_02_24_06_32_23.1519281840/token"
  },
  "time": "2025-02-24T07:14:24Z",
  "message": "violation event"
}
```

```json
{
  "level": "warn",
  "nodeName": "192.168.0.8",
  "containerID": "5b24d520534b9ad2b618cd9f014a7cca045e5d217718852af6d12d587ef2b6c6",
  "containerName": "c1",
  "podName": "demo-1-5bccf6777c-c8lzr",
  "podNamespace": "demo",
  "podUID": "7efce0ca-5609-4cf5-aba4-eba24036cc6c",
  "pid": 3811300,
  "mntNsID": 4026532725,
  "eventTimestamp": 1740366282,
  "eventType": "AppArmor",
  "event": {
    "version": 1,
    "event": 4,
    "pid": 3811300,
    "peerPID": 0,
    "task": 0,
    "magicToken": 0,
    "epoch": 1740366282,
    "auditSubId": 674,
    "bitMask": 0,
    "auditID": "1740366282.121:674",
    "operation": "mknod",
    "deniedMask": "c",
    "requestedMask": "c",
    "fsuid": 0,
    "ouid": 0,
    "profile": "varmor-demo-demo-1//child_0",
    "peerProfile": "",
    "comm": "bash",
    "name": "/etc/5",
    "name2": "",
    "namespace": "",
    "attribute": "",
    "parent": 0,
    "info": "",
    "peerInfo": "",
    "errorCode": 0,
    "activeHat": "",
    "netFamily": "",
    "netProtocol": "",
    "netSockType": "",
    "netLocalAddr": "",
    "netLocalPort": 0,
    "netForeignAddr": "",
    "netForeignPort": 0,
    "dbusBus": "",
    "dbusPath": "",
    "dbusInterface": "",
    "dbusMember": "",
    "signal": "",
    "peer": "",
    "fsType": "",
    "flags": "",
    "srcName": ""
  },
  "time": "2025-02-24T03:04:42Z",
  "message": "violation event"
}
```

```json
{
  "level": "debug",
  "nodeName": "192.168.0.8",
  "containerID": "8c1058d1159d3ed20960c0c9f53fc26968a1c75cd3b390a503e060ffd8c972da",
  "containerName": "c0",
  "podName": "demo-5-5f689fcfc4-5gxll",
  "podNamespace": "demo",
  "podUID": "72ae1199-c061-4bc0-a00e-9dc8061caddf",
  "pid": 1448697,
  "mntNsID": 4026533364,
  "eventTimestamp": 1740621808,
  "eventType": "Seccomp",
  "event": {
    "auditID": "1740621808.346:683",
    "epoch": 1740621808,
    "subj": "varmor-demo-demo-5 (enforce)",
    "pid": 1448697,
    "comm": "unshare",
    "exe": "/usr/bin/unshare",
    "syscall": "unshare"
  },
  "time": "2025-02-27T02:03:28Z",
  "message": "violation event"
}
```

## 系统接口

### VarmorPolicy
* 命名空间类型资源，与防护对象的命名空间一致
* 接口描述详见 [Interface Specification](interface_specification.zh_CN.md)
* 定义详见 [VarmorPolicy CRD](../../config/crds/crd.varmor.org_varmorpolicies.yaml)
* VarmorPolicy/Status 说明

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
* 接口说明详见 [Interface Specification](interface_specification.zh_CN.md)
* 定义详见 [VarmorClusterPolicy CRD](../../config/crds/crd.varmor.org_varmorclusterpolicies.yaml)
* VarmorClusterPolicy/Status 与 VarmorPolicy/Status 一致

### ArmorProfile
* 命名空间范围资源，与防护对象或 vArmor 组件的命名空间一致
* 内部接口，仅由 vArmor 内部使用
* 定义详见 [ArmorProfile CRD](../../config/crds/crd.varmor.org_armorprofiles.yaml)
* ArmorProfile/Status 说明

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

这里有一些[案例](../../test/demos)演示了如何使用 vArmor 缓解漏洞、加固具有特权能力的容器。
