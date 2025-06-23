---
slug: varmor-0.8.0-new-features-overview
title: vArmor 0.8.0 新特性简介
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes]
date: 2025-06-23T00:00
---

vArmor 0.8.0 版本进一步强化了网络访问控制能力与可观测性，并重构了 DefenseInDepth 防御模式，为云原生环境提供更灵活的白名单安全防护体系。本文将聚焦 vArmor 0.8.0 的核心新特性，以便您快速理解与应用。

<!-- truncate -->

## 网络访问控制能力升级

在 vArmor 0.8.0 之前， BPF enforcer 已支持基于 IP/CIDR 及端口的出口流量控制，并内置 [`block-access-to-metadata-service`](https://www.varmor.org/zh-cn/docs/v0.8/guides/policies_and_rules/built_in_rules/attack_protection#block-access-to-metadata-service) 规则防护云主机元数据服务。但云原生微服务的动态扩缩容特性，对精细化访问控制提出了更高要求。

vArmor v0.8.0 通过以下能力增强网络控制灵活性：

1. **多端口与端口范围定义**
  
    支持在单条规则中配置多个端口或端口区间（如 `80-443`），简化规则管理和规则数。

2. **PodServiceEgressControl 特性**

    支持基于 Pod 和 Service 维度的访问限制。

    - 通过 [`ingress-nightmare-mitigation`](https://www.varmor.org/zh-cn/docs/v0.8/guides/policies_and_rules/built_in_rules/vulnerability_mitigation#ingress-nightmare-mitigation) 内置规则，禁止容器访问集群的 ingress-nginx-controller-admission 服务，防御 CVE-2025-1974 漏洞。
    - 通过 [`block-access-to-kube-apiserver`](https://www.varmor.org/zh-cn/docs/v0.8/guides/policies_and_rules/built_in_rules/attack_protection#block-access-to-kube-apiserver) 内置规则，禁止容器访问集群的 kubernetes 服务（对应 API Server）。
    - 通过 [Pod](https://www.varmor.org/docs/v0.8/getting_started/interface_specification#pod) 和 [Service](https://www.varmor.org/docs/v0.8/getting_started/interface_specification#service) 接口自定义防护规则。

3. **新增特殊 IP 实体**

    可以使用如下实体针对特定地址进行出口访问控制，从而减少规则的数量。
    - `pod-self`：限制访问容器所在 Pod 的 Cluster IP（包含 Pod 的 IPv4 和 IPv6 地址）
    - `unspecified`：限制访问 0.0.0.0 和 ::
    - `localhost`：限制访问 127.0.0.1 和 ::1

    当您需要禁止容器访问 sidecar 中的服务时可能会用到以上实体。

策略示例：

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      bpfRawRules:
        network:
          egress:
            toDestinations:
            - ip: fdbd:dc01:ff:307:9329:268d:3a27:2ca7
            - cidr: 192.168.1.1/24
              ports:
              - port: 80
                endPort: 8080
            - ip: pod-self
              ports:
              - port: 80
            toPods:
            - namespace: demo
              podSelector:
                matchLabels:
                  app: demo-3
              ports:
              - port: 8070
              - port: 8080
            toServices:
            - namespace: nginx
              serviceSelector:
                matchLabels:
                  app: nginx
```

:::note[注意]
vArmor 提供容器级出口流量控制（区别于 NetworkPolicy 的 Pod 粒度）。但它仅用作安全加固和漏洞利用缓解的补充，而非取代 NetworkPolicy。建议与 NetworkPolicy 结合使用，基于最小权限原则构建微隔离体系。

当前仅 BPF enforcer 支持细粒度网络控制。在特定系统中（如 Ubuntu），AppArmor 4.0 也支持细粒度网络访问控制。未来 vArmor 将适配 AppArmor 4.0 以扩展能力边界。
:::

## 审计日志可观测性增强

vArmor 的 EnhanceProtect 模式支持仅告警不拦截（观察模式）、拦截并告警模式，但历史日志缺乏集群、策略上下文信息。v0.8.0 新增以下能力，以便您快速定位和分析违规行为。

1. **元数据注入功能**

    您可以在配置组件时，通过以下 Helm 参数向审计日志注入集群元数据。

    ```bash
    --set auditEventMetadata.clusterID="ID" \ 
    --set auditEventMetadata.clusterName="NAME" \  
    --set auditEventMetadata.region="REGION"  
    ```

    Log Example:
    ```json
    {
      "level": "warn",
      // highlight-start
      "metadata": {
        "clusterID": "ID",
        "clusterName": "NAME",
        "region": "REGION"
      },
      // highlight-end
      "nodeName": "n37-031-068",
      "podUID": "a66574c7-bd0e-4ba6-b994-827dc87b95b6",
      "podName": "demo-2-679c54b6d7-56m6h",
      "podNamespace": "demo",
      "containerID": "298c85c63f4560d0f2842e617b17b9245fbeefdb16eb5b6c0159199cbc731e0c",
      "containerName": "c1",
      "pid": 2798766,
      "mntNsID": 4026533660,
      "eventTimestamp": 1749047303,
      "eventType": "BPF",
      "action": "DENIED",
      "profileName": "varmor-demo-demo-2",
      "event": {
        "permissions": [
          "read"
        ],
        "path": "/run/secrets/kubernetes.io/serviceaccount/..2025_06_04_14_06_33.422982164/token"
      },
      "time": "2025-06-04T22:28:24+08:00",
      "message": "violation event"
    }
    ```

2. **策略名自动关联**

    自动解析 Pod 注解、审计事件中的策略名并写入日志。部分系统中 Seccomp 审计日志也将关联策略名称。
    
    日志示例：

    ```json
    {
      "level": "debug",
      "nodeName": "192.168.0.8",
      "podUID": "72ae1199-c061-4bc0-a00e-9dc8061caddf",
      "podName": "demo-5-5f689fcfc4-5gxll",
      "podNamespace": "demo",
      "containerID": "8c1058d1159d3ed20960c0c9f53fc26968a1c75cd3b390a503e060ffd8c972da",
      "containerName": "c0",
      "pid": 1448697,
      "mntNsID": 4026533364,
      "eventTimestamp": 1740621808,
      "eventType": "Seccomp",
      "action": "ALLOWED",
      // highlight-start
      "profileName": "varmor-demo-demo-5",
      // highlight-end
      "event": {...},
      "time": "2025-02-27T02:03:28Z",
      "message": "violation event"
    }
    {
      "level": "warn",
      "nodeName": "192.168.0.24",
      "podUID": "be8ea9dd-28c0-4401-b1e5-09fa06b14761",
      "podName": "demo-2-57cd6498bb-472vk",
      "podNamespace": "demo",
      "containerID": "fd808d9394a76680bd9f4de84413e6521cfc4e4c5097e0c6904b0f58e5f564cc",
      "containerName": "c1",
      "pid": 887808,
      "mntNsID": 4026532637,
      "eventTimestamp": 1740381264,
      "eventType": "BPF",
      "action": "DENIED",
      // highlight-start
      "profileName": "varmor-demo-demo-2",
      // highlight-end
      "event": {...},
      "time": "2025-02-24T07:14:24Z",
      "message": "violation event"
    }
    {
      "level": "warn",
      "nodeName": "192.168.0.8",
      "podUID": "7efce0ca-5609-4cf5-aba4-eba24036cc6c",
      "podName": "demo-1-5bccf6777c-c8lzr",
      "podNamespace": "demo",
      "containerID": "5b24d520534b9ad2b618cd9f014a7cca045e5d217718852af6d12d587ef2b6c6",
      "containerName": "c1",
      "pid": 3811300,
      "mntNsID": 4026532725,
      "eventTimestamp": 1740366282,
      "eventType": "AppArmor",
      "action": "DENIED",
      // highlight-start
      "profileName": "varmor-demo-demo-1",
      // highlight-end
      "event": {...},
      "time": "2025-02-24T03:04:42Z",
      "message": "violation event"
    }
    ```

## DefenseInDepth 模式重构

众所周知，基于 “默认拒绝”（Deny-by-Default）安全模型的强制访问控制策略能显著提升安全性，但制定兼具安全性和泛化能力的白名单配置文件则面临众多挑战。为此，vArmor 0.8.0 重构了 [DefenseInDepth 模式](https://www.varmor.org/zh-cn/docs/v0.8/guides/policies_and_rules/policy_modes/defense_in_depth)以支持：

1. **灵活配置文件源配置**

    可选择 BehaviorModeling 模式生成的配置文件、自定义配置文件作为配置文件源

2. **观察模式支持**

    持续收集异常，不断优化配置文件。

3. **自定义规则叠加**

    支持在 [DefenseInDepth](https://www.varmor.org/zh-cn/docs/v0.8/getting_started/interface_specification#defenseindepth) 接口中配置自定义规则，与选择的配置文件合并生成最终白名单配置文件。

:::note[计划]
未来，vArmor 还会结合 LLM 技术持续探索白名单配置文件的智能生成与优化，进一步降低策略管理成本。为安全防护提供更多选择。
:::

## 小结

欢迎试用 vArmor 0.8.0，期待您的反馈与建议！其他更新请参考 [release notes](https://github.com/bytedance/vArmor/releases/tag/v0.8.0)。
