---
slug: varmor-0.8.0-new-features-overview
title: vArmor 0.8.0 New Features Overview
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes]
date: 2025-06-23T00:00
---

vArmor 0.8.0 further enhances network access control and observability, and refactors the DefenseInDepth mode to provide a more flexible whitelist security protection system for cloud-native environments. This article focuses on the core new features of vArmor 0.8.0 to help you quickly understand and apply them.

<!-- truncate -->

## Enhanced Network Access Control

Before vArmor 0.8.0, the BPF enforcer already supported egress traffic control based on IP/CIDR and ports, and included the built-in [`block-access-to-metadata-service`](https://www.varmor.org/docs/v0.8/guides/policies_and_rules/built_in_rules/attack_protection#block-access-to-metadata-service) rule to protect cloud host metadata services. However, the dynamic scaling characteristics of cloud-native microservices impose higher requirements for fine-grained access control.

vArmor v0.8.0 enhances network control flexibility with the following capabilities:


1. **Multiple Ports and Port Ranges Support**

    Supports configuring multiple ports or port ranges (e.g., `80-443`) in a single rule, simplifying rule management and reducing rule count.

2. **PodServiceEgressControl Feature**

    Enables access restriction based on Pod and Service dimensions:

    - Use the [`ingress-nightmare-mitigation`](https://www.varmor.org/docs/v0.8/guides/policies_and_rules/built_in_rules/vulnerability_mitigation#ingress-nightmare-mitigation) built-in rule to block containers from accessing the cluster's `ingress-nginx-controller-admission` service, mitigating CVE-2025-1974 vulnerabilities.
    - Use the [`block-access-to-kube-apiserver`](https://www.varmor.org/docs/v0.8/guides/policies_and_rules/built_in_rules/attack_protection#block-access-to-kube-apiserver) built-in rule to prohibit containers from accessing the cluster's `kubernetes` service (corresponding to the API Server).
    - Customize protection rules via [Pod](https://www.varmor.org/docs/v0.8/getting_started/interface_specification#pod) and [Service](https://www.varmor.org/docs/v0.8/getting_started/interface_specification#service) interfaces.

3. **New Special IP Entities**

    Use the following entities to control egress access to specific addresses, reducing rule complexity:

    - `pod-self`: Restricts access to the Cluster IP of the Pod where the container resides (including IPv4 and IPv6 addresses).
    - `unspecified`: Restricts access to `0.0.0.0` and `::`.
    - `localhost`: Restricts access to loopback addresses `127.0.0.1` and `::1`.

    These entities are useful when prohibiting containers from accessing services in sidecars.

Policy Example:

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

:::note[Note]
vArmor provides container-level egress traffic control (distinct from NetworkPolicy's Pod-level granularity). It complements security hardening and vulnerability mitigation but does not replace NetworkPolicy. We recommend combining it with NetworkPolicy to build a micro-segmentation system based on the principle of least privilege.

Currently, only the BPF enforcer supports fine-grained network control. In specific systems (e.g., Ubuntu), AppArmor 4.0 also supports fine-grained network access control. vArmor will adapt to AppArmor 4.0 in the future to expand capability boundaries.
:::

## Enhanced Audit Log Observability

vArmor's EnhanceProtect mode supports "alarm-only mode (observation mode)" and "alarm-interception mode", but historical logs lacked cluster and policy context. v0.8.0 adds the following capabilities to facilitate quick troubleshooting of violation events:

1. **Metadata Injection**

    Inject cluster metadata into audit logs via Helm parameters during component configuration:

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

2. **Automatic Policy Name Association**

    Parses policy names from Pod annotations and audit events into logs. Seccomp audit logs in some systems will also associate policy name.
    
    Log Examples:

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

## DefenseInDepth Mode Refactoring

As known, mandatory access control policies based on the "Deny-by-Default" security model significantly enhance security, but formulating secure and generalized whitelist profiles poses challenges. vArmor 0.8.0 refactors the [DefenseInDepth mode](https://www.varmor.org/docs/v0.8/guides/policies_and_rules/policy_modes/defense_in_depth) to support:

1. **Flexible policy source configuration**

    Choose between profiles generated by the BehaviorModeling mode or custom profiles as profile sources.

2. **Observation mode support**
    
    Continuously collect violations to optimize security profiles iteratively.

3. **Custom rule overlay**

    Support configuring custom rules in the [DefenseInDepth](https://www.varmor.org/docs/v0.8/getting_started/interface_specification#defenseindepth) interface, which merge with selected profiles to generate final whitelist profiles.

:::note[Plan]
In the future, vArmor will continue to explore the intelligent generation and optimization of whitelist profiles by integrating LLM technology, further reducing policy management costs and providing more options for security protection.
:::

## Summary

Try vArmor 0.8.0 today and share your feedback! For other updates, refer to the [release notes](https://github.com/bytedance/vArmor/releases/tag/v0.8.0).