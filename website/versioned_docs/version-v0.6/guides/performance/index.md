---
slug: /guides/performance
sidebar_position: 2
---

# Performance

## Impact Factors

The factors affecting performance for vArmor's user-space and kernel-space components are as shown in the below

| Factor         | Explanation |
| -------------- | ----------- |
| Cluster scale  | As the cluster size increases, the CPU and memory consumed by the Manager for managing Agents also increase.|
| Resource scale | Creating a large number of VarmorPolicy CRs will result in increased CPU and memory consumption for Manager. Frequent creation/modification/deletion of VarmorPolicy CRs will result in increased CPU and memory consumption for both Manager and Agent in response.|
| AppArmor LSM   | The basic overhead introduced when the kernel enable the AppArmor LSM.<br />The more rules in a profile, the greater the performance impact on processes.|
| BPF LSM        | The basic overhead introduced when the kernel enable the BPF LSM.<br />The more rules in a profile, the greater the performance impact on processes.|
| Seccomp        | The basic overhead introduced when the kernel enable the Seccomp.<br />The more rules in a profile, the greater the performance impact on processes.|
|PLACEHOLDER||

## Resource Usage

vArmor user-space components use the resource quotas as shown in the table below by default.

| Version | Manager CPU | Manager Memory | Agent CPU   | Agent Memory |
| ------- |:-----------:|:--------------:|:-----------:|:-----------------------------------------------------------------------------------------:|
| v0.5.11 | 200m / 100m | 300Mi / 200Mi  | 200m / 100m | 100Mi / 40Mi (The BPF enforcer is disabled)<br />200Mi /100Mi (The BPF enforcer is enabled) |

Explanation:

* The default values are derived from experience and simulated test results (enabling protection for 400*32 Pods with one VarmorPolicy).
* You can set higher CPU and memory quotas for large-scale clusters by adjusting the values of helm chart during installation.
* When the BPF enforcer is enabled, the Agent requires more memory during startup

## Performance Test

import DocCardList from '@theme/DocCardList';

<DocCardList />