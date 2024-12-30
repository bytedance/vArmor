# 性能说明

[English](README.md) | 简体中文

## 影响因素

vArmor 的用户态组件和内核态组件对性能的影响因素如下表所示。

| 因素 | 说明 |
| --- | ---- |
| 集群规模                   | 集群规模越大，Manager 管理 Agent 所消耗的 CPU 和 内存越多 |
| VarmorPolicy 数量和操作频率 | 大量创建 VarmorPolicy CR 时，Manager 会消耗更多的 CPU 和内存进行响应<br />频繁创建/修改/删除 VarmorPolicy CR 时，Manager 和 Agent 会消耗更多的 CPU 和内存进行响应 |
| AppArmor LSM             | 开启 AppArmor LSM 为进程引入的基础开销<br />Profile 中的规则越多，对目标进程的性能影响越大|
| BPF LSM                  | 开启 BPF LSM 为进程引入的基础开销<br />Profile 中的规则越多，对目标进程的性能影响越大 |
| Seccomp                  | 开启 Seccomp 为进程引入的基础开销<br />Profile 中的规则越多，对目标进程的性能影响越大 |

## 资源占用

vArmor 用户态组件默认使用下表所示的值进行资源申请

| Version | Manager CPU | Manager Memory | Agent CPU   | Agent Memory |
| ------- |:-----------:|:--------------:|:-----------:|:--------------------------------------------------------------------:|
| v0.6.2 | 200m / 100m | 300Mi / 200Mi  | 200m / 100m | 100Mi / 40Mi (关闭 BPF enforcer 时)<br />200Mi /100Mi (开启 BPF enforcer 时) |

说明：

* 默认值来自经验和模拟测试结果 (一个 VarmorPolicy 对 400*32 个Pods 开启防护)
* 您可以在安装组件时，通过调整 Helm Values 来为大规模集群设置更多的内存配额
* 若开启了 BPF enforcer，Agent 在启动并加载 BPF program 时需要更多的内存，因此内存资源的申请额度较高

## 性能测试

* [BPF Enforcer 基线测试](bpf_benchmark.zh_CN.md)
* [对比测试](comparison_testing.zh_CN.md)
