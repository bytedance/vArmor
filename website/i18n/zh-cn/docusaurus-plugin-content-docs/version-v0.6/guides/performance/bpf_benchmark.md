---
sidebar_position: 1
description: 评估 BPF Enforcer 的性能。
---

# BPF Enforcer 基准测试

我们利用 [byte-unixbench](https://github.com/kdlucas/byte-unixbench) 在 VKE with kernel 5.10 集群中对 BPF enforcer (v0.5.0) 进行了初步的性能测试。

## 测试环境

* 集群版本 v1.20.15-vke.10
* 节点数 2
* 节点主机默认启用 AppArmor & BPF LSM
* 节点规格 ecs.g2i.xlarge (4vCPU 16GiB)

## 测试步骤

* 部署测试用的工作负载（通过 annotations 主动关闭测试容器的默认 AppArmor Profile）。
* 在测试容器内连续执行 10 次基线测试。
* 安装 vArmor。
* 在测试容器内连续执行 10 次基线测试。
* 为工作负载创建 VarmorPolicy（各类型策略各一条），在测试容器内连续执行 10 次基线测试。
* 更新 VarmorPolicy（各类型策略各两条），在测试容器内连续执行 10 次基线测试。
* 更新 VarmorPolicy（各类型策略各四条），在测试容器内连续执行 10 次基线测试。
* 更新 VarmorPolicy（各类型策略各八条），在测试容器内连续执行 10 次基线测试。
* 收集测试数据，对测试数据取均值，并以未安装 vArmor 时的测试结果为基准值，计算不同情况下的性能损失。

## 测试结果

* 安装 vArmor v0.5.0 后，若不对容器开启沙箱防护（或对容器开启 AlwaysAllow 模式沙箱）。将给容器进程引入最大 1.34% 的性能损失（Execl Throughput 维度）。
* vArmor v0.5.0 在 Execl Throughput 和 Process Creation 中引入的性能损耗最大，当为容器进程设置各类型策略 8 条规则后，其 execl 的最大性能损耗为 2.55%，进程创建的最大性能损耗为 2.32%。
* 不同测试用例的 File Copy 4096 bufsize 8000 maxblocks 得分与基准值相比有所波动，与预期不符。可能的原因是：
  * 当云主机在高负载时，cache 局部性/热度导致文件拷贝被加速等原因导致了波动。
  * 云主机存在超售情况，宿主机在测试期间整体负载存在波动，从而导致云主机内的基线测试结果有所波动。
  
![image](../../img/bpf_enforcer_benchmark.png)
