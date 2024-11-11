# 性能说明

[English](performance_specification.md) | 简体中文

## 影响因素

vArmor 的用户态组件和内核态组件对性能的影响因素如下表所示

| 因素                   | 说明                                                                                                                   |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 集群规模                 | 集群规模越大，Manager 管理 Agent 所消耗的 CPU 和 内存越多                                                                              |
| VarmorPolicy 数量和操作频率 | 大量创建 VarmorPolicy CR 时，Manager 会消耗更多的 CPU 和内存进行响应<br />频繁创建/修改/删除 VarmorPolicy CR 时，Manager 和 Agent 会消耗更多的 CPU 和内存进行响应 |
| AppArmor LSM         | 开启 AppArmor LSM 为进程引入的基础开销<br />Profile 中的规则越多，对目标进程的性能影响越大                                                            |
| BPF LSM              | 开启 BPF LSM 为进程引入的基础开销<br />Profile 中的规则越多，对目标进程的性能影响越大                                                                 |

## 资源占用

vArmor 用户态组件默认使用下表所示的值进行资源申请

| Version | Manager CPU | Manager Memory | Agent CPU   | Agent Memory |
| ------- |:-----------:|:--------------:|:-----------:|:--------------------------------------------------------------------:|
| v0.5.11 | 200m / 100m | 300Mi / 200Mi  | 200m / 100m | 100Mi / 40Mi (关闭 BPF enforcer 时)<br />200Mi /100Mi (开启 BPF enforcer 时) |

说明：

* 默认值来自经验和模拟测试结果 (一个 VarmorPolicy 对 400*32 个Pods 开启防护)
* 您可以在安装组件时，通过调整 Helm Values 来为大规模集群设置更多的内存配额
* 若开启了 BPF enforcer，Agent 在启动并加载 BPF program 时需要更多的内存，因此内存资源的申请额度较高

## 性能测试

### 针对 BPF Enforcer 的基准测试

我们利用 [byte-unixbench](https://github.com/kdlucas/byte-unixbench) 在 VKE with kernel 5.10 集群中对 BPF enforcer (v0.5.0) 进行了初步的性能测试。

#### 测试环境

* 集群版本 v1.20.15-vke.10
* 节点数 2
* 节点主机默认启用 AppArmor & BPF LSM
* 节点规格 ecs.g2i.xlarge (4vCPU 16GiB)

#### 测试步骤

* 部署测试用的工作负载（通过 annotations 主动关闭测试容器的默认 AppArmor Profile）
* 在测试容器内连续执行 10 次基线测试
* 安装 vArmor
* 在测试容器内连续执行 10 次基线测试
* 为工作负载创建 VarmorPolicy（各类型策略各一条），在测试容器内连续执行 10 次基线测试
* 更新 VarmorPolicy（各类型策略各两条），在测试容器内连续执行 10 次基线测试
* 更新 VarmorPolicy（各类型策略各四条），在测试容器内连续执行 10 次基线测试
* 更新 VarmorPolicy（各类型策略各八条），在测试容器内连续执行 10 次基线测试
* 收集测试数据，对测试数据取均值，并以未安装 vArmor 时的测试结果为基准值，计算不同情况下的性能损失

#### 测试结果

* 安装 vArmor v0.5.0 后，若不对容器开启沙箱防护（或对容器开启 AlwaysAllow 模式沙箱）。将给容器进程引入最大 1.34% 的性能损失（Execl Throughput 维度）
* vArmor v0.5.0 在 Execl Throughput 和 Process Creation 中引入的性能损耗最大，当为容器进程设置各类型策略 8 条规则后，其 execl 的最大性能损耗为 2.55%，进程创建的最大性能损耗为 2.32%
* 不同测试用例的 File Copy 4096 bufsize 8000 maxblocks 得分与基准值相比有所波动，与预期不符。可能的原因是：
  * 当云主机在高负载时，cache 局部性/热度导致文件拷贝被加速等原因导致了波动
  * 云主机存在超售情况，宿主机在测试期间整体负载存在波动，从而导致云主机内的基线测试结果有所波动
  
  <img src="./img/bpf_enforcer_benchmark.png" width="600" />


### 模拟真实场景和常见负载的性能测试

本测试模拟真实场景，对不同的 enforcer 进行对比测试。我们使用 [Phoronix Test Suite (PTS)](https://github.com/phoronix-test-suite/phoronix-test-suite)，针对一些常见负载（Redis、Apache 等）进行了一系列自动化性能测试。

#### 测试环境

* 集群版本 v1.26.10-vke.18
* 节点数 3
* 节点主机默认启用 AppArmor & BPF LSM
* 节点规格 ecs.g3i.xlarge (4vCPU 16GiB)

#### 测试场景

在本轮测试中，我们对 AppArmor、BPF 这两种 enforcer 进行横向对比测试，每个 enforcer 都选取三种典型场景，包括 AlwaysAllow、RuntimeDefault、EnhanceProtect，每个场景的 policy 如下所示：

* Init 基准测试

  不应用任何策略

* AlwaysAllow

  使用 AlwaysAllow Mode 进行测试，不开启任何 rule

* RuntimeDefault

  使用 RuntimeDefault Mode 进行测试，不开启任何 rule

* EnhanceProtect

  使用 EnhanceProtect Mode 进行测试，开启如下 rules
  - disable-cap-privilege
  - disallow-umount
  - disallow-access-procfs-root
  - mitigate-disk-device-number-leak
  - mitigate-sa-leak
  - mitigate-overlayfs-leak
  - Mitigate-host-ip-leak
  - Disallow-metadata-service
  - cgroups-lxcfs-escape-mitigation
  - runc-override-mitigation

此外，我们也对 Seccomp enforcer 进行了测试，开启了 4 条 Seccomp 内置规则（该测试仅供参考）。
所有测试用到的 policy 文件均可在 [test/perf/policy](../test/perf/policy) 目录下找到。

#### 测试步骤

我们编写了一个 bash 脚本用于实现自动化测试，该脚本主要完成如下任务：

* 在 Kubernetes 集群中创建和删除 Pod。
* 应用和移除不同的安全策略。
* 初始化测试配置，安装测试工具，运行 Phoronix 测试套件。
* 记录测试结果。

特别地，对于 Init、 BPF 和 Seccomp 模式，我们使用了不同的 Pod 配置，例如通过设置 `container.apparmor.security.beta.kubernetes.io/phoronix: unconfined` 来确保禁用 AppArmor，避免运行时组件默认开启的 AppArmor Profile 影响测试结果。
您可以在 [test/perf/policy](../test/perf/policy) 目录下找到 Pod 定义和 Phoronix 运行配置。

您可以在 [test/perf](../test/perf) 目录下找到自动化测试脚本。此外我们针对 sysbench 和 unixbench 也编写了单独的测试脚本，如果您感兴趣也可以自行进行测试。

#### 测试结果

* **EnhanceProtect**: BPF 的性能相比 AppArmor 下降了约 1.2%。
* **RuntimeDefault**: BPF 的性能相比 AppArmor 下降了约 0.6%。
* **AlwaysAllow**: BPF 的性能相比 AppArmor 下降了约 0.1%。

  <img src="./img/pts_benchmark.png" width="600" />
测试结果表明，虽然 BPF 相对于 AppArmor 在不同场景下通常表现出轻微的性能下降，但差异相对较小。这表明 BPF 是 AppArmor 的可行替代方案，在安全应用中具有可接受的性能损耗。

下面是各项的详细测试结果：

##### Phoronix-Apache

Requests Per Second-Higher is better

| Test Scenario           | Apache Concurrent Requests 4 | Apache Concurrent Requests 20 | Apache Concurrent Requests 100 | Apache Concurrent Requests 200 | Apache Concurrent Requests 500 | Apache Concurrent Requests 1000 |
| ----------------------- | ---------------------------- | ----------------------------- | ------------------------------ | ------------------------------ | ------------------------------ | ------------------------------- |
| NoProtect               | 16838.6                      | 17073.8                       | 16961.78                       | 16619.65                       | 14029.19                       | 11944.99                        |
| AlwaysAllow AppArmor    | 16469.41                     | 16505.84                      | 16764.14                       | 16312.69                       | 13750.24                       | 11729.78                        |
| AlwaysAllow BPF         | 16452.94                     | 16489.33                      | 16747.38                       | 16296.38                       | 13736.49                       | 11718.05                        |
| RuntimeDefault AppArmor | 16376.54                     | 16067.09                      | 16461.39                       | 16242.69                       | 13385.87                       | 11599.9                         |
| RuntimeDefault BPF      | 16360.16                     | 16051.02                      | 16444.93                       | 16226.45                       | 13372.48                       | 11588.3                         |
| Enhance AppArmor        | 15833.43                     | 15802.84                      | 16385.19                       | 16101.51                       | 13276.16                       | 11429.32                        |
| Enhance BPF             | 15817.6                      | 15787.04                      | 16368.8                        | 16085.41                       | 13262.88                       | 11417.89                        |
| Seccomp                 | 14882.43                     | 15035.12                      | 15454.24                       | 15312.25                       | 12870.28                       | 11162.86                        |

##### Phoronix-GIMP

Time Usage-Lower is better

| Test Scenario           | GIMP Resize Times | GIMP RotateTimes | GIMP Auto-Levels Times | GIMP Unsharp-Mask Times |
| ----------------------- | ----------------- | ---------------- | ---------------------- | ----------------------- |
| NoProtect               | 16.616            | 11.842           | 16.543                 | 19.888                  |
| AlwaysAllow AppArmor    | 16.672            | 11.951           | 16.658                 | 20.04                   |
| AlwaysAllow BPF         | 16.872            | 12.094           | 16.858                 | 20.28                   |
| RuntimeDefault AppArmor | 16.737            | 11.977           | 16.734                 | 20.221                  |
| RuntimeDefault BPF      | 16.762            | 12.044           | 16.887                 | 20.289                  |
| Enhance AppArmor        | 16.855            | 11.958           | 16.814                 | 20.312                  |
| Enhance BPF             | 16.876            | 12.101           | 16.947                 | 20.411                  |
| Seccomp                 | 16.915            | 12.863           | 18.082                 | 21.096                  |

##### Phoronix-Redis

Requests Per Second-Higher is better

| Test Scenario           | GET Connection 50 | SETConnection 50 | GETConnection 500 | SET Connection 500 | LPOPConnection 500 |
| ----------------------- | ----------------- | ---------------- | ----------------- | ------------------ | ------------------ |
| NoProtect               | 2356517           | 1612305          | 1944514           | 1614023            | 2298349            |
| AlwaysAllow AppArmor    | 2336892           | 1610689          | 1936035           | 1605186            | 2287682            |
| AlwaysAllow BPF         | 2322870           | 1601025          | 1924418           | 1595555            | 2273956            |
| RuntimeDefault AppArmor | 2316004           | 1610480          | 1957586           | 1598156            | 2281477            |
| RuntimeDefault BPF      | 2302108           | 1600817          | 1945840           | 1588567            | 2267788            |
| Enhance AppArmor        | 2314458           | 1597515          | 1929528           | 1589630            | 2252763            |
| Enhance BPF             | 2300571           | 1587930          | 1917951           | 1580093            | 2239246            |
| Seccomp                 | 2280476           | 1596606          | 1875229           | 1547045            | 2316358            |

##### Phoronix-Sysbench

Higher is better

| Test Scenario           | SysbenchRam/Memory | SysbenchCPU |
| ----------------------- | ------------------ | ----------- |
| NoProtect               | 4189.51            | 2831.65     |
| AlwaysAllow AppArmor    | 4030.55            | 2821.5      |
| AlwaysAllow BPF         | 4026.519           | 2818.679    |
| RuntimeDefault AppArmor | 4023.67            | 2818.7      |
| RuntimeDefault BPF      | 4019.646           | 2815.881    |
| Enhance AppArmor        | 3939.25            | 2808.13     |
| Enhance BPF             | 3935.311           | 2805.322    |
| Seccomp                 | 4138.07            | 2832.87     |