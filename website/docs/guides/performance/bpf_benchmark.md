---
sidebar_position: 1
description: Measure the performance of the BPF enforcer.
---
# BPF Enforcer Benchmark

We conducted a basic performance test of BPF enforcer (v0.5.0) on a VKE cluster with kernel 5.10 using [byte-unixbench](https://github.com/kdlucas/byte-unixbench).

*Note: We plan to conduct further comparative testing for typical applications and scenarios in the future.*

#### Test Environment

* Kubernetes version: v1.20.15
* Node number: 2
* The node host has AppArmor and BPF LSM enabled by default.
* Node specification: ecs.g2i.xlarge (4 vCPUs, 16 GiB RAM)

#### Test Steps

* Deploy a test workload (disabling the default AppArmor profile for the test container via annotation).
* Perform 10 consecutive baseline tests within the test container.
* Install vArmor
* Perform 10 consecutive baseline tests within the test container
* Create a VarmorPolicy for the workload (1 rule for each access control type)， then perform 10 consecutive baseline tests within the test container.
* Update the VarmorPolicy (2 rules for each access control type), then perform 10 consecutive baseline tests within the test container.
* Update the VarmorPolicy (4 rules for each access control type), then perform 10 consecutive baseline tests within the test container.
* Update the VarmorPolicy (8 rules for each access control type), then perform 10 consecutive baseline tests within the test container.
* Collect test data, calculate the average of the test data, and then use the test results without vArmor installation as the baseline to measure performance losses under different scenarios.

#### Test Results

* After installing vArmor v0.5.0, if the container is not sandboxed (or if the container is sandboxed with the AlwaysAllow mode), it introduces a maximum performance loss of 1.34% to container process (in terms of Execl Throughput).
* vArmor v0.5.0 introduces the most significant performance overhead in terms of Execl Throughput and Process Creation. When 8 rules of various access control types are set for container process, the maximum performance loss for execl is 2.55%, and the maximum performance loss for process creation is 2.32%.
* The File Copy 4096 bufsize 8000 maxblocks scores for different test cases fluctuate compared to the baseline, which is unexpected. Possible reasons for this could be:
  * When the elastic cloud server is under high load, file copying may be accelerated due to factors like cache heat, leading to fluctuations.
  * The host may experience overselling, which can result in fluctuations in baseline test results within the elastic cloud server.
  
![image](../../img/bpf_enforcer_benchmark.png)