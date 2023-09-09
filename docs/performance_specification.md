# The Performance Specification
English | [简体中文](performance_specification.zh_CN.md)

## Impact Factors
The factors affecting performance for vArmor's user-space and kernel-space components are as shown in the below

| Factor | Explanation |
|--------|-------------|
|Cluster scale|As the cluster size increases, the CPU and memory consumed by the Manager for managing Agents also increase.
|Resource scale|Creating a large number of VarmorPolicy CRs will result in increased CPU and memory consumption for Manager.<br>Frequent creation/modification/deletion of VarmorPolicy CRs will result in increased CPU and memory consumption for both Manager and Agent in response.
|AppArmor LSM|The basic overhead introduced when the kernel enable the AppArmor LSM.<br>The more rules in a profile, the greater the performance impact on processes.
|BPF LSM|The basic overhead introduced when the kernel enable the BPF LSM.<br>The more rules in a profile, the greater the performance impact on processes.


## Resource Usage
vArmor user-space components use the resource quotas as shown in the table below by default.

|Version| Manager CPU | Manager Memory |  Agent CPU  | Agent Memory |
|-------|:-----------:|:--------------:|:-----------:|:------------:|
|v0.5.1 | 200m / 100m | 300Mi / 200Mi  | 200m / 100m | 100Mi / 40Mi (The BPF enforcer is disabled)<br>200Mi /100Mi (The BPF enforcer is enabled)

Explanation:
* The default values are derived from experience and simulated test results (enabling protection for 400*32 Pods with one VarmorPolicy).
* You can set higher CPU and memory quotas for large-scale clusters by adjusting the values of helm chart during installation.
* When the BPF enforcer is enabled, the Agent requires more memory during startup
  
## Performance
### AppArmor Enforcer
No comparative testing has been conducted in a container environment; you can refer to the performance tests on the Linux AppArmor LSM conducted by the community in 2019. ([Linux 5.5 Git Threadripper + No Apparmor](https://openbenchmarking.org/result/1912315-PTS-LINUX55G46))

### BPF Enforcer
We conducted a basic performance test of BPF enforcer (v0.5.0) on a VKE cluster with kernel 5.10 using [byte-unixbench](https://github.com/kdlucas/byte-unixbench).

*Note: We plan to conduct further comparative testing for typical applications and scenarios in the future.*

Test environments:
* Kubernetes version: v1.20.15
* Node number: 2
* The node host has AppArmor and BPF LSM enabled by default.
* Node specification: ecs.g2i.xlarge (4 vCPUs, 16 GiB RAM)

Test steps:
* Deploy a test workload (disabling the default AppArmor profile for the test container via annotation).
* Perform 10 consecutive baseline tests within the test container.
* Install vArmor
* Perform 10 consecutive baseline tests within the test container
* Create a VarmorPolicy for the workload (1 rule for each access control type)， then perform 10 consecutive baseline tests within the test container.
* Update the VarmorPolicy (2 rules for each access control type), then perform 10 consecutive baseline tests within the test container.
* Update the VarmorPolicy (4 rules for each access control type), then perform 10 consecutive baseline tests within the test container.
* Update the VarmorPolicy (8 rules for each access control type), then perform 10 consecutive baseline tests within the test container.
* Collect test data, calculate the average of the test data, and then use the test results without vArmor installation as the baseline to measure performance losses under different scenarios.
  
Test results:
* After installing vArmor v0.5.0, if the container is not sandboxed (or if the container is sandboxed with the AlwaysAllow mode), it introduces a maximum performance loss of 1.34% to container process (in terms of Execl Throughput).
* vArmor v0.5.0 introduces the most significant performance overhead in terms of Execl Throughput and Process Creation. When 8 rules of various access control types are set for container process, the maximum performance loss for execl is 2.55%, and the maximum performance loss for process creation is 2.32%.
* The File Copy 4096 bufsize 8000 maxblocks scores for different test cases fluctuate compared to the baseline, which is unexpected. Possible reasons for this could be:
  * When the elastic cloud server is under high load, file copying may be accelerated due to factors like cache heat, leading to fluctuations.
  * The host may experience overselling, which can result in fluctuations in baseline test results within the elastic cloud server.

  <img src="./bpf_enforcer_benchmark.png" width="600">