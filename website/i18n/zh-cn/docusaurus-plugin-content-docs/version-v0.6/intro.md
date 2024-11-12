---
sidebar_position: 1
---

## 简介

vArmor 是一个云原生容器沙箱系统，它借助 Linux 的 [AppArmor LSM](https://en.wikipedia.org/wiki/AppArmor), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html) 和 [Seccomp](https://en.wikipedia.org/wiki/Seccomp) 技术实现强制访问控制器（即 enforcer），从而对容器进行安全加固。它可以用于增强容器隔离性、减少内核攻击面、增加容器逃逸或横行移动攻击的难度与成本。

您可以借助 vArmor 在以下场景对 Kubernetes 集群中的容器进行沙箱防护
* 业务场景存在多租户（多租户共享同一个集群），由于成本、技术条件等原因无法使用硬件虚拟化容器（如 Kata Container）
* 需要对关键的业务进行安全加固，增加攻击者权限提升、容器逃逸、横向渗透的难度与成本
* 当出现高危漏洞，但由于修复难度大、周期长等原因无法立即修复时，可以借助 vArmor 实施漏洞利用缓解（具体取决于漏洞类型或漏洞利用向量。缓解代表阻断利用向量、增加利用难度）

**vArmor 的特色**
* 云原生。vArmor 遵循 Kubernetes Operator 设计模式，用户可通过操作 [CRD API](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) 对特定的 Workloads 进行加固。从而以更贴近业务的视角，实现对容器化微服务的沙箱加固
* 支持单独或组合使用 AppArmor、BPF、Seccomp enforcer，对容器的文件访问、进程执行、网络外联、系统调用等进行强制访问控制
* 支持 Allow by Default 安全模型，即只有显式声明的行为会被阻断，从而减少性能损失和增加易用性
* 支持行为建模，并基于行为模型进行安全防护，即只有显式声明的行为会被允许
* 开箱即用。vArmor 包含多种内置加固规则供直接使用

vArmor 由字节跳动终端安全团队的 **Elkeid Team** 研发，目前该项目仍在积极迭代中。

*注意：如果需要高强度的隔离方案，建议优先考虑使用硬件虚拟化容器（如 Kata Container）进行计算隔离，并借助 CNI 的 NetworkPolicy 进行网络隔离。*


## 架构
<img src="./img/architecture.svg" width="600" />


## 前置条件
您可以通过策略对象（[VarmorPolicy](docs/usage_instructions.zh_CN.md#varmorpolicy)/[VarmorClusterPolicy](docs/usage_instructions.zh_CN.md#varmorclusterpolicy)）的 `spec.policy.enforcer` 字段来指定 enforcer。另外，您还可以单独、组合使用不同的 enforcer，例如：AppArmorBPF, AppArmorSeccomp, AppArmorBPFSeccomp。

不同 enforcers 所需要的前置条件如下表所示。

|强制访问控制器|要求|推荐|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15 及以上版本<br />2. 系统需开启 AppArmor LSM|GKE with Container-Optimized OS<br />AKS with Ubuntu 22.04 LTS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0<br />Debian 10 及以上版本<br />Ubuntu 18.04.0 LTS 及以上版本<br />[veLinux 1.0](https://www.volcengine.com/docs/6396/74967) 等
|BPF         |1. Linux Kernel 5.10 及以上版本 (x86_64)<br />2. containerd v1.6.0 及以上版本<br />3. 系统需开启 BPF LSM|EKS with Amazon Linux 2<br />GKE with Container-Optimized OS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0 (with 5.10 kernel)<br />AKS with Ubuntu 22.04 LTS <sup>\*</sup><br />ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br />OpenSUSE 15.4  <sup>\*</sup><br />Debian 11 <sup>\*</sup><br />Fedora 37<br />[veLinux 1.0 with 5.10 kernel](https://www.volcengine.com/docs/6396/74967) 等<br /><br />* *需手动启用节点的 BPF LSM*
|Seccomp     |1. Kubernetes v1.19 及以上版本|所有 Linux 发行版


## 策略模式与内置规则
vArmor 的策略支持 5 种运行模式：**AlwaysAllow、RuntimeDefault、EnhanceProtect、BehaviorModeling、 DefenseInDepth**。当策略运行在 **EnhanceProtect** 模式时，可使用内置规则和自定义接口对容器进行加固。

更多说明请参见 [策略模式与内置规则](docs/built_in_rules.zh_CN.md)。


## 快速上手
更多配置项和使用说明详见 [使用说明](docs/usage_instructions.zh_CN.md)。您可以参考 [样例](test/demo) 来了解相关功能的用法，从而辅助策略编写。您也可以尝试使用 [policy-advisor](tools/policy-advisor/README.md) 生成策略模版，并在模版基础上制定最终的策略。

### Step 1. 拉取 chart 包
```
helm pull oci://elkeid-cn-beijing.cr.volces.com/varmor/varmor --version 0.5.11
```

### Step 2. 安装
*您可以在非中国地区使用 elkeid-ap-southeast-1.cr.volces.com 域名*
```
helm install varmor varmor-0.5.11.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-cn-beijing.cr.volces.com"
```

### Step 3. 示例
```
# 创建名为 demo 的命名空间
kubectl create namespace demo

# 创建 VarmorPolicy，对符合 .spec.target.selector 的 Deployment 开启 AlwaysAllow 模式沙箱
kubectl create -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml

# 查看 VarmorPolicy & ArmorProfile 状态
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo

# 创建 Deployment
kubectl create -f test/demo/1-apparmor/deploy.yaml

# 获取 Pod name
POD_NAME=$(kubectl get Pods -n demo -l app=demo-1 -o name)

# 在 c1 容器中执行命令，读取 secret token
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

# 更新 VarmorPolicy 策略，禁止 Deployment 读取 secret token
kubectl apply -f test/demo/1-apparmor/vpol-apparmor-enhance.yaml

# 在 c1 容器中执行命令，读取 secret token，验证读取行为被禁止
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

# 删除 VarmorPolicy 和 Deployment
kubectl delete -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
kubectl delete -f test/demo/1-apparmor/deploy.yaml
```

### Step 4. 卸载
```
helm uninstall varmor -n varmor
```


## 性能说明
详见 [性能说明](docs/performance_specification.zh_CN.md)


## 许可证
vArmor 采用 Apache License, Version 2.0 许可证，受不同许可证约束的第三方组件除外。具体请参考代码文件中的代码头信息。

将 vArmor 集成到您自己的项目中应遵守 Apache 2.0 许可证以及适用于 vArmor 中包含的第三方组件的其他许可证。

vArmor 所使用的 eBPF 代码位于 [vArmor-ebpf](https://github.com/bytedance/vArmor-ebpf.git) 项目，并且使用 GPL-2.0 许可证。


## 致谢
vArmor 使用 [cilium/ebpf](https://github.com/cilium/ebpf) 来管理 eBPF 程序。

vArmor 在研发初期参考了 [Nirmata](https://nirmata.com/) 开发的 [kyverno](https://github.com/kyverno/kyverno) 的部分实现。 


## 演示
下面是一个使用 vArmor 对 Deployment 进行加固，防御 CVE-2021-22555 攻击的演示（Exploit 修改自 [cve-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555)）。<br />
![image](./img/cve-2021-22555-demo.gif)


## 404星链计划
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%" />

vArmor 现已加入 [404星链计划](https://github.com/knownsec/404StarLink)