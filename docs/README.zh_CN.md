# 简介
[English](README.md) | 简体中文

了解 vArmor 并通过快速入门指南创建您的第一个策略。

## 关于 vArmor

vArmor 是一个云原生容器沙箱系统，它借助 Linux 的 [AppArmor LSM](https://en.wikipedia.org/wiki/AppArmor)，[BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html) 和 [Seccomp](https://en.wikipedia.org/wiki/Seccomp) 技术实现强制访问控制器（即 enforcer），从而对容器进行安全加固。它可以用于增强容器隔离性、减少内核攻击面、增加容器逃逸或横行移动攻击的难度与成本。

您可以借助 vArmor 在以下场景对 Kubernetes 集群中的容器进行沙箱防护
* 业务场景存在多租户（多租户共享同一个集群），由于成本、技术条件等原因无法使用硬件虚拟化容器。
* 想要对关键的业务进行安全加固，增加攻击者权限提升、容器逃逸、横向渗透的难度与成本。
* 当出现高危漏洞，但由于修复难度大、周期长等原因无法立即修复时，可以借助 vArmor 实施漏洞利用缓解（具体取决于漏洞类型或漏洞利用向量。缓解代表阻断利用向量、增加利用难度）。


*注意：* 
*<br />- 安全防御的核心在于平衡风险与收益，通过选择不同类型的安全边界和防御技术，将不可控风险转化为可控成本。*
*<br />- runc + vArmor 不提供等同硬件虚拟化容器（如 Kata Container 等轻量级虚拟机）的隔离等级。如果您需要高强度的隔离方案，请优先考虑使用硬件虚拟化容器进行计算隔离，并借助 CNI 的 NetworkPolicy 进行网络隔离。*

**vArmor 的特点**
* **Cloud-Native**. vArmor 遵循 Kubernetes Operator 设计模式，用户可通过操作 [CRD API](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) 对特定的 Workloads 进行加固。从而以更贴近业务的视角，实现对容器化微服务的沙箱加固。
* **Multiple Enforcers**. vArmor 将 AppArmor、BPF、Seccomp 抽象为 Enforcer，并支持单独或组合使用，从而对容器的文件访问、进程执行、网络外联、系统调用等进行访问控制。
* **Allow-by-Default**. vArmor 当前重点支持此安全模型，即只有显式声明的行为会被阻断，从而减少性能损失和增加易用性。vArmor 支持对违反访问控制规则的行为进行审计，并支持放行违反访问控制规则的行为。
* **Built-in Rules**. vArmor 提供了一系列开箱即用的内置规则。这些规则为 Allow-by-Default 安全模型设计，从而极大降低对用户专业知识的要求。
* **Behavior Modeling**. vArmor 支持对工作负载进行行为建模。这对于制定白名单安全策略、分析哪些内置规则可用于加固应用，或指导工作负载的配置以遵循最小权限原则非常有用。
* **Deny-by-Default**. vArmor 可以使用白名单安全策略来加固工作负载，并提供一种更便于用户使用的方式来开发和管理安全策略。

vArmor 项目由字节跳动终端安全团队的 **Elkeid Team** 创建，目前该项目仍在积极迭代中。


## vArmor 如何工作

### 架构
vArmor 主要由 Manager 和 Agent 两个组件构成。Manager 用于响应和管理安全策略，而 Agent 则在集群节点上管理 enforcer（强制访问控制器）和 profile（安全配置文件）。


<div>
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="img/architecture.svg" width="600">
        <img src="img/architecture-dark.svg" width="600">
    </picture>
</div>

### 原理
* [VarmorPolicy](getting_started/usage_instructions.md#varmorpolicy) 和 [VarmorClusterPolicy](getting_started/usage_instructions.md#varmorclusterpolicy) CR 是 vArmor 的用户接口。
* 您可以通过管理 VarmorPolicy 或 VarmorClusterPolicy CR 策略对象，使用不同的强制访问控制器及其规则来加固容器。
* ArmorProfile CR 作为内部接口，用于安全配置文件的管理。

<div>
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="img/principle.svg" width="600">
        <img src="img/principle-dark.svg" width="600">
    </picture>
</div>

当 Manager 监听到 VarmorPolicy 或 VarmorClusterPolicy 对象的创建事件时，它会为其创建一个对应的 ArmorProfile 内部对象。Agent 监听并响应这个 ArmorProfile 对象，处理安全配置文件后将状态报告回 Manager。当用户创建工作负载时，APIServer 通过准入 webhook 将创建请求发送到 Manager。Manager 评估是否应该加固工作负载。如果需要，Manager 通过添加注释和修改 securityContext 等来变异工作负载。最后，工作负载的 Pod 将被调度到节点上，并在创建容器时为其设置安全上下文。

### 关键术语
#### 强制访问控制器
vArmor 将 AppArmor, BPF, Seccomp 抽象为强制访问控制器（即 Enforcer）。安全策略可以单独、组合使用它们来加固工作负载，例如：BPF、AppArmorBPF、AppArmorSeccomp、AppArmorBPFSeccomp 等。

您可以在 [VarmorPolicy](getting_started/usage_instructions.md#varmorpolicy) 或 [VarmorClusterPolicy](getting_started/usage_instructions.md#varmorclusterpolicy) 对象的 `spec.policy.enforcer` 字段中设置要使用的强制访问控制器。

#### 策略模式
vArmor 的策略可以运行在五种模式中：*AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling 和 DefenseInDepth*。这种灵活性使其能够满足不同场景的需求。

更多信息请参见 [策略模式](guides/policies_and_rules/policy_modes/README.zh_CN.md)。


#### 内置规则和自定义规则
当安全策略运行在 **EnhanceProtect** 模式时，[内置规则](guides/policies_and_rules/built_in_rules.zh_CN.md) 和 [自定义规则](guides/policies_and_rules/custom_rules.zh_CN.md) 可以被用于加固容器。此时，策略采用 **Allow-by-Default** 安全模型，这意味着只有明确声明的行为才会被阻止。这种方法在增强可用性的同时最大限度地减少了对性能的影响。


## 前置条件

不同强制访问控制器所需的前置条件如下表所示。

|强制访问控制器|要求|推荐|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15 及以上版本<br />2. 系统需开启 AppArmor LSM|GKE with Container-Optimized OS<br />AKS with Ubuntu 22.04 LTS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0<br />Debian 10 及以上版本<br />Ubuntu 18.04.0 LTS 及以上版本<br />[veLinux 1.0](https://www.volcengine.com/docs/6396/74967) 等
|BPF         |1. Linux Kernel 5.10 及以上版本 (x86_64)<br />2. containerd v1.6.0 及以上版本<br />3. 系统需开启 BPF LSM|EKS with Amazon Linux 2<br />GKE with Container-Optimized OS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0 (with 5.10 kernel)<br />AKS with Ubuntu 22.04 LTS <sup>\*</sup><br />ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br />OpenSUSE 15.4  <sup>\*</sup><br />Debian 11 <sup>\*</sup><br />Fedora 37<br />[veLinux 1.0 with 5.10 kernel](https://www.volcengine.com/docs/6396/74967) 等<br /><br />* *需手动启用节点的 BPF LSM*
|Seccomp     |1. Kubernetes v1.19 及以上版本|所有 Linux 发行版


## 快速入门
### 步骤 1. 拉取 chart 包

```bash
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.8.1
```

### 步骤 2. 安装
vArmor 默认支持 AppArmor 和 Seccomp enforcer。请参照 [配置选项](getting_started/installation.zh_CN.md#配置选项) 查看更多信息。

```bash
helm install varmor varmor-0.8.1.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-cn-beijing-1.cr.volces.com"
```
*您可以在非中国地区使用 elkeid-ap-southeast-1.cr.volces.com 域名*

### 步骤 3. 尝试以下用例
创建 demo 命名空间。

```bash
kubectl create namespace demo
```

创建一个运行在 **AlwaysAllow 模式** 中的 VarmorPolicy 对象，为符合 `spec.target.selector` 条件的 `deployments` 开启“防护”。


```yaml
cat << EOF | kubectl create -f -
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: demo-1
  namespace: demo
spec:
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: demo-1
  policy:
    enforcer: AppArmor
    mode: AlwaysAllow
EOF
```

查看 VarmorPolicy 和 ArmorProfile 对象的状态。

```bash
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo
```

创建目标工作负载。

```yaml
cat << EOF | kubectl create -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-1
  namespace: demo
  labels:
    sandbox.varmor.org/enable: "true"
    app: demo-1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: demo-1
  template:
    metadata:
      labels:
        app: demo-1
      annotations:
        # Use this annotation to explicitly disable the protection for the container named c0.
        # It always takes precedence over the '.spec.target.containers' field.
        container.apparmor.security.beta.varmor.org/c0: unconfined
    spec:
      containers:
      - name: c0
        image: debian:10
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent
      - name: c1
        image: debian:10
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent

EOF
```

获取目标 Deployment 的 Pod 名称。

```bash
POD_NAME=$(kubectl get Pods -n demo -l app=demo-1 -o name)
```

在容器 `c1` 中执行命令，读取其 SA token。

```bash
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token
```

切换 VarmorPolicy 对象到 **EnhancedProtect 模式**，并阻止 `c1` 容器读取 SA token。

```yaml
cat << EOF | kubectl apply -f -
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: demo-1
  namespace: demo
spec:
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: demo-1
  policy:
    enforcer: AppArmor
    mode: EnhanceProtect
    enhanceProtect:
      hardeningRules:
      - disable-cap-privileged
      attackProtectionRules:
      - rules:
        - mitigate-sa-leak
EOF
```

在容器 `c1` 中执行命令，读取其 SA token。验证读取行为是否被禁止。

```bash
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token
```

## 演示

下面是一个使用 vArmor 对 Deployment 进行加固，防御 CVE-2021-22555 攻击的演示（Exploit 修改自 [cve-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555)）。

更多演示请查看我们的 GitHub [仓库](https://github.com/bytedance/vArmor/tree/main/test/demos)。

![image](../test/demos/CVE-2021-22555/demo.zh_CN.gif)
