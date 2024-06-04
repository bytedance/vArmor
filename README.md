<a>
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/img/logo.svg" width="400">
    <img src="docs/img/logo-dark.svg" width="400">
  </picture>
</a>

<br>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://opensource.org/license/gpl-2-0/)

English | [简体中文](README.zh_CN.md)

## Introduction

**vArmor** is a cloud-native container sandbox system. It leverages Linux's [AppArmor LSM](https://en.wikipedia.org/wiki/AppArmor), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html) and [Seccomp](https://en.wikipedia.org/wiki/Seccomp) technologies to implement enforcers. It can be used to strengthen container isolation, reduce the kernel attack surface, and increase the difficulty and cost of container escape or lateral movement attacks. You can leverage vArmor in the following scenarios to provide sandbox protection for containers within a Kubernetes cluster.
* In multi-tenant environments, hardware-virtualized container solutions cannot be employed due to factors such as cost and technical conditions.
* When there is a need to enhance the security of critical business containers, making it more difficult for attackers to escalate privileges, escape, or laterally move.
* When high-risk vulnerabilities are present, but immediate remediation is not possible due to the difficulty or lengthy process of patching. vArmor can be used to mitigate the risks (depending on the vulnerability type or exploitation vector) to block or increase the difficulty of exploitation.


**vArmor Features:**
* Cloud-native. vArmor follows the Kubernetes Operator design pattern, allowing users to harden specific workloads by manipulating the [CRD API](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/). This approach enables sandboxing of containerized microservices from a perspective closely aligned with business needs.
* Supports the use of AppArmor, BPF, Seccomp enforcer individually or in combination, enforcing mandatory access control on container file access, process execution, network outbound, syscall, and more.
* Supports the Allow by Default security model, in which only behaviors explicitly declared will be blocked, thus minimize performance impact and enhancing usability.
* Supports behavior modeling, and provides protection based on behavior models, meaning only behaviors explicitly declared are permitted.
* Ready to use out of the box. vArmor includes multiple built-in rules for direct use.

vArmor was created by the **Elkeid Team** of the endpoint security department at ByteDance. And the project is still in active development.


*Note: To meet stringent isolation requirements, it is advisable to give priority to utilizing hardware-virtualized containers (e.g., Kata Containers) for compute isolation, in conjunction with network isolation provided by CNI's NetworkPolicy.*


## Architecture
<img src="docs/img/architecture.png" width="600">


## Prerequisites
You can specify the enforcer through the `spec.policy.enforcer` field of policy objects ([VarmorPolicy](docs/usage_instructions.md#varmorpolicy)/[VarmorClusterPolicy](docs/usage_instructions.md#varmorclusterpolicy)). In addition, you can also use different enforcers individually or in combination, such as: AppArmorBPF, AppArmorSeccomp, AppArmorBPFSeccomp etc.

The prerequisites required by different enforcers are as shown in the following table.

|Enforcer|Requirements|Recommendations|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15 and above<br>2. The AppArmor LSM is enabled|GKE with Container-Optimized OS<br>AKS with Ubuntu 22.04 LTS<br>[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0<br>Debian 10 and above<br>Ubuntu 18.04.0 LTS and above<br>[veLinux 1.0](https://www.volcengine.com/docs/6396/74967) etc.
|BPF         |1. Linux Kernel 5.10 and above (x86_64)<br>2. containerd v1.6.0 and above<br>3. The BPF LSM is enabled|EKS with Amazon Linux 2<br>GKE with Container-Optimized OS<br>[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0 (with 5.10 kernel)<br>AKS with Ubuntu 22.04 LTS <sup>\*</sup><br>ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br>OpenSUSE 15.4 <sup>\*</sup><br>Debian 11 <sup>\*</sup><br>Fedora 37 <br>[veLinux 1.0 with 5.10 kernel](https://www.volcengine.com/docs/6396/74967) etc.<br><br>* *Manual enabling of BPF LSM is required*
|Seccomp     |1. Kubernetes v1.19 and above|All Linux distributions


## The Policy Modes and Built-in Rules

The vArmor policy can operate in five modes: **AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling and DefenseInDepth**. When the policy is running in **EnhanceProtect** mode, built-in rules and custom interfaces can be used to harden the container.

For more information, please refer to [Policy Modes and Built-in Rules](docs/built_in_rules.md).


## Quick start

For more configuration options and detailed instructions, please refer to the [usage instructions](docs/usage_instructions.md). You can refer to the [examples](test/demo) to understand how to use the relevant features and write policies. You can also try using [policy-advisor](tools/policy-advisor/policy-advisor.py) to generate a policy template, and then build the final policy based on it.

### Step 1. Fetch chart
```
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.5.8
```

### Step 2. Install
*You can use the domain `elkeid-cn-beijing.cr.volces.com` inside of the CN region.*
```
helm install varmor varmor-0.5.8.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-ap-southeast-1.cr.volces.com"
```

### Step 3. Try with this example
```
# Create demo namespace
kubectl create namespace demo

# Create a VarmorPolicy object to enable the AlwaysAllow mode sandbox for Deployments that match the .spec.target.selector
kubectl create -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml

# View the status of VarmorPolicy & ArmorProfile object
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo

# Create the target Deployment object
kubectl create -f test/demo/1-apparmor/deploy.yaml

# Retrieve the Pod name of the target Deployment object
POD_NAME=$(kubectl get Pods -n demo -l app=demo-1 -o name)

# Execute a command in container c1 to read the secret token
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

# Update the VarmorPolicy object to prohibit the container c1 from reading the secret token.
kubectl apply -f test/demo/1-apparmor/vpol-apparmor-enhance.yaml

# Execute a command in container c1 to read the secret token and verify that the reading behavior is prohibited.
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

# Delete the VarmorPolicy and Deployment objects
kubectl delete -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
kubectl delete -f test/demo/1-apparmor/deploy.yaml
```

### Step 4. Uninstall
```
helm uninstall varmor -n varmor
```


## The Performance Specification
Please refer to this [documentation](docs/performance_specification.md).


## License

The vArmor project is licensed under Apache 2.0, except for third party components which are subject to different license terms. Please refer to the code header information in the code files.

Your integration of vArmor into your own projects should require compliance with the Apache 2.0 License, as well as the other licenses applicable to the third party components included within vArmor.

The eBPF code is located at [vArmor-ebpf](https://github.com/bytedance/vArmor-ebpf) and licensed under GPL-2.0.


## Credits
vArmor use [cilium/ebpf](https://github.com/cilium/ebpf) to manage and interact with the eBPF program.

vArmor references part of the code of [kyverno](https://github.com/kyverno/kyverno) developed by [Nirmata](https://nirmata.com/).


## Demo
Below is a demonstration of using vArmor to harden a Deployment and defend against CVE-2021-22555. (The exploit is modified from [cve-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555))<br>
![image](test/demo/vulnerability-mitigation/CVE-2021-22555/demo.gif)


## 404Starlink
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

vArmor has joined [404Starlink](https://github.com/knownsec/404StarLink)
