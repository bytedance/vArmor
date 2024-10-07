<div>
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/img/logo.svg" width="400">
        <img src="docs/img/logo-dark.svg" alt="Logo" width="400">
    </picture>
</div>
<br>

![BHArsenalUSA2024](docs/img/BlackHat-Arsenal-USA-2024.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/bytedance/vArmor)](https://goreportcard.com/report/github.com/bytedance/vArmor)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://opensource.org/license/gpl-2-0)
[![Latest release](https://img.shields.io/github/v/release/bytedance/vArmor)](https://github.com/bytedance/vArmor/releases)

English | [简体中文](README.zh_CN.md) | [日本語](README.ja.md)

vArmor is a cloud-native container sandbox system. It leverages Linux's [AppArmor LSM](https://en.wikipedia.org/wiki/AppArmor), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html) and [Seccomp](https://en.wikipedia.org/wiki/Seccomp) technologies to implement enforcers. It can be used to strengthen container isolation, reduce the kernel attack surface, and increase the difficulty and cost of container escape or lateral movement attacks. You can leverage vArmor in the following scenarios to provide sandbox protection for containers within a Kubernetes cluster.
* In multi-tenant environments, hardware-virtualized container solutions cannot be employed due to factors such as cost and technical conditions.
* When there is a need to enhance the security of critical business containers, making it more difficult for attackers to escalate privileges, escape, or laterally move.
* When high-risk vulnerabilities are present, but immediate remediation is not possible due to the difficulty or lengthy process of patching. vArmor can be used to mitigate the risks (depending on the vulnerability type or exploitation vector) to block or increase the difficulty of exploitation.

*Note: To meet stringent isolation requirements, it is advisable to give priority to utilizing hardware-virtualized containers (e.g., Kata Containers) for compute isolation, in conjunction with network isolation provided by CNI's NetworkPolicy.*


**vArmor Features:**
* **Cloud-Native**. vArmor follows the Kubernetes Operator design pattern, allowing users to harden specific workloads by manipulating the [CRD API](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/). This approach enables sandboxing of containerized microservices from a perspective closely aligned with business needs.
* **Multiple Enforcers**. vArmor abstracts AppArmor, BPF, and Seccomp as enforcers, supporting their use individually or in combination. This enables enforcing access control on container file access, process execution, network outbound, syscalls, and more.
* **Allow-by-Default**. vArmor currently focuses on supporting this model. Only explicitly declared behaviors will be blocked, effectively minimizing performance impact and enhancing usability.
* **Built-in Rules**. vArmor features a range of built-in rules ready to use out of the box. They are designed for the Allow-by-Default model, eliminating the need for expertise in policy creation.
* **Behavior Modeling**. vArmor supports behavior modeling for workloads. This can be used for developing an allowlist profile, analyze which built-in rules can harden the application, or guide the configuration of workloads to adhere to the principle of least privilege.
* **Deny-by-Default**. vArmor is capable of creating an allowlist profile from behavior models and ensuring that only explicitly declared behaviors are permitted.


vArmor was created by the **Elkeid Team** of the endpoint security department at ByteDance. And the project is still in active development.


## Documentation
vArmor reference documents are available at [varmor.org](https://varmor.org).

👉 **[Quick Start](https://www.varmor.org/docs/introduction#quick-start)**

👉 **[Installation](https://www.varmor.org/docs/getting_started/installation)**

👉 **[Usage Instructions](https://www.varmor.org/docs/getting_started/usage_instructions)**

👉 **[Policies and Rules](https://www.varmor.org/docs/guides/policies_and_rules)**

👉 **[Performance Specifications](https://www.varmor.org/docs/guides/performance)**


## Contributing
Thanks for your interest in contributing to vArmor! Here are some steps to help get you started:

✔ Read and agree to the [code of conduct](./CODE_OF_CONDUCT.md).

✔ Read the [development guide](docs/development_guide.md).

✔ Join vArmor [Lark group](https://applink.larkoffice.com/client/chat/chatter/add_by_link?link_token=ae5pfb2d-f8a4-4f0b-b12e-15f24fdaeb24&qr_code=true).


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
