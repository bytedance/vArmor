<div>
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="docs/img/logo.svg" width="400">
        <img src="docs/img/logo-dark.svg" alt="Logo" width="400">
    </picture>
</div>
<br />

![BHArsenalUSA2024](docs/img/BlackHat-Arsenal-USA-2024.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/bytedance/vArmor)](https://goreportcard.com/report/github.com/bytedance/vArmor)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://opensource.org/license/gpl-2-0)
[![Latest release](https://img.shields.io/github/v/release/bytedance/vArmor)](https://github.com/bytedance/vArmor/releases)

English | [简体中文](README.zh_CN.md) | [日本語](README.ja.md)

vArmor is a cloud-native container hardening system. It leverages Linux's [AppArmor LSM](https://en.wikipedia.org/wiki/AppArmor), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [Seccomp](https://en.wikipedia.org/wiki/Seccomp), and **Network Proxy** ([Envoy](https://www.envoyproxy.io/)-based sidecar) technologies to implement enforcers. It can be used to strengthen container isolation, reduce the kernel attack surface, enforce network egress access control at L4/L7 levels — including TLS MITM for decrypted HTTPS inspection, HTTP header injection, and anti-Domain-Fronting protection — and increase the difficulty and cost of container escape or lateral movement attacks. You can leverage vArmor in the following scenarios to provide sandbox protection for containers within a Kubernetes cluster.
* In multi-tenant environments, hardware-virtualized container solutions cannot be employed due to factors such as cost and technical conditions.
* You want to enhance the security of critical business containers, making it more difficult for attackers to escalate privileges, escape, or laterally move.
* When high-risk vulnerabilities are present but immediate remediation is not possible due to the difficulty or lengthy process of patching, vArmor can be used to mitigate the risks (depending on the vulnerability type or exploitation vector) to block or increase the difficulty of exploitation.
* You are deploying AI Agents or LLM-based applications and need to precisely control their outbound network access — preventing data exfiltration, unauthorized API calls, or abuse induced by prompt injection attacks.

*Note:* 
*<br />- The core of security defense lies in balancing risks and benefits, transforming uncontrollable risks into controllable costs by choosing different types of security boundaries and defense technologies.*
*<br />- runc + vArmor does not provide an isolation level equivalent to that of hardware virtualization containers (such as Kata Containers and other lightweight virtual machines). If you require a high-intensity isolation solution, please consider using hardware virtualization containers for compute isolation, and utilize CNI's NetworkPolicy for network isolation.*
*<br />- vArmor's NetworkProxy enforcer further complements NetworkPolicy by providing L7 access control for both HTTP and HTTPS (via TLS MITM), TLS SNI-based domain filtering, per-domain HTTP header injection, anti-Domain-Fronting protection, and comprehensive audit logging — capabilities that NetworkPolicy does not offer.*

**vArmor Features:**
* **Cloud-Native**. vArmor follows the Kubernetes Operator design pattern, allowing users to harden specific workloads by manipulating the [CRD API](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/). This approach enables sandboxing of containerized microservices from a perspective closely aligned with business needs.
* **Multiple Enforcers**. vArmor abstracts AppArmor, BPF, Seccomp, and NetworkProxy as enforcers, supporting their use individually or in combination. This enables enforcing access control on container file access, process execution, network outbound (L3–L7), syscalls, and more.
* **Network Proxy Enforcer**. vArmor introduces a sidecar-proxy-based enforcer (powered by Envoy) that transparently intercepts and controls container network egress traffic at L4 (TCP), L7 (HTTP/HTTPS), and TLS SNI levels. It supports TLS MITM termination, per-domain HTTP header injection (e.g., API key injection), anti-Domain-Fronting protection, allow-list and deny-list modes, audit logging, and dynamic policy updates without Pod restarts.
* **AI Agent Protection**. vArmor provides defense-in-depth for AI Agent workloads by combining kernel-level mandatory access control (AppArmor/BPF/Seccomp) with application-protocol-level network access control (NetworkProxy), effectively mitigating risks such as prompt injection-induced tool abuse, key leakage, and unauthorized data exfiltration.
* **Allow-by-Default**. vArmor currently focuses on supporting this model, where only explicitly declared behaviors will be blocked, which effectively minimizes performance impact and enhances usability. Besides, it supports auditing violations, and these violations can also be allowed rather than blocked.
* **Built-in Rules**. vArmor features a range of built-in rules ready to use out of the box. They are designed for the Allow-by-Default security model, eliminating the need for expertise in security profile creation.
* **Behavior Modeling**. vArmor features a range of built-in rules ready to use out of the box. They are designed for the Allow-by-Default security model, eliminating the need for expertise in security profile creation.
* **Deny-by-Default**. vArmor is capable of using allowlist profiles to harden workloads and provide a more user-friendly approach to develop and manage profiles.


vArmor was created by the **Elkeid Team** of the endpoint security department at ByteDance. And the project is still in active development.

## Architecture
<div style="text-align: center;">
  <img src="docs/img/architecture.svg" width="600">
</div>

## Documentation
vArmor reference documents are available at [varmor.org](https://varmor.org).

⏩ **[Quick Start](https://www.varmor.org/docs/main/introduction)**

⚙️ **[Installation](https://www.varmor.org/docs/main/getting_started/installation)**

📔 **[Usage Instructions](https://www.varmor.org/docs/main/getting_started/usage_instructions)**

📜 **[Policies and Rules](https://www.varmor.org/docs/main/guides/policies_and_rules)**

⏱️ **[Performance Specifications](https://www.varmor.org/docs/main/guides/performance)**


## Contributing
Thanks for your interest in contributing to vArmor! Here are some steps to help get you started:

🤝🏻 Read and agree to the [code of conduct](./CODE_OF_CONDUCT.md).

🛠️ Read the [development guide](https://www.varmor.org/docs/main/guides/development).

💬 Join vArmor [Lark group](https://applink.larkoffice.com/client/chat/chatter/add_by_link?link_token=ae5pfb2d-f8a4-4f0b-b12e-15f24fdaeb24&qr_code=true).


## License

The vArmor project is licensed under Apache 2.0, except for third party components which are subject to different license terms. Please refer to the code header information in the code files.

Your integration of vArmor into your own projects should require compliance with the Apache 2.0 License, as well as the other licenses applicable to the third party components included within vArmor.

The eBPF code is located at [vArmor-ebpf](https://github.com/bytedance/vArmor-ebpf) and licensed under GPL-2.0.


## Credits
vArmor use [cilium/ebpf](https://github.com/cilium/ebpf) to manage and interact with the eBPF program.

vArmor references part of the code of [kyverno](https://github.com/kyverno/kyverno) developed by [Nirmata](https://nirmata.com/).


## Demo
Below is a demonstration of using vArmor to harden a Deployment and defend against CVE-2021-22555. (The exploit is modified from [cve-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555))<br />
![image](test/demos/CVE-2021-22555/demo.gif)


## 404Starlink
<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

vArmor has joined [404Starlink](https://github.com/knownsec/404StarLink)
