---
slug: harden-the-AI-application-development-platform
title: AI Application Development Platform Security Hardening Practices
authors: [DannyWei]
tags: [LLM, AIAgent]
date: 2025-03-21T01:00
---

With the advent of the era of large language models, AI applications based on LLMs have been constantly emerging. This has also given rise to AI application development platforms represented by Coze, Dify, Camel, etc. These platforms provide visual design and orchestration tools, enabling users to quickly build various AI applications using no-code or low-code approaches with the capabilities of large language models (LLMs), thus meeting personalized needs and realizing business value.

An AI application development platform is essentially a SaaS platform, where different users can develop and host AI applications. Therefore, the platform needs to pay attention to the risk of cross-tenant attacks and take corresponding preventive measures. This article will take the actual risk of the "code execution plugin" as an example to demonstrate the necessity of isolation and hardening. It will also introduce to you how to use vArmor to harden plugins, thereby ensuring the security of the platform and its tenants.

<!-- truncate -->

## Code Execution Plugin

In AI application development, the code execution plugin is an important tool for implementing complex applications such as Agents, Workflows, and ChatBots. Almost all AI application development platforms have built-in Python and JavaScript code execution plugins, and some even provide an IDE environment to facilitate users to develop and release new plugins.

![image](dify.png)
![image](ide.png)

According to our research, many AI application development platforms execute user code through the combination of runc containers and code sandboxes. Currently, there are multiple technologies that can be used to implement code sandboxes, such as chroot, seccomp, bubblewrap, pyodide, and so on. The basic idea is to create a Python or JavaScript runtime environment with restricted permissions and strictly limit the dependent packages that the script can use. This is to prevent malicious users from obtaining the code execution permissions of the underlying system.

**However, when there are vulnerabilities in the code sandbox solution, the container becomes the last line of defense. Attackers may combine other vulnerabilities to further escalate privileges and carry out penetration, posing a threat to all applications and user data hosted on the platform.**

## Dify's Code Execution Plugin

### Basic Implementation
[Dify](https://dify.ai) is a well-known and open-sourced AI application development platform. It uses a self-developed [dify-sandbox](https://github.com/langgenius/dify-sandbox) as the code execution plugin and deploys it through the runc container. dify-sandbox runs user code using a non-root user, switches the root directory before running the user code, and uses seccomp to restrict the system calls with a whitelist. At the same time, dify-sandbox also restricts the packages that user code can use, sacrificing some flexibility in exchange for security.

### Sandbox Escape Case
Dify fixed a sandbox escape vulnerability ([CVE-2024-10252](https://nvd.nist.gov/vuln/detail/CVE-2024-10252)) in October 2024. This vulnerability allows attackers to inject arbitrary commands through the `preload` field and escape the code sandbox. Attackers could use this vulnerability to obtain the root rights of the container, and then further escalate privileges and carry out penetration, thus endangering the security of the entire platform and its users.

The following is a demonstration of this vulnerability. Attackers can use this vulnerability to get a reverse shell with root rights, then use other vulnerabilities to escape the runc container, ultimately accessing the host machine.

![image](poc1.gif)

## Hardening Practices

### Solutions
From the Dify case, we can see that runc containers + code sandboxes can provide a certain level of security, and its strength depends on the implementation of the code sandbox. However, once an attacker escapes the code sandbox by exploiting a vulnerability, they can further attack the entire platform and users, which poses a relatively large security risk in a multi-tenant scenario. Therefore, the industry often uses the following high isolation-level solutions to execute untrusted code:

* Cloud vendor FaaS services
* Lightweight virtual machine containers
* Cloud vendor ECS
* ...

As described in our article "[How to Choose a Hardening Solution](https://www.varmor.org/docs/main/practices/#how-to-choose-a-hardening-solution)", we recommend giving priority to using technical solutions with a high isolation-level solution to execute untrusted code. Only when such solutions cannot be implemented, consider using vArmor to harden the container to increase the cost for attackers and detect their intrusion behaviors.

### Hardening with vArmor
Next, we will still take the Dify code execution plugin as an example to demonstrate how to use vArmor to harden the container of the "code execution plugin". We plan to build **a dedicated policy** for it according to the following steps:

1. [Optional] Use vArmor's behavior modeling feature to collect the behavior data of the dify-sandbox container.
2. [Optional] Use the policy advisor provided by vArmor to generate a policy template for the dify-sandbox container (a blacklist policy based on built-in rules).
3. Formulate a hardening policy, then create the policy object in the cluster and start hardening the dify-sandbox.
4. [Optional] Switch the policy to the observation mode, continuously collect logs, and observe whether any legitimate behaviors are blocked by the hardening policy.
5. Enable the violation auditing feature of the policy, continuously collect logs, and monitor the illegal behaviors within the container.

Due to space limitations, this article will not describe the process of building the policy in detail. The following is the hardening policy we generated for dify-sandbox based on vArmor's built-in rules.

```yaml
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: dify-sandbox-policy
  namespace: dify
spec:
  # Perform a rolling update on existing workloads.
  # It's disabled by default.
  updateExistingWorkloads: true
  target:
    # The policy protects all the containers by default if the .spec.target.containers is nil.
    kind: Deployment
    selector:
      matchLabels:
        app.kubernetes.io/name: dify
        component: sandbox
  policy:
    enforcer: BPFSeccomp
    mode: EnhanceProtect
    enhanceProtect:
      # Audit the actions that violate the mandatory access control rules.
      # Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
      # It's disabled by default.
      auditViolations: true
      hardeningRules:
      - disallow-mount
      - disallow-umount
      - disable-cap-privileged
      - disallow-abuse-user-ns
      - disallow-create-user-ns
      - disallow-load-all-bpf-prog
      - disallow-load-bpf-via-setsockopt
      - disallow-userfaultfd-creation
      attackProtectionRules:
      - rules:
        - mitigate-sa-leak
        - mitigate-disk-device-number-leak
        - mitigate-overlayfs-leak
        - mitigate-host-ip-leak
        - disallow-metadata-service
        - disable-write-etc
        - disable-busybox
        - disable-wget
        - disable-curl
        - disable-chmod
        - disable-chmod-x-bit
        - disable-chmod-s-bit
        - disable-su-sudo
      vulMitigationRules:
      - cgroups-lxcfs-escape-mitigation
      - runc-override-mitigation
```

After applying the above policy, when attacker try to escape Dify's code sandbox using CVE-2024-10252 again and attempt further intrusion, we can see that the subsequent actions of the attacker are successfully blocked. At the same time, the malicious operations of the attacker are also recorded in the audit log, and users can use this to build an intrusion detection and response mechanism.

![image](poc2.gif)

```json
{
  "level": "warn",
  "nodeName": "172.16.0.32",
  "containerID": "c6711f231208edcc75b9bef3491df50fb656418277ce39fefd55ff32af6f1ab4",
  "containerName": "sandbox",
  "podName": "dify-sandbox-9864b46bf-t96br",
  "podNamespace": "dify",
  "podUID": "1f64384a-ce86-412b-bd23-a8000ce17c37",
  "pid": 683162,
  "mntNsID": 4026534445,
  "eventTimestamp": 1742462286,
  "eventType": "BPF",
  "event": {
    "permissions": [
      "read"
    ],
    "path": "/proc/16839/net/arp"
  },
  "time": "2025-03-20T09:18:07Z",
  "message": "violation event"
}
{
  "level": "warn",
  "nodeName": "172.16.0.32",
  "containerID": "c6711f231208edcc75b9bef3491df50fb656418277ce39fefd55ff32af6f1ab4",
  "containerName": "sandbox",
  "podName": "dify-sandbox-9864b46bf-t96br",
  "podNamespace": "dify",
  "podUID": "1f64384a-ce86-412b-bd23-a8000ce17c37",
  "pid": 683291,
  "mntNsID": 4026534445,
  "eventTimestamp": 1742462291,
  "eventType": "BPF",
  "event": {
    "permissions": [
      "read"
    ],
    "path": "/run/secrets/kubernetes.io/serviceaccount/..2025_03_20_09_15_14.2072511118/token"
  },
  "time": "2025-03-20T09:18:12Z",
  "message": "violation event"
}
```

## Conclusion

AI application development platforms, based on LLM technology and combined with visualization, low-code, etc., significantly reduce the development and operation costs of AI applications. As a multi-tenant SaaS service, tenant isolation should be given due attention. Especially when the platform provides users with functions such as code execution plugins, IDE environments, and plugin stores, while these functions expand and enhance the platform's capabilities, they also provide more attack entry points for malicious users.

vArmor has the characteristics of being cloud-native, flexible, ready-to-use, and easy to use. You can use it to harden different types of workloads in AI application development platforms, thereby improving the security level of the platform and ensuring the security of user data.
