---
slug: /practices
sidebar_position: 4
---

import ThemeImage from '@site/src/components/ThemeImage';

# Practices

## Introduction

This article will analyze the purpose of the vArmor project, elaborate on how it addresses the challenges in current container security policy management. From a technical perspective, it will introduce the diverse usage scenarios and methods of vArmor in cloud-native technology stacks such as multi-tenant isolation, core business hardening, and privileged container hardening. It will demonstrate how to utilize the project's technical features to solve specific problems, achieve technical and business goals, and help enterprises build a solid security defense line in the cloud-native environment.

## Why vArmor Was Launched

Container runtime components and Kubernetes have added support for LSM and Seccomp. Seccomp became generally available in Kubernetes v1.19, and AppArmor LSM became generally available in Kubernetes v1.30. Users can write and manage AppArmor, SELinux, and Seccomp Profiles on their own and configure security policies in workloads for hardening. Container runtime components come with default AppArmor and Seccomp security policies. However, the default Seccomp profile needs to be explicitly set to be enabled for containers, and the default AppArmor profile requires operating system support to be enabled for containers.

Fully leveraging the security mechanisms of the Linux system can effectively harden containers. Technologies such as LSM and Seccomp enforce mandatory access control on container processes, reducing the attack surface and increasing the difficulty and cost of container escape or lateral movement attacks. Their basic principles are shown in the following figure.

<ThemeImage 
  lightSrc="/img/lsm.svg" 
  darkSrc="/img/lsm-dark.svg" 
  alt="lsm" 
/>
<br /><br />

However, writing and managing security policies face numerous challenges:
* The default profiles of container runtime components have limitations. They cannot defend against some vulnerabilities, misconfiguration risks, nor can they restrict attackers' penetration behavior within containers.
* Building AppArmor, Seccomp, or SELinux profiles requires expertise.
* Developing robust security profiles, especially those in the Deny-by-Default mode, for complex, fast-changing and  large-scale containerized applications is difficult.
* AppArmor or SELinux LSM is dependent on the operating system distribution, which has limitations.
* In a Kubernetes environment, automating the management and application of different security profiles is complex.

To address these issues, vArmor emerged. It provides multiple policy modes, built-in rules, and configuration options. Users can configure policy objects as needed to meet different scenario requirements. vArmor will generate and update security profiles (AppArmor, BPF, Seccomp profiles) based on the definition of policy objects to harden target workloads.

At the same time, vArmor supports three features: intercept, intercept and alarm, and alarm only without interception, meeting different scenario needs. Based on BPF and Audit technologies, vArmor has also implemented a behavior modeling feature. It can collect the behaviors of different applications and generate behavior models, which are used to build security profiles in the Allow-by-Default and Deny-by-Default modes.

Based on the above solutions of vArmor to the challenges in container security policy management, the following will detail its various scenarios in practical applications, showing how it helps enterprises enhance their container security protection capabilities.

## vArmor's Application Scenarios

### Multi-tenant Isolation

#### Risks of Multi-tenant Applications

Most modern SaaS, PaaS, and MaaS applications adopt a multi-tenant model. Severe vulnerabilities and exploit chains may enable malicious users to access the data of other tenants. With the advent of the large model era, the usage of cloud services has increased. Those building these services need to pay attention to multi-tenant isolation risks and take preventive measures to reduce the risk of cross-tenant attacks.
 
The following is a typical vulnerability-enabled cross-tenant attack sequence<sup><a href="#ref1">1</a></sup>.

![image](../img/attack-sequence.png)


Numerous cases show that the root causes of cross-tenant vulnerabilities and exploit chains mainly include:
* The user interface has a relatively high complexity, and harmless bugs and features in the interface exacerbate the risks.
* The implementation of multi-tenant shared components is improper.
* The security boundaries of multi-tenant exclusive components are improperly implemented.

To address these issues, the following mitigation measures can be taken:
* Reduce the complexity of the user interface.
* Transform shared components into tenant-exclusive components.
* Enhance the isolation of tenant-exclusive components.

#### How to Choose a Hardening Solution

Wiz pointed out in the PEACH framework that for multi-tenant applications, the tenant isolation technology solution should be selected based on the results of security modeling, taking into account factors such as compliance, data sensitivity, and cost. Enterprises should convert uncontrollable risks into controllable costs by choosing different types of security boundaries and defense technologies.

Tenant isolation is used to compensate for the multi-tenant isolation security risks brought about by the complexity of the interface. The complexity of the interface is positively correlated with the probability of vulnerabilities. The following table describes a simple method for evaluating interface complexity<sup><a href="#ref1">1</a></sup>.

| **Interface type** | **Typical input (example)** | **Typical process** | **Complexity level** 
|--|--|--|--|
| Arbitrary code execution environment | Arbitrary | Execution | High |
| Database client | SQL query | Database operation | High |
| Arbitrary file scanner | Arbitrary | Parsing | Medium |
| Binary data parsing | Protobuf | Parsing | Medium |
| Web crawler | JavaScript | Rendering | Medium |
| Port scanner | Metadata | Parsing | Low |
| Reverse proxy | Arbitrary | Proxy | Low |
| Queue message upload | Arbitrary | Proxy | Low |
| Data entry form | String | Parsing | Low |
| Bucket file upload | Arbitrary | Storage | Low |

For complex interfaces, such as components that support tenants to execute arbitrary code, it is recommended to choose a high isolation-level security boundary (such as containers based on lightweight virtual machine technology) to ensure the security of tenant data. For less complex tenant scenarios and interfaces, such as file parsing, data parsing, web page rendering, file upload, etc., technologies such as vArmor can be considered for hardening.

#### What Else Needs to Be Done

Since the isolation level of runc + vArmor is lower than that of hardware-virtualized containers (such as lightweight virtual machine containers like Kata Container), it cannot defend against all container escape vulnerabilities. Therefore, when using vArmor to harden multi-tenant applications, it is necessary to assume that advanced attackers may use vulnerabilities to escape to the host. The following security practices are recommended to increase the attack cost after an attacker escapes and detect attack behaviors in a timely manner.

* Tenant workloads should meet the Baseline or Restricted standards of the Pod Security Standard<sup><a href="#ref1">2</a></sup> and implement network micro-segmentation using technologies such as NetworkPolicy.
* Develop reasonable scheduling strategies to avoid scheduling different tenant workloads to the same node.
* Different tenants should use exclusive namespaces. Tenant workloads should be granted limited Kubernetes RBAC and IAM permissions based on the principle of least privilege, avoiding the grant of sensitive permissions. The list of sensitive RBAC permissions can refer to the whitepaper<sup><a href="#ref1">3</a></sup> published by Palo Alto Networks.
* Develop reasonable scheduling strategies to schedule system component workloads with sensitive RBAC and IAM permissions to a dedicated node pool, ensuring that there are no service accounts and user accounts that can be abused on the nodes where tenant workloads are located.
* Identity authentication and authorization should be enabled for the sensitive interfaces of system components to avoid unauthorized vulnerabilities.
* Introduce an intrusion detection system to conduct intrusion detection and defense at the host and Kubernetes contexts to detect and respond to intrusion behaviors in a timely manner.

### Core Business Hardening

#### Benefits of Hardening

Some strong isolation solutions based on hardware virtualization technology and user-space kernels (such as Kata, gVisor, etc.) have been introduced in the industry. However, their usage thresholds and costs are relatively high, making runc containers still the mainstream in most business scenarios and widely used. While enjoying the performance and convenience brought by runc containers, security problems such as weak container isolation also arise. For example, in recent years, vulnerabilities in the Linux kernel, runc components, and container runtime components have occurred frequently. New vulnerabilities can be used for container escape and other attacks at regular intervals. Many enterprises are also prone to introducing escape risks due to incorrect design and configuration during the design, development, and deployment of containerized applications.

The research report<sup><a href="#ref1">4</a></sup> released by Verizon shows that on average, enterprises need 55 days to fix 50% of critical vulnerabilities after patches are available.  And the vulnerability repair time for infrastructure may be even longer. And after a high-risk vulnerability is fully repaired, new vulnerabilities may emerge and wait to be fixed. During the vulnerability repair period, enterprises lack defensive measures other than intrusion detection.

#### Reasons for Using vArmor

vArmor has the following features, making it a choice for core business hardening:
* **Cloud-native**: It follows the Kubernetes operator design pattern, is close to the development and operation and maintenance habits of cloud-native applications, hardens containerized applications from a business perspective, and is easy to understand and get started with.
* **Flexibility**: The policy supports multiple operating modes (such as AlwaysAllow, RuntimeDefault, EnhanceProtect modes) and can be dynamically switched without restarting the workload. It supports three features: intercept, intercept and alarm, and alarm only without interception, which is helpful for policy debugging and security monitoring.
* **Out-of-the-box**: Based on ByteDance's practices in the field of container security, it provides a series of built-in rules. Users can choose to use them in policy objects as needed. vArmor will generate and manage AppArmor, BPF, and Seccomp Profiles in the Allow-by-Default mode according to the configuration of policy objects, reducing the requirement for professional knowledge.
* **Ease of use**: It provides a behavior modeling function, policy advisor tools, etc., to assist in policy formulation and reduce the usage threshold.

#### Common Usage Methods

The rich features of vArmor provide diverse choices for the formulation and operation of security policies. The following are some common usage methods:

* **Alarm-only without Interception Mode (Observation Mode)**: Configure the sandbox policy to the alarm-only without interception mode, collect alarm logs, and analyze the impact of the security policy on the target application.

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      # Audit the actions that violate the mandatory access control rules.
      # Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
      # It's disabled by default.
      auditViolations: true
      # Allow the actions that violate the mandatory access control rules.
      # Any detected violation will be allowed instead of being blocked and logged to the same log file 
      # as the auditViolations feature. You can utilize the feature to achieve some kind of observation mode.
      # It's diabled by default.
      allowViolations: true
```

* **Intercept and Alarm Mode**: After the sandbox policy is formulated, adjust it to run in the intercept and alarm mode, continuously collect alarm logs, implement mandatory access control on the target workload, and detect violations in a timely manner.

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      # Audit the actions that violate the mandatory access control rules.
      # Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
      # It's disabled by default.
      auditViolations: true
      # This is different from the observation mode. Set it to false, that is, illegal behaviors are not allowed. Intercept and record logs.
      allowViolations: false
```

* **Response to High-risk Vulnerabilities**: When high-risk vulnerabilities occur, analyze mitigation solutions based on the type of vulnerability or the vulnerability exploitation vector, update the sandbox policy (add built-in rules, custom rules), and defend before the vulnerability is repaired.

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      # The custom AppArmor rules:
      appArmorRawRules:
      - "deny /etc/shadow r,"
      # The custom BPF LSM rules:
      bpfRawRules:
        processes:
        - pattern: "**ping"
          permissions:
          - exec
        network:
          egresses:
          - ip: fdbd:dc01:ff:307:9329:268d:3a27:2ca7
          - ipBlock: 192.168.1.1/24 # 192.168.1.0 to 192.168.1.255
            port: 80
          sockets:
          - protocols:
            - "udp"
      # The custom Seccomp rules:
      syscallRawRules:
      # disallow chmod +x XXX, chmod 111 XXX, chmod 001 XXX, chmod 010 XXX...
      - names:
        - fchmodat
        action: SCMP_ACT_ERRNO
        args:
        - index: 2
          value: 0x40     # S_IXUSR
          valueTwo: 0x40
          op: SCMP_CMP_MASKED_EQ
        - index: 2
          value: 0x8      # S_IXGRP
          valueTwo: 0x8
          op: SCMP_CMP_MASKED_EQ
        - index: 2
          value: 1        # S_IXOTH
          valueTwo: 1
          op: SCMP_CMP_MASKED_EQ
```

* **Policy Impact Troubleshooting**: When users suspect that the sandbox policy affects the normal execution of the target application, the policy mode can be switched to the AlwaysAllow or RuntimeDefault mode for troubleshooting.

```bash
kubectl patch vcpol $POLICY_NAME --type='json' -p='[{"op": "replace", "path": "/spec/policy/mode", "value":"AlwaysAllow"}]'
```

* **Behavior Modeling Mode**: Use the experimental function - the [behavior modeling mode](../guides/policies_and_rules/policy_modes/behavior_modeling.md) to model the target application. After the modeling is completed, use the [policy advisor](../guides/policy_advisor.md) to generate a sandbox policy template.

```yaml
spec:
  policy:
    enforcer: AppArmorSeccomp
    mode: BehaviorModeling
    modelingOptions:
      # The duration in minutes to modeling
      duration: 30
```

### Privileged Container Hardening

#### Definition of Privileged Containers

Privileged containers usually refer to containers with `.securityContext.privileged=true`. Such containers are granted all capabilities and can access all devices and kernel interfaces of the host. **In this article, all containers with configurations that break isolation are referred to as "privileged containers"**, including but not limited to privileged containers, sensitive capabilities, sensitive mounts, shared namespaces, and sensitive RBAC permissions.

Many enterprises, due to historical issues, system design requirements, and insufficient security awareness, introduce "privileged containers" in their business workloads and system components of the production environment. The risky configurations of these containers can be easily exploited by attackers to achieve container escape, lateral movement, and other attacks. For example, in the BrokenSesame vulnerability exploitation chain disclosed by Wiz<sup><a href="#ref1">5</a></sup>, the risk designs and misconfigurations such as sharing PID ns between containers and the management container having privileges can be exploited by attackers for lateral movement and privilege escalation attacks.

#### Reducing Risks of Privileged Containers

Enterprises are recommended to first evaluate and remove the risky configurations that lead to "privileged containers" based on the principle of least privilege. If high risk configurations cannot be removed, consider eliminating the risks through refactoring. When the above measures cannot be implemented, it is recommended to choose security boundaries with different isolation levels to harden containers based on business scenarios, taking into account factors such as compliance, data sensitivity, and cost.

vArmor can be used as a supplement to harden before completely eliminating the security risks of "privileged containers". Users can use the [built-in rules](../guides/policies_and_rules/built_in_rules/index.md) and [custom rules](../guides/policies_and_rules/custom_rules.md) provided by vArmor to restrict the behavior of potential attackers, block known attack vectors, and increase the attack cost and the probability of intrusion detection. vArmor has built in three types of rules: "container hardening", "attack protection", and "vulnerability mitigation", and is constantly updated. In the "container hardening" type of rules, a series of rules are specifically built-in for the security risks of "privileged containers" to block some known attack vectors.

For example, in a container with the CAP_SYS_ADMIN capability, escaping the container by overwriting the host's core_pattern is a common attack method. As shown below, attackers can obtain write permissions to the host's core_pattern file by mounting new procfs, remounting procfs, moving the procfs mount point, etc.

```bash
# mount a new procfs
mkdir /tmp/proc
mount -t proc tmpproc /tmp/proc
echo "xxx" > /tmp/proc/sys/kernel/core_pattern

# bind mount a procfs
mount --bind /proc/sys /tmp/proc
mount -o remount,rw /tmp/proc /tmp/proc
echo "xxx" > /tmp/proc/sys/kernel/core_pattern
```

The built-in rule `disallow-mount-procfs` can block these exploitation vectors.

```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    hardeningRules:
    - disallow-mount-procfs
    # Privileged is used to identify whether the policy is for the privileged container.
    # If set to `nil` or `false`, the EnhanceProtect mode will build AppArmor or BPF profile on
    # top of the RuntimeDefault mode. Otherwise, it will build AppArmor or BPF profile on top of the AlwaysAllow mode.
    # Default is false.
    privileged: true
```

#### Assisting in the Deprivileging of Privileged Containers

There are often many "privileged containers" in the enterprise production environment. A large number of research reports and cases have clarified the hazards of using "privileged containers". However, enterprises may still find it difficult to deprivilege existing "privileged containers" and cannot grant new containers the necessary capabilities according to the principle of least privilege.

vArmor provides an experimental feature - the "BehaviorModeling mode". Users can create a security policy in this mode, collect and process the behaviors of the target workload within a specified duration, and conduct behavior modeling. After the modeling is completed, vArmor will generate an ArmorProfileModel object to save and export the behavior model of the target workload. When the behavior data is large, it will be cached in the data volume, and users can export it through the corresponding interface.

```yaml

spec:
  policy:
    enforcer: AppArmorSeccomp
    # Switching the mode from BehaviorModeling to others is prohibited, and vice versa.
    # You need recraete the policy to switch the mode from BehaviorModeling to DefenseInDepth.
    mode: BehaviorModeling
    modelingOptions:
      # The duration in minutes to modeling
      duration: 30
```

The behavior data includes the capabilities required by the target application, the processes executed, the files read and written, the syscalls invoked, etc. This information can be used to assist in deprivileging. Users can refer to the [usage instructions](../guides/policies_and_rules/policy_modes/behavior_modeling.md#basic-usage) for further information on how to use the behavior modeling function of vArmor. Currently, only the AppArmor and Seccomp enforcers support the behavior modeling function.

## Summary

As a cloud-native container sandbox system, vArmor provides effective solutions to the challenges in the writing and management of security policies in the current container security field. In the multi-tenant isolation scenario, although it cannot reach the isolation level of hardware-virtualized containers, by coordinating a series of security practices, it can reduce the risk of cross-tenant attacks. In terms of core business hardening, with its cloud-native, flexible, out-of-the-box, and easy-to-use features, it provides effective security protection measures for enterprises while they enjoy the performance and convenience of runc containers. For privileged containers, vArmor can not only harden through built-in and custom rules to block attack methods but also utilize the behavior modeling function to assist in deprivileging.

With its rich features and flexible application methods, vArmor provides comprehensive and practical protection for container security, helping enterprises balance the needs of security and business development in the cloud-native environment.

## References

1. [PEACH: A Tenant Isolation Framework for Cloud Applications](https://www.datocms-assets.com/75231/1671033753-peach_whitepaper_ver1-1.pdf)<a id="ref1"/>
2. [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)<a id="ref2"/>
3. [Kubernetes Privilege Escalation: Excessive Permissions in Popular Platforms](https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms)<a id="ref3"/>
4. [2024 Data Breach Investigations Report](https://www.verizon.com/business/resources/Te3/reports/2024-dbir-data-breach-investigations-report.pdf)<a id="ref4"/>
5. [#BrokenSesame: Accidental ‘write’ permissions to private registry allowed potential RCE to Alibaba Cloud Database Services](https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-r)<a id="ref5"/>
