---
slug: /practices
sidebar_position: 4
---

import ThemeImage from '@site/src/components/ThemeImage';

# 应用实践

## 简介

本文将阐述我们推出 vArmor 项目的目的，解析其在容器安全策略管理中的挑战与解决方案。然后从技术角度出发，介绍其在多租户隔离、核心业务加固与特权容器加固等场景的应用，展示如何凭借项目的技术特性来解决特定问题，从而实现技术与业务目标，助力企业构建云原生环境下的安全防线。

## 为什么推出 vArmor

容器运行时组件和 Kubernetes 早已增加了对 LSM、Seccomp 的支持，其中 Seccomp 在 Kubernetes v1.19 GA，AppArmor LSM 在 Kubernetes v1.30 GA。用户可以自行编写和管理 AppArmor、SELinux、Seccomp Profiles，并在工作负载中配置安全策略对其进行加固。几乎所有的容器运行时组件都附带了默认的 AppArmor 和 Seccomp 安全策略，但默认的 Seccomp 策略需要显式设置才会为容器开启，而默认的 AppArmor 策略需要操作系统支持才会为容器自动开启。

充分利用 Linux 系统的安全机制可以有效加固容器。例如通过 LSM、Seccomp 等技术对容器进程进行强制访问控制，可以减少内核攻击面、增加容器逃逸或横向移动攻击的难度与成本。它们的基本原理如下图所示。

<ThemeImage 
  lightSrc="/img/lsm.svg" 
  darkSrc="/img/lsm-dark.svg" 
  alt="lsm" 
/>
<br /><br />

然而，编写和管理安全策略则面临诸多挑战：
* 容器运行时组件的默认安全策略存在局限性，无法防御某些漏洞、错误配置风险，也不能限制攻击者在容器内的渗透行为。
* 构建 AppArmor、Seccomp、SELinux Profile 需要专业知识。
* 为复杂且快速迭代的容器化应用制定健壮的安全策略（尤其是 Deny-by-Default 模式的策略）难度较大。
* AppArmor 或 SELinux LSM 依赖操作系统发行版，存在一定局限性。
* 在 Kubernetes 环境中，自动化管理和应用不同的安全策略比较复杂。

为了解决这些问题，vArmor 应运而生。它提供了多种策略模式、内置规则和配置选项，vArmor 会根据策略对象的定义，管理安全策略（AppArmor Profile、BPF Profile、Seccomp Profile）对不同工作负载的容器进行加固。vArmor 还基于 BPF 和 Audit 技术实现了行为建模功能，可以对不同应用进行行为采集并生成行为模型，从而辅助构建安全策略。

例如，用户可以按需配置策略对象，实现违规拦截、拦截并告警、只告警不拦截三种效果，并使用内置规则和自定义规则动态更新策略对象，从而满足不同应用场景的需要。下面我们将用几个实际应用场景来展示 vArmor 如何助力企业提升云原生环境中的容器安全防护能力。

## vArmor 的应用场景

### 多租户隔离

#### 多租户应用的风险

现代 SaaS 应用程序大多采用多租户模式，严重的漏洞及相应的利用链，极有可能致使恶意用户得以访问其他租户的数据。随着大语言模型时代来临，云服务的使用量还会进一步增长。因此，构建此类服务的人员更需关注多租户隔离风险并采取防范举措，以降低跨租户攻击的风险。

下图是 Wiz 在 PEACH 框架中描绘的一个典型跨租户攻击序列<sup><a href="#ref1">[1]</a></sup>：

![image](../img/attack-sequence.png)

大量案例表明，跨租户漏洞、漏洞利用链的根因主要包括：
* 用户接口复杂度较高，接口中的无害 bugs、features 加剧风险
* 多租户共享组件实现不当。
* 多租户独占组件安全边界实现不当。

针对这些问题，可采取以下缓解措施：
* 减少用户接口复杂度
* 将共享组件转变成租户独占组件
* 提升租户独占组件的隔离性

#### 如何选择加固方案

Wiz 在 PEACH 框架中指出，针对多租户应用，应根据安全建模结果，综合合规、数据敏感度、成本等因素选择租户隔离技术方案。企业可以通过选择不同类型的安全边界和防御技术，将不可控风险转化为可控成本。

租户隔离用于弥补由于接口的复杂性而带来的多租户隔离安全风险。而接口复杂度则与漏洞出现概率正相关，下表描述了接口复杂度的简单评估方法<sup><a href="#ref1">[1]</a></sup>。

| **接口类型** | **典型输入形式（样例）** | **典型处理方式** | **复杂度** 
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

因此，对于复杂接口（如支持租户执行任意代码的组件），建议选择高隔离等级的安全边界来保障租户数据安全，例如基于轻量级虚拟机技术的容器。对于不复杂的租户场景和接口，如文件解析、数据解析、网页渲染、文件上传等，可考虑使用 vArmor 等技术方案进行加固。

#### 还需要做什么

由于 runc + vArmor 的隔离等级不及硬件虚拟化容器（如 Kata Container 等轻量级虚拟机容器），因而无法防御所有容器逃逸漏洞。因此，在使用 vArmor 加固多租户应用时，需假设高级攻击者可能会利用漏洞逃逸到宿主机。我们建议您配合以下安全实践，来增加攻击者逃逸后进一步攻击的难度和成本，并及时发现攻击行为。

* 租户负载应满足 Pod Security Standard 的 Baseline 或 Restricted 标准<sup><a href="#ref2">[2]</a></sup>，并使用 NetworkPolicy 等技术实施网络微隔离。
* 制定合理的调度策略，避免不同租户负载调度到同一个节点。
* 不同租户使用独占命名空间，以最小权限原则授予租户负载有限的 Kubernetes RBAC 和 IAM 权限，避免授予敏感权限。敏感 RBAC 权限列表可参考 Palo Alto Networks 发布的白皮书<sup><a href="#ref3">[3]</a></sup>。
* 制定合理的调度策略，将具有敏感 Kubernetes RBAC 和 IAM 权限的系统组件负载调度到专用节点池，确保租户负载所在节点不存在可被滥用的服务账号和用户账号。
* 系统组件的敏感接口应开启身份认证和鉴权，避免未授权漏洞。
* 引入入侵检测系统，在主机、Kubernetes 层面进行入侵检测和防御，及时发现并响应入侵行为。

### 核心业务加固

#### 加固的收益

虽然业内已经推出了一些基于硬件虚拟化技术和用户态内核的强隔离方案（例如 Kata、gVisor 等），但由于其技术门槛和成本较高，使得 runc 容器仍将是大部分业务场景的主流。用户在享受 runc 容器带来的性能与便捷时，也面临着诸如容器隔离性较弱的安全问题。例如近年来 Linux 内核、runc 组件、容器运行时组件的漏洞频发，每隔一段时间就会有新的漏洞可被用于容器逃逸等攻击；许多企业在容器化应用设计、开发、部署时，也易因错误设计和配置引入逃逸风险。

Verizon 发布的研究报告<sup><a href="#ref4">[4]</a></sup>表明，企业在补丁可用后平均需 55 天才能解决 50% 的关键漏洞，而影响基础设施的漏洞修复时间可能更长。当某个高危漏洞被全量修复后，可能又有新的漏洞出现并等待修复。在漏洞修复期间，企业往往缺乏除了入侵检测以外的防御措施。

#### 使用 vArmor 的理由

vArmor 的以下特性，使其成为加固核心业务的选择：

* **云原生**：遵循 Kubernetes Operator 设计模式，贴近云原生应用开发和运维习惯，从业务视角加固容器化应用，因此易于理解和上手。
* **灵活性**：策略支持多种运行模式（例如 AlwaysAllow、RuntimeDefault、EnhanceProtect 模式），可动态切换且无需重启工作负载。支持拦截、拦截并告警、仅告警不拦截三种特性，有助于策略调试和安全监控。
* **开箱即用**：基于字节跳动在容器安全领域的攻防实践，提供了一系列内置规则，用户可按需在策略对象中选择使用。vArmor 会根据策略对象的配置，生成和管理 Allow-by-Default 模式的 AppArmor、BPF、Seccomp Profile，降低了对专业知识的要求。
* **易用性**：提供了行为建模功能、策略顾问工具，从而辅助策略制定，进一步降低了使用门槛。

#### 常见用法

vArmor 丰富的特性为安全策略的制定和运营提供了多样的选择，以下是一些常见的使用方式：
* **仅告警不拦截模式（观察模式）**：将沙箱策略配置为仅告警不拦截模式，通过采集告警日志来分析安全策略对目标应用的影响。

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      # AuditViolations determines whether to audit the actions that violate the mandatory access control rules. Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
      # It's disabled by default.
      auditViolations: true
      # AllowViolations determines whether to allow the actions that are against the mandatory access control rules.
      # It's disabled by default.
      allowViolations: true
```

* **拦截并告警模式**：沙箱策略制定完成后，可调整为拦截并告警模式运行，并持续采集告警日志。从而实现对目标工作负载的强制访问控制，并及时发现违规行为。

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      # AuditViolations determines whether to audit the actions that violate the mandatory access control rules. Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
      # It's disabled by default.
      auditViolations: true
```

* **高危漏洞应对**：当出现高危漏洞时，您可以基于漏洞类型或利用向量分析对应的缓解方案，并通过更新策略对象（添加内置规则、自定义规则），在漏洞修复前进行防御。

```yaml
spec:
  policy:
    enforcer: BPF
    mode: EnhanceProtect
    enhanceProtect:
      # The custom AppArmor rules:
      appArmorRawRules:
      - rules: |
          audit deny /etc/hosts r,
          audit deny /etc/shadow r,
      - rules: "audit deny /etc/hostname r,"
        targets:
        - "/bin/bash"
      # The custom BPF LSM rules:
      bpfRawRules:
        processes:
        - pattern: "**ping"
          permissions:
          - exec
        network:
          egresses:
          - ip: fdbd:dc01:ff:307:9329:268d:3a27:2ca7
          - ipBlock: 192.168.1.1/24
            port: 80
          sockets:
          - protocols:
            - "udp"
      # The custom Seccomp rules:
      syscallRawRules:
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

* **策略影响排查**：当用户怀疑沙箱策略影响目标应用正常执行时，可将策略模式动态切换为 AlwaysAllow、RuntimeDefault 模式排查（注：已启动容器的 Seccomp Profile 不支持动态更新）。

```bash
kubectl patch vcpol $POLICY_NAME --type='json' -p='[{"op": "replace", "path": "/spec/policy/mode", "value":"AlwaysAllow"}]'
```

* **行为建模模式**：可以使用实验功能 —— [行为建模模式](../guides/policies_and_rules/policy_modes/behavior_modeling.md)，对目标应用进行建模。建模完成后使用[策略顾问](../guides/policy_advisor.md)来生成沙箱策略模版，辅助沙箱策略的制定。

```yaml
spec:
  policy:
    enforcer: AppArmorSeccomp
    mode: BehaviorModeling
    modelingOptions:
      # The duration in minutes to modeling
      duration: 30
```

### 特权容器加固

#### 特权容器的定义

特权容器通常指包含 `.securityContext.privileged=true` 设置的容器，此类容器会被授予全部 capabilities，可访问宿主机所有设备和内核接口。**本文将所有拥有打破隔离性配置的容器称为 “特权容器”**，包括但不限于 privileged container、sensitive capabilities、sensitive mounts、shared namespaces、sensitive RBAC permissions。

许多企业因历史遗留问题、系统设计需求、安全意识不足等原因，在生产环境的业务负载和系统组件中引入了 “特权容器”。然而，这些容器的风险配置容易被攻击者利用，从而导致容器逃逸、横向移动等攻击。例如在 Wiz 披露的 BrokenSesame<sup><a href="#ref5">[5]</a></sup> 漏洞利用链中，容器间共享 PID ns、管理容器具有特权等风险设计和错误配置，就可被攻击者利用进行横向移动和权限提升攻击。


#### 降低特权容器的风险

我们建议企业优先以最小权限原则评估并移除导致 “特权容器” 的风险配置。并在无法移除时，使用强隔离级别的安全边界来加固容器。

vArmor 可以作为补充，在彻底消除 “特权容器” 安全风险前进行加固。用户可利用 vArmor 提供的[内置规则](../guides/policies_and_rules/built_in_rules/index.md)和[自定义规则](../guides/policies_and_rules/custom_rules.md)来限制潜在攻击者的行为，阻断已知的攻击手法，提升攻击成本和入侵检测几率。vArmor 内置了 “容器加固”、“攻击防护” 和 “漏洞缓解” 三类规则，并且还在不断更新。在 “容器加固” 类规则中，vArmor 专门为 “特权容器” 安全风险内置了一系列规则，可用于阻断一些已知的攻击手法。

例如，在拥有 CAP_SYS_ADMIN capability 的容器中，通过改写宿主机的 core_pattern 来逃逸容器是常见的攻击手法。如下所示，攻击者可以通过挂载新的 procfs、重新挂载 procfs、移动 procfs 挂载点等方式获取宿主机 core_pattern 文件的写权限。

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

使用 vArmor 的内置规则 `disallow-mount-procfs` 可阻断此利用向量。

```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    hardeningRules:
    - disallow-mount-procfs
    privileged: true
```

#### 辅助特权容器降权

企业生产环境中往往存在许多“特权容器”，虽然大量研究报告和案例都阐明过使用“特权容器”的危害，但企业可能仍然难以对已有的“特权容器”进行降权，也无法按照最小权限原则授予新增容器必要的 capabilities。

vArmor 提供了实验功能 —— 行为建模模式。用户可以创建此模式的安全策略，并在指定时间范围内收集和处理目标工作负载的行为。建模结束后，vArmor 会生成一个 ArmorProfileModel 对象，用来保存目标工作负载的行为模型。当行为数据较多时，行为数据会被缓存在数据卷中，用户可以通过对应接口将其导出。

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

行为数据包括目标应用所需的 capability、执行的进程、读写的文件、调用的 syscall 等，用户可以利用这些信息来辅助降权。请参考[使用说明](../guides/policies_and_rules/policy_modes/behavior_modeling.md#使用说明)进一步了解如何使用 vArmor 的行为建模功能（注：当前仅 AppArmor 和 Seccomp enforcer 支持行为建模功能）。


## 总结

vArmor 针对当前容器安全领域在安全策略编写与管理方面的难题，提供了有效的解决方案。在多租户隔离场景下，尽管无法达到硬件虚拟化容器的隔离级别，但通过配合一系列安全实践，可降低跨租户攻击风险；在核心业务加固方面，vArmor 凭借云原生、灵活、开箱即用和易用等特性，为企业在享受 runc 容器性能与便捷的同时，提供了有效的安全防护手段；对于特权容器，vArmor 既能通过内置和自定义规则加固，阻断常见攻击手法，又能利用行为建模功能辅助降权。

vArmor 以其丰富的特性和灵活的应用方式，为容器安全提供了全面且实用的保障，助力企业在云原生环境中平衡安全与业务发展的需求。

## 引用

1. [PEACH: A Tenant Isolation Framework for Cloud Applications](https://www.datocms-assets.com/75231/1671033753-peach_whitepaper_ver1-1.pdf)<a id="ref1"/>
2. [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)<a id="ref2"/>
3. [Kubernetes Privilege Escalation: Excessive Permissions in Popular Platforms](https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms)<a id="ref3"/>
4. [2024 Data Breach Investigations Report](https://www.verizon.com/business/resources/Te3/reports/2024-dbir-data-breach-investigations-report.pdf)<a id="ref4"/>
5. [#BrokenSesame: Accidental ‘write’ permissions to private registry allowed potential RCE to Alibaba Cloud Database Services](https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-r)<a id="ref5"/>
