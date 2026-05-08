---
slug: varmor-vuln-policy-generator
title: "vArmor 漏洞策略生成器：从漏洞披露到缓解策略的分钟级响应"
authors: [DannyWei]
tags: [VulnerabilityMitigation, AI, Skill, DirtyFrag, ContainerEscape]
date: 2026-05-08T00:00
---

内核漏洞层出不穷。每当一个能够导致容器逃逸的高危 CVE 被公开，安全团队都要经历一套熟悉的流程：阅读公告、研究 PoC、确定阻断点、编写缓解规则、验证不会影响业务、分阶段上线。即便各个环节都有 AI 辅助，整套流程跑下来仍然需要数小时，而且不同 CVE 之间大量工作是重复的。能不能用 AI Agent 把这个周期进一步压缩？

我们开发了 **vArmor 漏洞策略生成器**来压缩这个周期。它是一个 AI 驱动的 Skill，输入漏洞信息（CVE 编号、PoC 仓库、分析文章），输出针对特定漏洞的 vArmor 缓解规则——用户将其融合到已有策略中即可实施防护。本文介绍这个 Skill 的设计思路，以最近公开的 [Dirty Frag](https://github.com/V4bel/dirtyfrag) 漏洞为例进行演示，并讨论如何获得最佳使用效果。

<!--truncate-->

## 问题：手动分析无法规模化

每个新漏洞都需要相同的分析步骤：

1. 理解根因和利用机制
2. 识别哪些利用步骤可以在内核/网络/文件系统层面阻断
3. 评估每种阻断选项对业务的影响
4. 编写语法正确的 vArmor 策略 YAML
5. 规划分阶段上线方案（先观察再拦截）

这些工作重复性高、容易出错，而漏洞从披露到被实际利用的窗口期越来越短。我们需要一种方式来自动化这些结构化推理过程，同时保留人工对最终决策的把控。

## 漏洞策略生成器 Skill

这个 Skill 将我们的漏洞分析方法论编码为结构化 prompt，引导 LLM 完成完整的分析-生成流程：

### 工作流程

1. **信息收集** — 获取 CVE 详情、PoC 代码、相关分析文章
2. **根因分析** — 识别漏洞代码路径、所需系统调用、内核模块和权限
3. **可利用性评估** — 评估每个变体在容器环境中的实际威胁等级（不是所有变体都一样危险，后文详述）
4. **防御点分析** — 将每个利用步骤映射到 vArmor 可阻断点，权衡精准度与业务影响
5. **策略生成** — 产出多层级缓解策略，直接引用 vArmor 的 Go API 类型定义确保语法正确
6. **部署指引** — 提供观察-拦截分阶段上线方案

Skill 覆盖所有漏洞类型：内核 LPE、应用层 RCE（如 [IngressNightmare](https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/vulnerability_mitigation#ingress-nightmare-mitigation)）、容器运行时逃逸、供应链攻击等。

### 影响输出质量的因素

Skill 的实际效果取决于多个因素的共同作用：

- **Skill prompt 本身的质量** — 结构化的方法论和参考案例引导 LLM 的推理链路。我们在这上面做了大量迭代。
- **信息检索能力** — LLM 需要能够获取 PoC 源码、漏洞分析文章和 vArmor API 定义。能检索到的信息越多越准确，分析结果越好。
- **LLM 自身能力** — 这是一个高难度任务：多步技术推理、将内核内部机制与策略语法交叉引用、最终产出合法 YAML。SOTA 模型的表现明显优于小模型。可利用性评估的深度和生成策略的语法正确性，都直接取决于模型本身的推理能力。
- **人工审核** — Skill 产出的是*草稿*而非最终策略。安全工程师应当验证分析结论（尤其是业务影响评估），然后将规则融合到已有策略中再部署到生产环境。

建议使用最强的可用模型，并尽可能提供充分的上下文信息（PoC 代码、详细的分析文章）以获得最佳效果。

## 实战演示：缓解 Dirty Frag

接下来用 [Dirty Frag](https://github.com/V4bel/dirtyfrag) 漏洞来演示 Skill 的实际效果。这是一个有两个利用变体的 page-cache 污染漏洞。

### 漏洞简介

Dirty Frag 利用 Linux 内核网络子系统的逻辑缺陷，通过 `skb` fragment 引用实现对 page-cache 页面的原地写入。两个变体：

| 变体 | 机制 | 前置条件 |
|------|------|---------|
| **ESP** | IPsec ESP 变换对引用 page-cache 页面的 skb frag 执行原地加密 | `unshare(CLONE_NEWUSER\|CLONE_NEWNET)` 获取 `CAP_NET_ADMIN` |
| **RxRPC** | `rxkad_verify_packet_1` 对 skb frag 执行原地解密 | `af_rxrpc.ko` 模块加载 |

与 [Copy Fail (CVE-2026-31431)](https://copy.fail/) 类似，page cache 在宿主机范围内共享。非特权容器污染的 page-cache 页面可以被共享相同镜像层的特权 DaemonSet 执行——经典的容器逃逸路径。

### 变体可利用性评级（不是所有变体都一样危险）

Skill 强调的一点：不要平等对待所有变体。对于 Dirty Frag：

| 变体 | 前置条件可满足性 | 利用稳定性 | 实用性 | 防御优先级 |
|------|----------------|-----------|--------|-----------|
| ESP | **高** — unprivileged user ns 在主流发行版上默认可用 | 确定性 4 字节可控写入 | **高** | 必须防御 |
| RxRPC | **低** — 依赖 af_rxrpc.ko 模块加载 | 需要爆破（shellcode 注入理论需 N*2^56 次尝试） | **低** | 建议防御（零成本） |

ESP 变体是真正的威胁。RxRPC 在实际中基本停留在理论层面，但阻止 AF_RXRPC 对业务零影响，属于免费的保险，没有理由不做。

### 防御点分析

| 变体 | 利用步骤 | 阻断方式 | 精准度 | 业务影响 |
|------|---------|---------|--------|---------|
| ESP | `unshare(CLONE_NEWUSER)` | 阻止 user namespace 创建 | 高 | 极少数应用受影响 |
| ESP | `splice()` | 禁用 splice 系统调用 | 高 | **大量应用受影响**（nginx、kafka 等） |
| RxRPC | `socket(AF_RXRPC)` | 阻止 AF_RXRPC 套接字 | 高 | 无影响 |
| RxRPC | `add_key()` | 限制 keyring 操作 | 低 | 部分应用受影响 |

最优选择：阻止 user namespace 创建（ESP）+ 阻止 AF_RXRPC 套接字（RxRPC）。精准度最高，影响面最小。

### 生成的策略

```yaml
# 最小影响方案 — 覆盖 ESP + RxRPC 两个变体
apiVersion: crd.varmor.org/v1beta1
kind: VarmorClusterPolicy
metadata:
  name: dirty-frag-mitigation
spec:
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: your-workload
  policy:
    enforcer: AppArmorBPFSeccomp
    mode: EnhanceProtect
    enhanceProtect:
      # --- 阻断 ESP 变体 ---
      # 阻止 unshare(CLONE_NEWUSER)，切断 CAP_NET_ADMIN 来源
      hardeningRules:
        # For AppArmor/BPF enforcer
        - disallow-abuse-user-ns
        # For Seccomp enforcer
        - disallow-create-user-ns

      # --- 阻断 RxRPC 变体 ---
      # 阻止 AF_RXRPC 套接字创建（AFS 专用协议，业务零影响）

      # For AppArmor enforcer
      appArmorRawRules:
      - rules: |
          audit deny network rxrpc,

      # For BPF enforcer
      bpfRawRules:
        network:
          sockets:
          - qualifiers: ["audit", "deny"]
            domains: ["rxrpc"]

      # For Seccomp enforcer
      syscallRawRules:
      - names:
        - socket
        action: SCMP_ACT_ERRNO
        args:
        - index: 0
          value: 33
          op: SCMP_CMP_EQ
```

> **注意**：请根据实际部署的 enforcer 选择对应规则，无需全部使用。

### 分阶段部署

**阶段一 — 观察**（仅审计，不拦截）：

```yaml
spec:
  policy:
    enforcer: AppArmorBPF
    mode: EnhanceProtect
    enhanceProtect:
      auditViolations: true
      allowViolations: true
      hardeningRules:
        - disallow-abuse-user-ns
      appArmorRawRules:
      - rules: |
          audit network rxrpc,
      bpfRawRules:
        network:
          sockets:
          - qualifiers: ["audit"]
            domains: ["rxrpc"]
```

观察期间检查 `/var/log/varmor/violations.log`，确认没有业务触发的违规记录。

**阶段二 — 拦截**（确认无冲突后切换）：

```yaml
spec:
  policy:
    enforcer: AppArmorBPF
    mode: EnhanceProtect
    enhanceProtect:
      auditViolations: true
      hardeningRules:
        - disallow-abuse-user-ns
      appArmorRawRules:
      - rules: |
          audit deny network rxrpc,
      bpfRawRules:
        network:
          sockets:
          - qualifiers: ["audit", "deny"]
            domains: ["rxrpc"]
```

### 与 Copy Fail 的关系

[Copy Fail (CVE-2026-31431)](https://copy.fail/) 使用 AF_ALG 套接字实现 page-cache 污染。它的缓解规则（`copy-fail-mitigation` 内置规则）阻止 AF_ALG，**不能**防御 Dirty Frag。不同的内核子系统，不同的阻断规则：

- Copy Fail: AF_ALG → 阻止 AF_ALG
- Dirty Frag ESP: user namespace + xfrm → 阻止 user ns
- Dirty Frag RxRPC: AF_RXRPC + rxkad → 阻止 AF_RXRPC

### 其他缓解建议

- **禁用内核模块**：如果相关模块不是静态编译到内核中的，可以通过 modprobe 规则禁用 `esp4`、`esp6` 和 `rxrpc`，从根本上消除攻击面。先检查 `grep -E "CONFIG_INET_ESP|CONFIG_INET6_ESP|CONFIG_AF_RXRPC" /boot/config-$(uname -r)`，然后 `printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf`
- **Sysctl 加固**：设置 `kernel.unprivileged_userns_clone=0` 或 `user.max_user_namespaces=0`，在内核层面禁用非特权 user namespace 创建（消除 ESP 变体）
- **默认 seccomp profile**：为容器配置 Kubernetes 默认 seccomp profile（`RuntimeDefault`），默认禁用 `unshare` 系统调用
- **vArmor Seccomp 规则**：使用 Seccomp enforcer 的内置规则 `disallow-create-user-ns` 阻止 `unshare` 系统调用——注意 Seccomp 规则需要重启容器才能生效
- **镜像层隔离**：为特权 DaemonSet 使用独立基础镜像，打断 page-cache 逃逸链路

## 获取 Skill

Skill 提供中英文两个版本：

- [英文版](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_en.md)
- [中文版](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_zh.md)

将 SKILL.md 作为系统上下文加载到任何支持自定义 prompt 的 AI 助手中（Claude、GPT、Gemini 等），然后提供漏洞信息即可：

```
用户：刚看到一个新漏洞 Dirty Frag，https://github.com/V4bel/dirtyfrag
     帮我看看能不能用 vArmor 缓解，生成防护策略
```

Skill 会自动获取仓库内容、识别两个变体、引用 vArmor API 类型定义确保语法正确，产出带有业务影响评估和分阶段部署指引的缓解策略。

## 结论

vArmor 漏洞策略生成器将重复性的 CVE 分析-规则编写流程转化为结构化的半自动工作流。它不会取代安全工程师——最终的部署决策仍然需要人工判断——但它把"新 CVE 出来了"到"缓解规则准备就绪"的周期从数小时压缩到数分钟。

配合 vArmor 的观察-拦截分阶段部署模型，团队可以更快地完成从漏洞披露到生产防护的全流程。

## 参考链接

- [Dirty Frag — GitHub 仓库](https://github.com/V4bel/dirtyfrag)
- [Copy Fail (CVE-2026-31431)](https://copy.fail/)
- [Copy Fail — Kubernetes 容器逃逸 PoC](https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC)
- [vArmor 漏洞缓解规则](https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/vulnerability_mitigation)
- [vArmor 策略生成器 Skill](https://github.com/bytedance/vArmor/tree/main/skills/vuln-policy-generator)
