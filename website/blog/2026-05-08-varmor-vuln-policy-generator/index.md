---
slug: varmor-vuln-policy-generator
title: "Introducing the vArmor Vulnerability Policy Generator: From CVE to Mitigation in Minutes"
authors: [DannyWei]
tags: [VulnerabilityMitigation, AI, Skill, DirtyFrag, ContainerEscape]
date: 2026-05-08T00:00
---

New kernel vulnerabilities keep coming. When a critical CVE drops — especially one that enables container escape — security teams face a familiar scramble: read the advisory, study the PoC, figure out what to block, write mitigation rules, validate they won't break production, then roll them out. Even with AI assistance for individual steps, the end-to-end cycle still takes hours — and the work is largely repetitive across different CVEs. Can we use an AI Agent to compress this further?

We built the **vArmor Vulnerability Policy Generator** to do exactly that. It's an AI-powered Skill that takes vulnerability information (CVE ID, PoC repo, write-up) as input and produces vArmor mitigation rules targeting the specific vulnerability — ready for you to integrate into your existing policies and deploy. In this post, we walk through the Skill's design, demonstrate it against the recently disclosed [Dirty Frag](https://github.com/V4bel/dirtyfrag) vulnerability, and discuss how to get the most out of it.

<!--truncate-->

## The Problem: Manual Analysis Doesn't Scale

Every new vulnerability requires the same analytical steps:

1. Understand the root cause and exploitation mechanism
2. Identify which exploit steps can be blocked at the kernel/network/filesystem level
3. Evaluate business impact of each blocking option
4. Write syntactically correct vArmor policy YAML
5. Plan phased rollout (observe first, then enforce)

This is repetitive, error-prone work — and the window between disclosure and active exploitation keeps shrinking. We needed a way to automate the structured reasoning while keeping a human in the loop for final decisions.

## The Vulnerability Policy Generator Skill

The Skill encodes our vulnerability analysis methodology into a structured prompt that guides any capable LLM through the full workflow:

### Workflow

1. **Information gathering** — Fetch CVE details, PoC code, and related write-ups
2. **Root cause analysis** — Identify the vulnerable code path, required syscalls, kernel modules, and privileges
3. **Exploitability assessment** — Rate each variant's real-world threat level in container environments (not all variants are equal — more on this below)
4. **Defense point analysis** — Map every exploit step to potential vArmor blocking points, evaluating precision vs. business impact
5. **Policy generation** — Produce multi-tier mitigation policies with correct syntax (referencing vArmor's Go API type definitions directly)
6. **Deployment guidance** — Provide observe-then-enforce rollout instructions

The Skill covers all vulnerability types: kernel LPE, application RCE (like [IngressNightmare](https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/vulnerability_mitigation#ingress-nightmare-mitigation)), container runtime escapes, supply chain attacks, and more.

### What Affects Output Quality

The Skill's effectiveness depends on several factors working together:

- **Skill prompt quality** — The structured methodology and reference cases guide the LLM's reasoning chain. We've iterated on this extensively.
- **Information retrieval** — The LLM needs access to PoC source code, vulnerability write-ups, and vArmor API definitions. Better retrieval yields better analysis.
- **LLM capability** — This is a demanding task: multi-step technical reasoning, cross-referencing kernel internals with policy syntax, and producing valid YAML. SOTA models perform significantly better than smaller models. The quality of the exploitability assessment and the syntactic correctness of generated policies are directly tied to model capability.
- **Human review** — The Skill generates *drafts*, not final policies. Security engineers should validate the analysis, especially the business impact assessment, before integrating the rules into existing policies and deploying to production.

We recommend using the strongest available model and providing as much context (PoC code, detailed write-ups) as possible for best results.

## Demo: Mitigating Dirty Frag

To show the Skill in action, let's walk through the [Dirty Frag](https://github.com/V4bel/dirtyfrag) vulnerability — a page-cache corruption primitive with two exploitation variants.

### Quick Background

Dirty Frag exploits logic flaws in the Linux kernel's network subsystem to achieve in-place writes to page-cache pages through `skb` fragment references. It has two variants:

| Variant | Mechanism | Prerequisites |
|---------|-----------|---------------|
| **ESP** | IPsec ESP transform encrypts skb frags referencing page-cache pages in-place | `unshare(CLONE_NEWUSER\|CLONE_NEWNET)` for `CAP_NET_ADMIN` |
| **RxRPC** | `rxkad_verify_packet_1` decrypts skb frags in-place | `af_rxrpc.ko` module loaded |

Like [Copy Fail (CVE-2026-31431)](https://copy.fail/), the page cache is shared host-wide. A corrupted page-cache page from an unprivileged container can be executed by a privileged DaemonSet sharing the same image layer — classic container escape.

### Per-Variant Exploitability (Not All Variants Are Equal)

One thing the Skill emphasizes: don't treat all variants equally. For Dirty Frag:

| Variant | Prerequisite Satisfiability | Exploitation Stability | Practicality | Defense Priority |
|---------|---------------------------|----------------------|--------------|-----------------|
| ESP | **High** — unprivileged user namespaces available by default | Deterministic 4-byte controlled write | **High** | Must defend |
| RxRPC | **Low** — depends on `af_rxrpc.ko` being loaded | Brute-force required (N*2^56 attempts for shellcode) | **Low** | Recommended (zero-cost) |

The ESP variant is the real threat. RxRPC is mostly theoretical in practice, but since blocking AF_RXRPC has zero business impact, we defend against it anyway — it's free insurance.

### Defense Point Analysis

| Variant | Exploit Step | Block Method | Precision | Business Impact |
|---------|-------------|--------------|-----------|-----------------|
| ESP | `unshare(CLONE_NEWUSER)` | Block user namespace creation | High | Very few apps affected |
| ESP | `splice()` | Disable splice syscall | High | **Many apps affected** (nginx, kafka, etc.) |
| RxRPC | `socket(AF_RXRPC)` | Block AF_RXRPC socket | High | No impact |
| RxRPC | `add_key()` | Restrict keyring ops | Low | Some apps affected |

Optimal choice: block user namespace creation (ESP) + block AF_RXRPC socket (RxRPC). Maximum precision, minimum blast radius.

### Generated Policy

```yaml
# Minimal Impact — Covers both ESP and RxRPC variants
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
      # --- Block ESP variant ---
      # Blocks unshare(CLONE_NEWUSER), cutting off the CAP_NET_ADMIN source
      hardeningRules:
        # For AppArmor/BPF enforcer
        - disallow-abuse-user-ns
        # For Seccomp enforcer
        - disallow-create-user-ns

      # --- Block RxRPC variant ---
      # Blocks AF_RXRPC socket creation (AFS-specific, zero business impact)

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

> **Note**: Select rules matching your deployed enforcer — you don't need all of them.

### Phased Deployment

**Phase 1 — Observe** (audit only, no blocking):

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

Monitor `/var/log/varmor/violations.log` for any business-triggered violations during the observation period.

**Phase 2 — Enforce** (after confirming no conflicts):

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

### Relationship with Copy Fail

[Copy Fail (CVE-2026-31431)](https://copy.fail/) uses AF_ALG sockets for page-cache corruption. Its mitigation (`copy-fail-mitigation` built-in rule) blocks AF_ALG — this does **NOT** protect against Dirty Frag. Different kernel subsystems, different blocking rules:

- Copy Fail: AF_ALG → block AF_ALG
- Dirty Frag ESP: user namespace + xfrm → block user ns
- Dirty Frag RxRPC: AF_RXRPC + rxkad → block AF_RXRPC

### Additional Recommendations

- **Kernel upgrade**: Apply the upstream patch when available
- **Module blacklist**: Add `af_rxrpc` to the kernel module blacklist (eliminates RxRPC variant entirely)
- **Sysctl hardening**: `kernel.unprivileged_userns_clone=0` where supported (eliminates ESP variant)
- **Image layer isolation**: Use separate base images for privileged DaemonSets to break the page-cache escape chain

## Getting the Skill

The Skill is available in both English and Chinese:

- [English Version](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_en.md)
- [Chinese Version](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_zh.md)

Load the SKILL.md file as system context in any AI assistant that supports custom prompts (Claude, GPT, Gemini, etc.), then provide vulnerability information and ask for a vArmor mitigation policy:

```
User: New vuln just dropped - Dirty Frag (https://github.com/V4bel/dirtyfrag).
      Can vArmor mitigate it? Generate a protection policy.
```

The Skill will automatically fetch the repo, identify both variants, reference vArmor API type definitions for correct syntax, and produce policies with business impact assessment and phased deployment guidance.

## Conclusion

The vArmor Vulnerability Policy Generator turns the repetitive CVE-to-rule cycle into a structured, semi-automated workflow. It won't replace security engineers — you still need human judgment for final deployment decisions — but it reduces the time from "new CVE dropped" to "mitigation rules ready for review" from hours to minutes.

Combined with vArmor's observe-then-enforce deployment model, teams can go from vulnerability disclosure to production protection much faster than before.

## References

- [Dirty Frag — GitHub Repository](https://github.com/V4bel/dirtyfrag)
- [Copy Fail (CVE-2026-31431)](https://copy.fail/)
- [Copy Fail — Kubernetes Container Escape PoC](https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC)
- [vArmor Vulnerability Mitigation Rules](https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/vulnerability_mitigation)
- [vArmor Policy Generator Skill](https://github.com/bytedance/vArmor/tree/main/skills/vuln-policy-generator)
