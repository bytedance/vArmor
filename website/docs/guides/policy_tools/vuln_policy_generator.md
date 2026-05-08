---
slug: /guides/policy_tools/vuln_policy_generator
sidebar_position: 2
description: Generate vulnerability mitigation rules with an AI-powered Skill.
---

# Vulnerability Policy Generator

The Vulnerability Policy Generator is an AI Skill that automates the analysis of security vulnerabilities and generates vArmor mitigation rules. Given a CVE ID, PoC repository, or vulnerability write-up, it produces rules that you can integrate into your existing vArmor policies.

## What It Does

The Skill guides an LLM through a structured analysis workflow:

1. **Information gathering** — Fetches CVE details, PoC code, and related write-ups
2. **Root cause analysis** — Identifies the vulnerable code path, required syscalls, kernel modules, and privileges
3. **Exploitability assessment** — Rates each variant's real-world threat level in container environments
4. **Defense point analysis** — Maps every exploit step to potential vArmor blocking points, evaluating precision vs. business impact
5. **Rule generation** — Produces mitigation rules with correct syntax (referencing vArmor API type definitions)
6. **Deployment guidance** — Provides observe-then-enforce phased rollout instructions

## Supported Vulnerability Types

| Type | Examples | vArmor Defense Dimension |
|------|----------|--------------------------|
| Kernel LPE / Container Escape | Dirty Pipe, Copy Fail, Dirty Frag | Syscall restriction, socket protocol blocking, namespace restriction |
| Application RCE / Cluster Takeover | IngressNightmare (CVE-2025-1974) | Network access control (restrict access to sensitive Services/ports) |
| Container Runtime Escape | CVE-2019-5736 (runc) | File write restriction |
| Arbitrary File Read/Write | Various web application vulns | File access control |
| Credential Theft | ServiceAccount token abuse | File read restriction, network egress restriction |
| Supply Chain | Log4Shell, etc. | Network egress restriction, process execution restriction |

## Usage

### Step 1: Get the Skill

Download the SKILL.md file from the vArmor repository:

- [English Version](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_en.md)
- [Chinese Version](https://github.com/bytedance/vArmor/blob/main/skills/vuln-policy-generator/SKILL_zh.md)

### Step 2: Load into an AI Assistant

Load the SKILL.md file as system context in any AI assistant that supports custom prompts or skills (Claude, GPT, Gemini, etc.).

### Step 3: Provide Vulnerability Information

Give the AI assistant vulnerability details and ask it to generate vArmor mitigation rules:

```
User: New vuln just dropped - Dirty Frag (https://github.com/V4bel/dirtyfrag).
      Can vArmor mitigate it? Generate protection rules.
```

### Step 4: Review and Integrate

The Skill produces a vulnerability analysis report and mitigation rules. Review the output — especially the business impact assessment — then integrate the rules into your existing VarmorPolicy or VarmorClusterPolicy.

## Factors Affecting Output Quality

- **LLM capability** — This is a demanding task requiring multi-step technical reasoning and valid YAML generation. SOTA models produce significantly better results than smaller models.
- **Information retrieval** — Better results when the LLM can access PoC source code, detailed write-ups, and vArmor API definitions.
- **Skill prompt quality** — The structured methodology and reference cases guide the LLM's reasoning chain.
- **Human review** — The Skill generates drafts, not final policies. Always validate before deploying to production.

## Example Output

See the [blog post](https://www.varmor.org/blog/varmor-vuln-policy-generator) for a complete walkthrough using the Dirty Frag vulnerability, including the generated rules and phased deployment instructions.

## Relationship with Policy Advisor

| | Policy Advisor | Vulnerability Policy Generator |
|---|---|---|
| **Form** | Python CLI tool | AI Skill (prompt file) |
| **Input** | Application features, capabilities, behavior data | Vulnerability information (CVE, PoC) |
| **Output** | General hardening policy template | Mitigation rules for a specific vulnerability |
| **Question answered** | "What protections should I apply to this workload?" | "How do I defend against this new CVE?" |

Both tools are complementary. Policy Advisor generates baseline hardening policies; Vulnerability Policy Generator adds targeted mitigation rules when new threats emerge.
