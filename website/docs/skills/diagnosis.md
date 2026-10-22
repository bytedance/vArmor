---
slug: /guides/skills/diagnosis
sidebar_position: 1
description: Automatically diagnose vArmor policy and component issues and get recommendations for resolving them.
---

# Automated Diagnosis

The Automated Diagnosis skill (`varmor-diagnosis`) automates the investigation of policy and component issues. Describe symptoms such as an ineffective policy, unexpected permission errors, or an unhealthy component. The assistant selects relevant checks, correlates configuration, status, events, and logs, and explains the findings and recommended next steps.

## What it helps you do

- Automatically check policy configuration, target matching, injection, and enforcement to investigate why protection is ineffective.
- Automatically inspect vArmor component health and relevant events and logs to help locate component failures.
- Correlate application failures with protection rules, including node support, BehaviorModeling, and NetworkProxy issues.

Diagnosis is read-only. The assistant provides findings and recommendations without changing policies, restarting workloads, or modifying nodes.

## Before you begin

Install the complete `skills/varmor-diagnosis/` directory as described in the [Skills overview](index.md). You can analyze existing configuration, events, and logs without connecting to a cluster. Live investigation requires kubectl access and read permissions for the relevant resources and logs. Optional helper scripts use Python 3 with no additional Python packages.

Share the cluster context, namespace, a known application, Pod, policy, or node, the symptom, and the approximate failure time when available. You do not need to discover every related object yourself.

## Example requests

Investigate an application failure:

> Use varmor-diagnosis to investigate Deployment checkout in namespace shop, context staging. Permission errors started about ten minutes after a policy change. Keep the investigation read-only and explain whether the evidence connects the failure to vArmor.

Analyze existing material:

> Analyze these policy YAML files, Pod events, and audit excerpts with varmor-diagnosis. Do not connect to a cluster. Explain what can be confirmed and what evidence is still missing.

## Typical workflow

1. Describe the symptom, affected target, and relevant recent changes.
2. The assistant automatically selects relevant checks and correlates policy and component evidence.
3. Review the findings, affected scope, confidence, recommended actions, and verification steps.

## Results and considerations

You receive a distinction between confirmed facts, possible causes, and missing evidence, with a formal diagnosis report when needed. A Ready policy alone does not prove that a workload is protected, and a permission error alone does not prove that vArmor caused the failure.

To refine an EnhanceProtect policy after diagnosis, use [Automated Policy Optimization](policy-optimization.md). For installation and detailed usage, see the [English guide](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.md) or [Chinese guide](https://github.com/bytedance/vArmor/blob/main/skills/varmor-diagnosis/README.zh_CN.md).
