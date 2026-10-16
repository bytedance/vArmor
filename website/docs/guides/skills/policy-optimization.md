---
slug: /guides/skills/policy-optimization
sidebar_position: 2
description: Automate EnhanceProtect policy analysis and tuning to reduce disruption to necessary application behavior.
---

# vArmor Policy Optimization

The vArmor Policy Optimization skill (`varmor-policy-optimization`) automates policy checks, observation log analysis, and candidate preparation to reduce manual tuning. Starting from an EnhanceProtect policy that meets your security goals, the assistant identifies conflicts with necessary application behavior and prepares optimization recommendations. After you select which rules to remove, it generates a candidate policy for your review and authorization before any update.

## What it helps you do

- Automatically validate an existing policy or prepare a draft from your confirmed protection requirements.
- Automatically analyze observation logs, attribute events to policy rules, and explain conflicts for your review.
- Generate a candidate policy and change summary from your decisions, and guide validation and subsequent optimization rounds.

The skill supports namespaced `VarmorPolicy` and cluster-scoped `VarmorClusterPolicy` in EnhanceProtect mode. Optimization removes selected existing rules; it does not optimize DefenseInDepth policies or generate BehaviorModeling models.

## Before you begin

Install the complete `skills/varmor-policy-optimization/` directory as described in the [Skills overview](index.md). Local policy checks require Python 3 and PyYAML. Live observation also requires kubectl access to the target vArmor cluster and an environment that can keep collection running throughout the agreed window.

Provide an existing policy YAML or the workload you want to protect, the cluster context and namespace, and the business scenarios you will exercise.

## Example requests

Check an existing policy locally:

> Use varmor-policy-optimization to review ./checkout-policy.yaml for EnhanceProtect observation. Explain anything that needs attention. Do not connect to a cluster or deploy it.

Prepare an optimization round:

> Help me optimize the EnhanceProtect policy for Deployment checkout in namespace shop, context staging. I will test startup, normal requests, retries, and scheduled tasks. Show me the policy and observation plan before starting.

## Typical workflow

1. Review the initial policy and agree on the business scenarios and observation window.
2. Authorize the observation policy. Once collection is ready, exercise the application.
3. Review the automated rule analysis and choose whether to remove rules, retain them, or continue observation.
4. Review the candidate policy and changes, authorize the update, and repeat as needed.

Each round has a saved task record, so you can return later or continue in another conversation using its path.

## Results and considerations

You receive rule analysis, your recorded decisions, and, when removals are approved, a candidate policy, change summary, and validation and rollback recommendations. Policy changes require your approval.

Observation does not guarantee that all behavior is allowed: custom RawRules can still block requests or operations. The assistant explains those effects before you run the application. Sufficient business coverage matters more than a quiet log; missing evidence or policy changes during observation can prevent a removal recommendation. The skill does not automatically switch the final policy into enforcement mode.

For installation and the complete workflow, see the [English guide](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.md) or [Chinese guide](https://github.com/bytedance/vArmor/blob/main/skills/varmor-policy-optimization/README.zh_CN.md).
