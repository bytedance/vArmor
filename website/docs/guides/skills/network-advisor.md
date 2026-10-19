---
slug: /guides/skills/network-advisor
sidebar_position: 1
description: Get network access policy recommendations for your application and validate them before deployment.
---

# vArmor Network Allowlist Advisor

The vArmor Network Allowlist Advisor (`varmor-network-advisor`) helps you decide which outbound connections an application needs and prepare a suitable network access policy. Describe the application and its requirements; the assistant recommends a NetworkProxy allowlist and guides you through review, testing, and deployment.

## What it helps you do

- Prepare a policy for a new application or adjust a compatible existing policy.
- Recommend access permissions based on your requirements and observed application behavior, and explain what each permission allows.
- Review necessary access, test allowed and denied requests, and refine the policy as requirements change.

## Before you begin

Install the complete `skills/varmor-network-advisor/` directory as described in the [Skills overview](index.md). Execution requires Python 3.9+, kubectl, and a working vArmor NetworkProxy installation on v0.10 or later. The assistant checks the capabilities and permissions needed for the selected workflow.

Provide the cluster context, namespace, and application name or Pod labels. Include an existing policy if you have one, and describe the business scenarios that must keep working. You can start with a planned application or request a draft without deploying it.

## Example requests

Start with policy recommendations:

> Use varmor-network-advisor to recommend a network access policy for Deployment checkout in namespace shop, context staging. Order creation and order lookup must keep working. Explain the plan before deploying anything.

Review known requirements:

> The application needs the payment API and our internal inventory service. Help me define the required access and prepare a policy draft for review. Do not deploy it yet.

## Typical workflow

1. Describe the application and required access. Review the proposed policy and observation plan.
2. After you authorize observation and the assistant confirms collection is ready, create or recreate the target Pods and exercise representative business scenarios.
3. Review recommended permissions and decide which access is necessary.
4. Authorize enforcement testing when ready, verify allowed and denied access, and decide whether to retain or adjust the policy.

Known requirements can also lead directly to a reviewed draft and validation. You manage application labels and workload/Pod lifecycles; the assistant handles policy preparation and authorized policy changes.

## Results and considerations

When reusing an existing policy, this skill preserves its system protection mode and rules while focusing on NetworkProxy access control. To refine the system protection rules in an EnhanceProtect policy, use [vArmor Policy Optimization](policy-optimization.md). For ineffective policies or unhealthy components, use [vArmor Diagnosis](diagnosis.md).

You receive a policy draft, permission explanations, review records, and validation results. Recommendations depend on the business scenarios you cover; observed access alone does not establish that it should be allowed. HTTPS visibility affects how precisely access can be restricted, so the assistant explains the available scope before you approve a policy.

For installation and the complete workflow, see the [English guide](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.md) or [Chinese guide](https://github.com/bytedance/vArmor/blob/main/skills/varmor-network-advisor/README.zh_CN.md).
