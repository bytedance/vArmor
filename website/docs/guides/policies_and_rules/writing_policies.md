---
sidebar_position: 0
description: Select a workload, write a policy, and verify enforcement.
---

# Writing Policies

A useful policy starts with a concrete requirement: identify the workload, the operation to control, an operation that must keep working, and the expected audit evidence. Begin in a dedicated namespace before applying the policy to production workloads.

## 1. Choose the enforcement mechanism

Use [Enforcers](../enforcers/index.md) to map the requirement to a supported mechanism, and check [Installation](../../getting_started/installation.md) for its prerequisites. Then select a compatible [Policy Mode](policy_modes/index.md). Rule names and audit switches are not interchangeable between enforcers.

## 2. Select the workload precisely

Use a namespaced `VarmorPolicy` for the first policy. Choose either `spec.target.name` or `spec.target.selector`, not both, and use a supported kind: Pod, Deployment, StatefulSet or DaemonSet. `spec.target` is immutable; changing it requires a new policy.

For a Deployment target, the selector matches the Deployment object's `metadata.labels`, not only the labels inside its Pod template. The selected workload must also opt in with `sandbox.varmor.org/enable: "true"`. Inspect both the controller and the generated Pods when diagnosing a mismatch.

A cluster-scoped policy takes precedence over a matching namespaced policy. Check for an existing `VarmorClusterPolicy` before interpreting a local policy's results. See [Interface Operations](../../getting_started/usage_instructions.md#interface-operations).

## 3. Start with the smallest rule set

Use the [AppArmor usage example](../../getting_started/usage_instructions.md#example) on a compatible node, or the matching enforcer's guide for another mechanism. Add one restriction at a time. The [built-in rules](built_in_rules/index.md), [custom rules](custom_rules.md) and [API reference](../../getting_started/interface_specification.md) supply the supported fields.

For example, define the expected outcomes before writing a rule:

| Check | Expected result |
| --- | --- |
| An application operation required for normal service | Succeeds |
| The specific operation the rule is intended to prohibit | Fails due to the configured enforcer |
| Audit evidence, if enabled for that operation | Identifies the tested policy/workload and expected action |

Observation mode is useful only where the chosen enforcer supports it. NetworkProxy uses its own rule qualifiers and `defaultAction`; `allowViolations` does not turn its deny rules into observation rules.

## 4. Apply and inspect the actual workload

Apply the policy before creating the test workload. For an existing controller-managed workload, review the impact of `updateExistingWorkloads` in the [API reference](../../getting_started/interface_specification.md) before requesting reinjection or a rollout.

```bash
kubectl apply -f policy.yaml
kubectl get varmorpolicy -n YOUR_NAMESPACE YOUR_POLICY -o yaml
kubectl get armorprofile -n YOUR_NAMESPACE
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o yaml
```

Replace the uppercase names with your test resources. Follow [State Management](../../getting_started/usage_instructions.md#state-management) to inspect failures. Confirm that the actual container has the expected profile or, for NetworkProxy, the injected containers. Control-plane status alone is insufficient to establish effective protection.

## 5. Verify behavior and audit evidence

Execute the permitted and prohibited operations in the selected application container. Specify `kubectl exec -c` explicitly in a multi-container Pod. Correlate results with [audit logs](../../getting_started/usage_instructions.md#audit-logs) where configured; an absent log may be the rule's documented silent behavior.

For networking, distinguish a proxy rejection from a backend response or a connection failure. Use a backend you control to confirm whether the request arrived. For a changed policy, wait for the actual configuration/profile to take effect and repeat both checks.

## 6. Update, roll back and remove

Keep the tested policy in version control. Change one requirement at a time, verify its effects, and retain the previous valid specification for rollback. Seccomp profile changes require new containers; NetworkProxy has separate configuration and Pod-template lifecycles. Review the chosen enforcer's guide before assuming a change is live.

Deleting a policy and removing protection from existing containers are not interchangeable operations. Follow [Usage Instructions](../../getting_started/usage_instructions.md) and inspect the resulting workload template and replacement Pods. For a disposable tutorial, delete only the namespace and resources created for that tutorial.

## More examples and tools

Use [Policy Advisor](../policy_tools/policy_advisor.md) for a starting template, then validate the result against the current API and your workload. The repository contains additional [examples](https://github.com/bytedance/vArmor/tree/main/test/examples) and [demos](https://github.com/bytedance/vArmor/tree/main/test/demos); select examples matching the installed release.
