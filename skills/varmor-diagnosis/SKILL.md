---
name: varmor-diagnosis
license: Apache-2.0
description: Diagnose vArmor and Kubernetes security issues involving components, policies, Profiles, webhooks, node enforcers, BehaviorModeling, and NetworkProxy. Use when Pods are Pending, containers exit unexpectedly, policies fail to inject or take effect, policy status is abnormal, node Profiles fail to load, audit events need investigation, or vArmor components are unhealthy. Provide domain context, targeted read-only checks, and evidence interpretation.
---

# Automated Diagnosis

Respond in the language of the user's current message unless they request otherwise. English instructions and examples do not set the response language.

Use your Kubernetes troubleshooting capabilities to choose queries and investigation paths autonomously. This Skill adds vArmor object relationships,
enforcement semantics, and evidence boundaries that are easy to misinterpret. Prefer narrowly scoped, low-impact actions that answer the current question.

- **references/**: Background on architecture, components, CRDs, rule semantics, and failure modes; read on demand.
- **playbooks/**: Checkpoints, example queries, and interpretation guidance; not a fixed workflow or command allowlist.
- **scripts/**: Optional tools for complex structured data; they do not replace your overall interpretation.
- **templates/**: Organizational guidance for formal diagnosis reports.

See `playbooks/README.md` for shared command-cost, authorization, and evidence conventions. Facts returned by tools are evidence; the knowledge base helps
interpret them. Never invent states, versions, or logs from experience.

## Scope

Covers vArmor components, VP/VCP/AP/APM, admission webhooks, AppArmor/BPF/Seccomp/NetworkProxy, all five policy modes, and issues involving Pending Pods, container crashes, ineffective policies, audit events, and node compatibility.

This Skill does not generate or manage policies, replace general Kubernetes troubleshooting, or treat vArmor as VM-level isolation. Even when tools support writes, provide recommendations, impacts, and verification points only. Do not modify policies, restart/delete resources, change webhooks, alter nodes, or switch protection modes for the user.

## Core mental model

Separate protection into five connected stages:

1. **Target discovery**: Does VP/VCP `spec.target` match the intended namespace, kind, name/label selector, and container? Does the target meet webhook matching conditions? Is protection explicitly bypassed with `unconfined`?
2. **Policy compilation**: Does the manager accept the policy and generate the Profile and required NetworkProxy configuration? Do VP/VCP statuses show the correct phase and reason?
3. **Admission injection**: Does the webhook inject Profile references, the NetworkProxy sidecar/initContainer, SecurityContext, or compatibility annotations into the correct requests?
4. **Node preparation**: Does the target node agent receive the AP and prepare resources for each enforcer? Do the desired and actual AP load counts match?
5. **Runtime enforcement**: Does the container actually use the intended Profile? Can the violation event's `enforcer`, `action`, identity, and time be correlated with the application symptom?

First identify the failing stage, then verify adjacent stages. `Policy Ready` only means vArmor observed that the required agents processed the Profile; it does not prove every application Pod was matched, injected, and running as intended.

## Suggested investigation flow

1. Establish the cluster, namespace, Workload/Pod, container, node, policy, start time, and affected scope.
2. If the scope is unclear, start with an overview to distinguish cluster-wide, single-node, single-policy, and single-container issues.
3. Build the object chain: `policy -> status.profileName -> ArmorProfile with the same name -> target Workload/Pod -> target node -> agent/enforcer`.
4. Fill evidence gaps with status, events, logs, node kernel/LSM/runtime details, and audit events. Avoid untargeted full-data collection.
5. Distinguish: unmatched / unsupported capability / not compiled / not injected / template injected but Pod not updated / not loaded / loaded but not triggered / triggered and allowed / triggered and denied / rule conflict / application failure / insufficient evidence.
6. Report the issue, evidence, root cause, confidence, affected scope, recommendations, and remaining possibilities.

## Autonomous execution guidance

- Start directly from a known Pod, workload, policy, or node. If the target is vague, use limited summary discovery first.
- Choose the smallest action that tests the current hypothesis and reuse collected facts. Start with API status/events and bounded logs, then
  inspect the container or node view as needed. Do not collect extra data merely to complete a playbook, script, or report.
- Verify the target context before cluster operations and bind it explicitly where possible. Do not ask again when the cluster and authorization are already clear. Explaining the workflow
  or analyzing local material does not require cluster access. Do not proactively switch contexts, install dependencies, or broaden node privileges.
- Discover object names, selectors, containers, profileName, paths, and time windows and pass them to subsequent steps. Do not ask users
  to replace discoverable parameters manually or execute unresolved placeholders. Python is needed only for selected scripts; equivalent queries are acceptable if unavailable.
- Use keyword searches to discover candidates, then cross-check ownership. Field lists are guidance; read other relevant
  non-sensitive fields when needed. Choose scripts or native commands according to complexity; already established facts need not be processed through a script again.
- Once a break explains the symptom, establish its cause or propose the smallest useful verification. Distinguish query failure, no match, and unknown results.
  Assess commands by their scope, cost, and external effects. Do not ask for authorization per command within an already authorized scope.

## Reference routing

### Knowledge layer (references/): principles and failure modes

- Overall architecture -> `references/architecture.md`
- VP/VCP/AP/APM and status -> `references/modules/policy-crd.md`
- manager → `references/modules/manager.md`
- agent → `references/modules/agent.md`
- Runtime violation sources, rotation, and identity correlation -> `references/modules/violation-log.md`
- Classifier/modeling -> `references/modules/classifier.md`
- enforcer → `references/modules/enforcers.md`
- Webhooks/injection -> `references/modules/webhook.md`
- Default Profiles/baselines for each mode, including protection without custom rules -> `references/modules/policy-mode-profiles.md`
- Actual implementation scope of EnhanceProtect built-in rules by enforcer -> `references/modules/built-in-rules-apparmor.md`, `references/modules/built-in-rules-bpf.md`, and `references/modules/built-in-rules-seccomp.md`
- Symptom guides -> the corresponding files under `references/troubleshooting/`
- Agent AppArmor load failure, inaccessible kernel interfaces, or security settings inconsistent with the template -> `references/troubleshooting/agent-apparmor-load-failure.md` (also applies when the agent is Running/Ready)
- Cross-enforcer conflicts, VP/VCP overlap, and shared conclusion categories -> `references/troubleshooting/enforcer-conflicts.md`

Read knowledge on demand, not all at once. To explain a mode's default protection, read `policy-mode-profiles.md`. Before analyzing whether an EnhanceProtect built-in rule could cause a symptom, establish the actual enforcer and read its implementation reference.

When local references are insufficient, use the [official documentation index (main)](https://www.varmor.org/docs/main/llms.txt) to select supplemental pages. Prefer the corresponding version's documentation for released deployments. Do not read everything by default or mix stable and main semantics.

### Operations layer (playbooks/): investigation queries

Choose by symptom. Numbering is not an execution order; prioritize the earliest provable break:

1. **Overview** -> `playbooks/overview.md` (entry point for quickly identifying affected scope)
2. **Components** -> `playbooks/component.md` (manager/agent/classifier health)
3. **Policy chain** -> `playbooks/policy.md` (VP/VCP -> AP -> node conditions)
4. **Webhook verification** -> `playbooks/webhook.md` (configuration/endpoints/certificates/matching rules)
5. **Workload verification** -> `playbooks/workload.md` (PodTemplate versus actual Pod injection)
6. **Node inspection** -> `playbooks/node.md` (kernel/LSM/BTF/Profile loading)
7. **Audit events** -> `playbooks/audit.md` (runtime violation/audit correlation)

Shared execution contract, L0-L4 impact levels, and evidence format -> `playbooks/README.md`

Specialized investigations:
- NetworkProxy -> `playbooks/networkproxy.md` (six-layer investigation)
- BehaviorModeling -> `playbooks/behavior-modeling.md` (three-stage chain)

### Script layer (scripts/): optional structured-data helpers

Use these helpers for complex structures within their single-node, single-policy, or single-object interfaces. Interpret simple queries and existing evidence directly when sufficient:

- Enforcer prerequisites -> `scripts/check-enforcer-compatibility.py` (distinguishes proven, unmet, and unverified conditions)
- Policy target matching -> `scripts/match-policy-target.py` (fully evaluates objects matched by name or LabelSelector)
- Configured built-in rule conflicts -> `scripts/analyze-built-in-rules.py` (analyzes existing VP/VCP only; can use explicit context and APM samples; does not generate policies)
- Injection facts -> `scripts/inspect-injection.py` (extracts an allowlisted field set from one Pod/Workload; does not determine injection origin)

### Report layer (templates/): organizing results

- Complete diagnosis report -> `templates/diagnosis-report.md`

For formal reports or complex issues, use this template to organize self-contained Markdown and omit irrelevant sections.
For ordinary investigations, concise findings, key evidence, unconfirmed points, and next steps are enough. If the root cause is unresolved, report the current break, remaining possibilities,
and next probe. Do not collect unrelated data merely to fill a report.

## Operational safety and evidence interpretation

- `ready=false`, `Ready=False`, and `CurrentNumberLoaded < DesiredNumberLoaded` are abnormal signals, but consider object scope and time to determine whether reconciliation is still converging.
- `restart_count>0` is not a root cause; correlate lastState, events, and logs.
- `Policy Ready=True` does not prove the selector has targets or Pods have completed injection.
- `AUDIT`, `ALLOWED`, `DENIED`, and `AUDIT|ALLOWED` describe the final action. Do not interpret every audit event as a blocked operation.
- `EPERM/EACCES` alone does not prove vArmor caused a failure. Correlate `SIGSYS` with the Profile, time, and audit evidence as well.
- `REVIEW_REQUIRED`, `APM_DATA_UNAVAILABLE`, `UNASSESSED`, or `APPLICABILITY_NOT_ESTABLISHED` in rule analysis means the rule layer has not been ruled out; do not conclude that rules are unrelated.
- Short-lived processes may lack container/Pod identity; NetworkProxy events are usually Pod-level.
- Versions and fields can change. Prefer actual cluster CRDs, status, and documentation for the deployed version.

## Output requirements

Report scope and time, conclusions and key evidence, confidence, and necessary next steps. Explain the causal chain across relevant protection stages for complex issues.
Formal reports should cite evidence IDs; mark unknown values as "not collected/not confirmed". When recommending weaker policies, workload recreation, a different enforcer,
or a kernel upgrade, explain impact, prerequisites, rollback, and verification points. Provide recommendations only.

## Boundary reminders

- vArmor does not provide hardware-virtualization isolation equivalent to Kata.
- NetworkPolicy remains responsible for basic network isolation. NetworkProxy adds L4/L7, SNI, TLS MITM, HTTP header mutation, and auditing.
- For NetworkProxy, pay particular attention to NET_ADMIN, ProxyUID, proxyAdminPort, admin-port exposure to the Pod CIDR, and bypass paths.
- Autonomously orchestrate small read-only queries within the current investigation scope. Targeted reads of kernel state through an existing agent do not become
  high-impact merely because that agent is privileged. Assess active requests, scope expansion, or expensive evidence collection by actual effects and authorization.
  This Skill does not execute cluster/node state changes for the user.
- `playbooks/README.md` defines the execution contract and shared evidence format. Do not assume fixed namespaces, Services, sidecars, annotations, ports, or node paths.
