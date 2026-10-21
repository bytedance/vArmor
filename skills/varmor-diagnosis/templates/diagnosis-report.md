<!--
Usage rules:
1. Use this template for formal or complex investigations; remove irrelevant sections and produce a self-contained report. It is optional for ordinary questions.
   Replace {{placeholders}} in retained sections; do not collect extra evidence solely to fill the template.
2. Mark uncollected or unproven information as "not collected" or "unconfirmed"; never invent it from experience.
3. Cite at least one evidence ID (E1, E2, ...) for every key conclusion.
4. Use absolute timestamps with time zones; distinguish the failure window from collection times.
5. Retain only diagnostic summaries; never include Secrets, private keys, tokens, sensitive Annotation values,
   full HostPaths, full APM file paths, complete resource JSON, or unrelated application logs.
6. If the root cause is unresolved, report the earliest established breakpoint, ruled-out and remaining explanations, and the next probe.
   Do not force a root-cause conclusion for completeness.
-->

# vArmor Diagnosis Report: {{brief issue title}}

## 1. Basic information

| Item | Details |
|---|---|
| Report generated | {{YYYY-MM-DD HH:mm:ss TZ}} |
| Failure window | {{start to end; unconfirmed if unknown}} |
| Diagnostic scope | {{cluster/namespace/Workload/Pod/container/node}} |
| User symptom | {{one-sentence observable symptom}} |
| vArmor version | {{version or not collected}} |
| Kubernetes version | {{version or not collected}} |
| Policy | {{VP/VCP namespace/name; unconfirmed if unavailable}} |
| Profile | {{ArmorProfile/profileName; unconfirmed if unavailable}} |
| Enforcer / Mode | {{AppArmor/BPF/Seccomp/NetworkProxy; mode}} |

## 2. Executive summary

- **Diagnostic status**: {{localized / partially localized / insufficient evidence / no vArmor abnormality found}}
- **Current breakpoint**: {{unmatched / unsupported capability / not compiled / not injected / template injected but Pod outdated / not loaded / loaded but not triggered / triggered and allowed / triggered and denied / rule conflict / application issue / insufficient evidence}}
- **Impact scope**: {{one container/Pod/Workload/node, multiple nodes, or cluster-wide; include counts or unconfirmed}}
- **Main conclusion**: {{narrowest directly supported conclusion, citing E IDs}}
- **Root-cause confidence**: {{high / medium / low}}, because {{degree of evidence closure}}
- **Recommended priority**: {{P0 / P1 / P2}}; first action: {{low-risk remediation or next probe}}

## 3. Key conclusions

| Severity | Category | Conclusion | Impact | Confidence | Evidence |
|---|---|---|---|---|---|
| {{P0/P1/P2/info}} | {{breakpoint category}} | {{conclusion}} | {{scope}} | {{high/medium/low}} | {{E1, E2}} |

> Severity indicates response priority, not evidentiary confidence. Do not list unsupported speculation as a conclusion.

## 4. Status and scope snapshot

| Object observed | Expected state | Actual state | Assessment | Observation time | Evidence |
|---|---|---|---|---|---|
| {{manager/agent/classifier/VP/VCP/AP/Workload/Pod/Node}} | {{expected}} | {{actual}} | {{normal/abnormal/unconfirmed}} | {{absolute time TZ}} | {{E IDs}} |

## 5. Protection chain

| Stage | Objects checked | Key observation | Status | Evidence |
|---|---|---|---|---|
| Target discovery | VP/VCP target, target object, container | {{name/selector matching; unconfined state}} | {{pass/fail/unconfirmed}} | {{E IDs}} |
| Policy compilation | VP/VCP status, profileName, AP | {{phase/conditions/AP generation}} | {{pass/fail/unconfirmed}} | {{E IDs}} |
| Admission injection | Webhook, PodTemplate, actual Pod | {{Profile/sidecar/initContainer/volume injection facts}} | {{pass/fail/unconfirmed}} | {{E IDs}} |
| Node installation | Node, agent, LSM/runtime, AP node condition | {{expected/actual loading; unproven capabilities}} | {{pass/fail/unconfirmed}} | {{E IDs}} |
| Runtime enforcement | Actual Profile, events, action, application symptoms | {{loaded but not triggered/allowed/denied/no associated events}} | {{pass/fail/unconfirmed}} | {{E IDs}} |

**Earliest established breakpoint**: {{stage and specific object}}.

**Why downstream healthy states do not invalidate this breakpoint**: {{brief explanation; remove if inapplicable}}.

## 6. Cause analysis

### 6.1 Confirmed facts

1. {{directly observed fact, citing E1}}
2. {{fact, citing E2}}

### 6.2 Reasoning chain

1. {{which evidence confirms or rules out which stage}}
2. {{how object identity, Profile, node, and time are correlated}}
3. {{why the current conclusion fits the evidence better than alternatives}}

### 6.3 Root cause or current breakpoint

{{If resolved, state the direct root cause and mechanism. Otherwise state explicitly: "Current evidence only establishes a breakpoint at ..., and the root cause remains unconfirmed."}}

### 6.4 Ruled-out and remaining explanations

| Type | Item | Basis |
|---|---|---|
| Ruled out | {{other enforcer/runtime/CNI/DNS/service mesh/application logic, etc.}} | {{E IDs or check results}} |
| Not ruled out | {{factors that could still explain the symptoms}} | {{missing evidence}} |

## 7. Key evidence

### E1 - {{evidence title}}

- **Object**: {{kind namespace/name, UID, generation/resourceVersion where applicable}}
- **Collection time**: {{YYYY-MM-DD HH:mm:ss TZ}}
- **Source**: {{command, script, or object field}}
- **Observation**: {{minimum necessary raw fields or log summary}}
- **Supported conclusion**: {{what this evidence directly proves and cannot prove}}

```text
{{retain necessary excerpts only; remove or redact sensitive values}}
```

### E2 - {{evidence title}}

- **Object**: {{object identity}}
- **Collection time**: {{YYYY-MM-DD HH:mm:ss TZ}}
- **Source**: {{source}}
- **Observation**: {{observation}}
- **Supported conclusion**: {{conclusion with explicit limits}}

## 8. Remediation recommendations

| Priority | Recommendation | Risk level | Impact and prerequisites | Rollback | Success criteria |
|---|---|---|---|---|---|
| {{P0/P1/P2}} | {{recommended action; do not directly execute writes}} | {{L0-L4}} | {{scope, authorization, and dependencies}} | {{explicit rollback}} | {{observable verification results}} |

Recommended order:

1. {{prefer low-risk, reversible actions that test a hypothesis}}
2. {{explain security impacts of relaxing policies, recreating Workloads, switching enforcers, or upgrading kernels}}

## 9. Next verification

> Remove this section if the root cause is resolved and no verification remains.

| Priority | Open question | Minimal probe | Risk level | Expected outcomes and branches |
|---|---|---|---|---|
| {{1}} | {{question}} | {{single-object, single-node, or bounded-window check}} | {{L0-L4}} | {{meaning of outcome A; next direction for outcome B}} |

## 10. Limitations and notes

- {{data gaps, Event retention, log windows, RBAC, or authorization limits}}
- {{APM is a bounded behavior sample; REVIEW_REQUIRED means the rule layer is not ruled out, and NO_CONFLICT_OBSERVED does not establish absence of conflicts, where applicable}}
- {{no cluster writes were performed; list any authorized L3/L4 verification performed here}}
