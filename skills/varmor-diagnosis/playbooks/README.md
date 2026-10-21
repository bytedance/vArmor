# vArmor diagnosis playbooks

## Purpose and use

These playbooks provide vArmor-specific checkpoints, query examples, and interpretation guidance. Choose commands,
correlate objects, and adapt the investigation to symptoms and actual facts. Examples are neither a fixed pipeline nor a command allowlist.
Use your judgment for general Kubernetes queries/troubleshooting; consult `references/` for domain principles as needed.

Start from a user-specified Pod, policy, workload, or node. When scope is unclear, use `overview.md` for limited discovery.
Use `component.md` for component health, `policy.md` for policy/AP issues, `webhook.md` and `workload.md` for injection,
`node.md` for node loading, and `audit.md` for runtime denials. NetworkProxy and BehaviorModeling have specialized playbooks.
Once a break adequately explains the symptom, establish its cause or verification; do not traverse unrelated stages for completeness.

## Close evidence gaps with small actions

Each query should answer a current question. Usually inspect target status and related events first, then bounded component logs,
and enter container/node views only if insufficient. Reuse established object identities, configurations, and results;
read again only when verifying a state change.

- **Discovery scope**: Prefer namespace, resource kind, label/field selectors, owners, and node constraints. Keywords
  can discover candidates, but verify ownership through references, owner, image, policy, and version. Without a locator, perform one
  bounded summary list, then narrow to relevant objects. Do not scan all nodes, Pods, or historical logs by default.
- **Read cost**: Prefer exact files/fields, then shallow directories/bounded lists. Bound logs by both time and lines,
  adding byte limits for high volume. Save bounded raw excerpts locally with restricted permissions if needed. Local `grep/head/tail`
  truncation does not bound remote reads, transfer, or scanning. A single-object `-o json` can support local parsing and avoid repeated GETs;
  jsonpath/custom-columns mainly limit display, not server-side field projection.
- **Node impact**: Prefer short, targeted, read-only exec commands: one LSM-state file, one
  Profile file, or listening ports. Bound directory searches by path, depth, and timeout. Locate objects before considering full BPF-table
  enumeration or large logs. For node NotReady, OOM, or kernel errors, reduce remote probing and prefer existing logs/API evidence.
- **Failures**: Distinguish query failure, absent objects, no matches, and insufficient evidence. Retain stderr and exit status. Complex
  pipelines may use pipefail or explicit checks so filter success cannot hide kubectl failure. If a command is unavailable, choose an equivalent
  low-impact path; do not automatically install tools or create debug containers.
- **Parameters and time**: Discover and propagate actual names, scope, containers, paths, and failure windows; never execute unresolved placeholders.
  Specify exec containers explicitly and apply reasonable remote-query/exec timeouts. kubectl request timeout bounds API requests;
  bound long exec separately using the execution tool or available timeout utility, without assuming this kills the remote process.

Do not narrate every routine setting. Communicate material findings, scope expansion, and impact.

## Operational boundaries and authorization

This Skill diagnoses only. Policy changes, resource deletion/recreation, rollouts, Profile load/unload, network-rule changes,
and node-state changes are recommendations only. Do not create privileged Pods, enter host namespaces, or broaden privileges for evidence collection.

Assess impact by **actual action, access scope, resource cost, and external effects**. These levels describe impact rather than a fixed approval
pipeline. privileged/hostPath/hostNetwork are risk factors; not every command inside such containers is a write:

| Level | Typical action | Execution considerations |
|---|---|---|
| L0 | Target-object status, relationships, and summary API queries | Execute autonomously within the current investigation scope. |
| L1 | Bounded logs/events, relevant configuration, and certificate metadata | Bound scope and handle sensitive information. |
| L2 | Targeted read-only state/file/listener checks in a confirmed container, including confirmed kernel state through existing agent mounts | Assess exact path/command; bound container, volume, and duration; current authorization must cover access. |
| L3 | Active connectivity/application requests, port-forward, or proxy admin endpoints | Establish target, request effects, and total timeout; use authorization covering the action and clean up forwarding afterward. |
| L4 | Broad/expensive node evidence collection or sensitive host data; cluster/node changes | Read-only collection only when needed and specifically authorized; state changes are recommendations only. |

Verify and show the target context first. Do not seek confirmation again when the user specified the cluster or current authorization covers it. Do not switch
contexts automatically; bind later commands explicitly where possible. Explaining workflows or analyzing supplied material does not require cluster access.
Authorization may come from the user's permission for the current scope or platform approval/access policy covering the action. Do not confirm every command
within the same scope; ask when the target is unclear, scope expands, or impact materially increases. RBAC and command executability establish technical access only.

## Optional scripts

Scripts help with error-prone structures and repeated judgments; they do not choose the diagnostic path or gate conclusions.
Prefer native commands for simple fields. Scripts help with full selectors, rule metadata, or batches of injection fields.
Do not rerun scripts merely to complete a step when evidence is sufficient. Equivalent kubectl/local parsing is acceptable if semantics are preserved.
Follow script interfaces, invoke from the Skill root or with absolute paths, and bind target/context.

Script results are supporting evidence: `ERROR` means failure; `TO_PROVE/PARTIALLY_VERIFIED` means a capability remains unproven;
`REVIEW_REQUIRED/UNASSESSED/APM_DATA_UNAVAILABLE` cannot rule out rule conflicts, and no APM match means only
the supplied sample did not match. Close unproven points with independent evidence instead of repeatedly querying for a desired script state.
Injection scripts extract facts only; interpret origin and lifecycle yourself. Script catalogs have version limits; prefer actual objects and
corresponding implementations, and do not invent rule semantics from names.

## Evidence and delivery

Retain object identity, source, time, key status/logs, and relationships needed for conclusions. Use UID, containerID,
generation/resourceVersion to distinguish recreation, old instances, or configuration changes; every query need not fill a complete table.
Separate direct facts, inference, unconfirmed points, and confidence. Proving a denial does not necessarily prove it caused the entire application failure.
Use independent evidence when fields are missing; otherwise provide the smallest next probe.

Ordinary replies need scope, findings, key evidence, and next steps. Organize formal/complex diagnoses with the report template.
Field lists are prompts selected for the question; do not collect data to fill a form. Do not expose Secrets, private keys, tokens,
unrelated application logs, or full resource dumps. Read necessary non-sensitive annotation/configuration values selectively (such as Profile references,
flags, and ports), and redact display. Keyword filtering is not redaction. Store required raw material with restricted directory/file
permissions (recommended 0700/0600), without relying on cross-shell umask; do not proactively delete user material.

## vArmor interpretation reminders

- Policy Ready does not prove target matches, Pod injection, or runtime use of the intended Profile.
- Observe PodTemplate and actual Pod separately; webhooks do not write back to existing Pods.
- Profile presence/loading and actual container use are different evidence. Resolve VP/VCP overlap from final AP and Pod configuration.
- `EPERM/EACCES/SIGSYS` alone does not prove vArmor attribution; `AUDIT/ALLOWED` does not mean denial.
- Interpret `allowViolations` and `auditViolations` by enforcer. NetworkProxy also requires rule, qualifier,
  and defaultAction analysis. Sidecar Ready does not prove traffic passes through it.
- APM is a behavior-modeling sample, not ordinary audit storage or a complete application allowlist.
