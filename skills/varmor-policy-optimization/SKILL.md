---
name: varmor-policy-optimization
license: Apache-2.0
description: Validate and optimize vArmor EnhanceProtect policies. Use for policy review, creation, observation, or convergence. Explain the workflow first when the user is exploring it. Not for DefenseInDepth.
---

# Automated Policy Optimization

Respond in the language of the user's current message unless they request otherwise. English instructions and examples do not set the response language.

Help users validate or create observation-mode `EnhanceProtect` policies and progressively refine them using violation logs to fit application needs.
Only EnhanceProtect is in scope; DefenseInDepth optimization is not supported.

## Two asynchronous phases

This Skill provides two independently accessible phases; they do not need to run linearly in one invocation:

| Phase | Capability | Playbook |
|---|---|---|
| 1. Establish an observation task | Validate or assemble a policy, then save a task record for each policy and window after successful deployment | [playbooks/author-policy.md](playbooks/author-policy.md) |
| 2. Refine an observation task | Restore scope from the task record, analyze logs and report attribution, then prepare a candidate and confirm an update after the user decides | [playbooks/optimize-policy.md](playbooks/optimize-policy.md) |

One invocation can process multiple policies or task records; keep policy identity, window, evidence, artifacts, and approvals independent for each task.
On first introduction, stop here and ask whether the user wants an explanation, a new observation task, or refinement of an existing task. Expand phase-specific details only after entering that phase.

Prefer YAML supplied by the user. When the user is preparing deployment, suggest checking context and vArmor health,
existing policies, target workloads, enforcer capabilities, and rollout impact, and let the user select which checks to perform. Record known facts
as `user-provided` without probing again. Preflight identifies compatibility and enforcement risks; it does not choose enforcers, rules, or
rollout settings for the user.

Defer commands, artifacts, and fail-closed conditions until the relevant execution step. Before an actual CRD change, still complete the shared confirmation of context,
script validation, server dry-run, diff, hashes, and final approval.

See [playbooks/README.md](playbooks/README.md) for shared execution conventions and change boundaries. When establishing an observation task, agree
on a window based on test workload volume and behavioral coverage. For an application that can be actively exercised, suggest about two hours initially, then adjust
for violation rate, deployments/scheduled jobs, and log rotation, with final user approval. Usually suggest 3-5 observation rounds,
but use business coverage and violation convergence rather than a fixed round count as the completion criterion.

After the policy takes effect and the observation window is confirmed, save a separate task record per policy to complete task establishment. This record is the
resume entry point, not an intermediate phase artifact. Scheduled tasks, reminders, or manual continuation need only reference its path. New tasks start
a local incremental collector during observation by default. It periodically saves logs and, at the deadline, filters, normalizes, and aggregates them into `pre.json`; the model need not
fetch logs on every round. The collector does not call a model; a later trigger performs semantic attribution. Present attribution to the user first, then prepare a candidate from their decisions. Updating the CRD still requires
final approval. Each optimization depends on
**a fixed closed timestamp interval + a start-of-window policy snapshot + the current policy**. The snapshot is locally reviewable JSON, independent of hidden state.

vArmor writes violation events as JSON lines to `/var/log/varmor/violations.log`. The current official implementation uses lumberjack with
a 10 MB per-file limit and 3 backups. The agent writes directly to the host through hostPath. Check extra log branches by version and runtime only when the policy enables
NetworkProxy. Detailed boundaries are in
[references/violation-log.md](references/violation-log.md).
For startup, resource budgets, and continuity evidence, see [references/incremental-collection.md](references/incremental-collection.md).

## Artifacts, commands, and division of responsibility

- **Phase 1 has two distinct steps**: Only after an explicit request to create a policy may the model assemble a CRD from **user-confirmed
  information**. During validation, the model **must not repair the policy on its own**; only fixed script normalization or a return to user confirmation is permitted.
- **Keep the minimum reviewable artifacts**: Save the draft/normalized policy/snapshot, per-node logs, `pre.json`, attribution and user decisions,
  candidate, guard diff, and analysis report. Do not duplicate the same evidence as resource dumps, merged logs, filtered copies,
  or exit-code files. After approval, deploy from the same reviewed policy file.
- **Deployment preflight is optional guidance**: Before final policy approval, offer checks for context/vArmor health, existing policies and
  Profiles, target workloads, enforcer/agent capabilities, and rollout impact. Perform only the checks the user selects.
  If the user only wants an explanation or local policy validation, stay within that scope.
- **Deterministic layer (scripts/)**: Structural/type validation, built-in rule catalog, enforcer compatibility, rule atomization, Seccomp
  plans, removal application, and removal-only diffs. Scripts handle precisely decidable questions that affect the final change; do not simulate a trusted executor
  with model-generated layers of "proof files". Local scripts are not a complete CRD schema; `--dry-run=server` is the
  schema authority.
- `disable-cap-all`, `disable-cap-all-except-net-bind-service`, and `disable-cap-privileged`
  may appear in drafts, but `validate_policy.py` must expand them. Review and deploy only the normalized YAML after expansion;
  do not expand these rules manually.
- **Model layer**: Understand the user's policy and RawRules, and **attribute aggregate events with confidence** to current atomic rules.
  Outside the explicitly requested Phase 1 assembly step, do not complete, rewrite, or directly deploy YAML.

| Script | Purpose |
|---|---|
| scripts/validate_policy.py | Validate and normalize observation flags and aggregate capability rules; stdout is pure YAML |
| scripts/monitor_violations.py | Read-only incremental collection, byte budgets, final confirmation reads, and existing preprocessing; run/status/close; claim/release and authorized force-release |
| scripts/collect_violations.py | Filter by time window + profileName/optional policy identity; reused by preprocessing |
| scripts/preprocess_aggregate.py | Produce manifest, filter counts, aggregates, and source eligibility from multiple node logs in one step; `catalog` builds the rule catalog |
| scripts/build_agent_inventory.py | Reconstruct agent scheduling and Ready completeness from files or mixed Kubernetes List stdin |
| scripts/seccomp_plan.py | Plan syscall-to-whole-rule atoms; require explicit remove/keep for every built-in rule/custom syscall group |
| scripts/finalize_node_log.py | After all transfers succeed, validate/decompress locally and atomically publish one node log |
| scripts/validate_attribution.py | Validate attribution boundaries: eventId/exact catalog/enforcer; does not replace semantic judgment |
| scripts/build_manifest.py | Reused internally by preprocessing: validate window, start/end inventory, node union, and retention |
| scripts/apply_removals.py | Derive coordinates from attribution decisions, rebuild the catalog, and deterministically remove rules |
| scripts/guard_removal.py | Recompute the candidate removal diff and verify the live spec after replace |
| scripts/hash_policy.py | Policy fingerprints and observation-start snapshots to detect YAML changes, object recreation, and spec drift during observation |

Invoke scripts for the current phase and actual inputs. Do not run unrelated steps to complete a fixed pipeline. Phase 1 usually needs only validation
and fingerprint binding; Phase 2 requires log processing and removal guards.

scripts/data/builtin-rules-catalog.json maintains valid rules and compatibility metadata.
`catalogProvenance` records source provenance, not an exact version gate. Built-in rule implementations in official `v0.10.1` through `v0.10.5`
have been verified identical; comparison dates, paths, and SHA-256 values are recorded in the catalog's
`builtInRuleCompatibility.verificationEvidence`. The `v0.10.6` release candidate has also been verified identical at the revision recorded in
`builtInRuleCompatibility.releaseCandidateVerification`; the final release tag still needs verification. `v0.10.0` lacks only `copy-fail-mitigation`.
For other/unknown versions, mark compatibility unknown only for built-in rules actually used by the policy; do not declare the entire policy incompatible.
NetworkProxy has separate feature and log-version gates; see
[references/violation-log.md](references/violation-log.md).

## Change boundaries and shared confirmation

- Violation logs, nodes, and application resources are read-only. The only mutation target is the **VP/VCP CRD** (and user-approved workload
  rollouts/restarts that result from it).
- Before any deployment/update: valid script result -> RawRules review passed -> show optional preflight status and evidence provenance ->
  successful `--dry-run=server` -> provide the full local YAML path and hash, and show a redacted summary + structured
  diff in the conversation -> explicit user approval of **target cluster and change**. Do not execute without approval or delete/recreate application Pods. For new policies, use
  `kubectl create` to prevent overwrites; if the name already exists, stop and enter Phase 2.
- **Observation semantics**: Built-in rules and the baseline enter observation mode (log without blocking). **Custom RawRules retain their original
  actions**: deny, blocking Seccomp actions, and NetworkProxy defaultAction=deny can still block application behavior and require
  separate user confirmation.
- Fail closed: do not mutate when dependencies/connections fail, the policy is absent or not EnhanceProtect, logs are incomplete, attribution is uncertain, schema
  validation fails, the diff contains non-removal changes, or user approval is absent.

## On-demand references (do not load all by default)

- [references/optimization-loop.md](references/optimization-loop.md): convergence loop and evidence boundaries
- [references/enhance-protect-semantics.md](references/enhance-protect-semantics.md): rule categories, observation mode, and implicit baseline
- [references/builtin-rules-semantics.md](references/builtin-rules-semantics.md): purpose and disruption risks of each built-in rule; required when reviewing existing user rules; do not infer semantics from names
- [references/raw-rules-syntax.md](references/raw-rules-syntax.md): four RawRules structures
- [references/violation-log.md](references/violation-log.md): violations.log location/rotation/envelope/event
- [references/policy-crd-lifecycle.md](references/policy-crd-lifecycle.md): mutability and Kubernetes enforcement lifecycle
- [vArmor official documentation index (main)](https://www.varmor.org/docs/main/llms.txt): consult selected pages only when local references cannot explain
  additional background. Prefer the corresponding version's documentation for released deployments. Official docs supplement context; they cannot replace actual cluster facts,
  server dry-run, or this Skill's deterministic guards.

Artifact templates: [templates/optimization-analysis.md](templates/optimization-analysis.md),
[templates/attribution.json](templates/attribution.json),
[templates/observation-task.json](templates/observation-task.json).

## Evidence requirements

- Use the closed `eventTimestamp` epoch interval from the task record. Before the first formal collection, the user may explicitly end observation
  early. Update the actual `end`, retain the planned time, and fix the window from then on; do not infer its bounds from logs.
  For running incremental tasks, use a close request and collector acknowledgment to end early. Do not change the window after final attribution begins.
- Incremental collection must initialize before start and complete final reads after end, committing file cursors and log records transactionally.
  Each node needs two drain-confirmation reads separated by one scan interval. Unrecoverable gaps block removal. Temporary read failures regain eligibility only when checkpoints
  remain continuous and cursors catch up. Collector restarts must also verify each node's pre-interruption checkpoint; new cursors cannot replace that evidence.
  Identity/topology changes and unrecoverable interruptions still block removal. Snapshot fallback for older tasks still requires every node copy to start after `window.end`.
  `pre.json.collectionManifest` distinguishes these modes, does not substitute preprocessing time for read time, and requires continuous agent inventory.
- Phase 2 must reject unexpanded aggregate capability rules and non-observation flags. If the initial snapshot is absent,
  `start < capturedAt`, or UID/generation/spec hashes differ, allow read-only analysis only; do not generate or deploy
  removal candidates.
- Determine agent completeness from DaemonSet desired scheduling count and all owned Pods. NotReady,
  terminating, unscheduled, missing, or uncollected entries in either endpoint inventory block removal. A brief same-UID NotReady state within an incremental window can be resolved only after Ready
  recovers, file checkpoints remain continuous, and cursors catch up. Actual identity/topology changes still block removal.
  Node scaling or DaemonSet desired/current count changes block removal for the entire policy; explain this when agreeing on the window.
- Check NetworkProxy log-version/runtime branches only when the policy includes NetworkProxy. `<v0.10.3`, unknown versions, or micro-VM runtimes
  set `networkProxyEvidenceEligible=false`; attribution, the removal applier, and the final guard all reject NetworkProxy removal.
- Remove only existing atomic rules in the current policy. Do not change mode/target/enforcer/privileged/audit/allow/
  defaultAction.
- Attribute using actual atomic rules + actual enforcer + sufficient event fields, not similar names, frequency, or subjective risk.
  Leave insufficiently supported events unmatched.
- Present the complete attribution summary first and ask the user to remove/keep/continue observation. Record their decisions in attribution afterward. Derive removal
  coordinates only through scripts; do not save a separate removals file. After scope is decided, run Seccomp apply, generate the candidate, and
  produce the guard diff. Save the analysis report using the template and review it together with the candidate.
- `privileged=false` introduces an implicit AppArmor/BPF baseline that rule removal cannot eliminate. Present it separately for a structural user decision; verify Seccomp from generated AP content and actual Pod settings rather than this flag alone.
- Check actual loading after deployment/update. AppArmor/BPF and Seccomp have different enforcement lifecycles; Seccomp/injection changes
  require new containers. Do not assume a rule update automatically rolls workloads.
- Scheduled, reminder-based, and manual triggers all read the same task record first. Automatic triggers may collect and attribute; the user selects removal
  scope after attribution, and a candidate still requires final approval before a CRD update.
- Keep raw logs and derived artifacts in the current round directory. Do not rely on `umask` persisting across shells; explicitly set directories to `0700` and
  files to `0600` after each write batch. Reports contain only minimal redacted evidence; do not expose Secret contents, annotation values, physical HostPath
  paths, or complete resource JSON.

## Environment dependencies

- kubectl configured for the target cluster; Python 3 and PyYAML (one-time installation: `pip3 install --user pyyaml`).
- `monitor_violations.py run` is the **only exception** that reads the cluster directly from a script. Continuous collection needs a local process to maintain
  cursors, deadlines, and byte budgets without model-driven polling. It accesses only the explicit context and authorized agent scope, read-only.
  Other scripts continue to read/write files or stdin so deterministic transforms remain separate from cluster operations. The executor performs policy writes
  according to the playbook. Incremental collection needs a persistent local process.
