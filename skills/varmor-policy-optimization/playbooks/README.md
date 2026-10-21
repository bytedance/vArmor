# Playbook Execution Contract

This file defines execution conventions shared by two asynchronous phases. Enter phases independently in different invocations or sessions, or process
multiple tasks in one invocation. Detailed domain knowledge is in `references/`.

## 1. Prerequisites

- For user-confirmed cluster preflight, log collection, or changes, `kubectl` must access the target cluster and the context must be confirmed.
  Do not run kubectl merely to introduce the Skill or validate YAML locally, and never switch contexts independently.
- Python 3 + PyYAML (one-time installation: `pip3 install --user pyyaml`).
- Scripts are in `scripts/`. `monitor_violations.py run` accesses the cluster read-only within the authorized agent scope; other
  data-processing scripts read files or stdin. The executor still performs all CRD writes under this contract.

## 2. Commands and artifacts

- Persist key policies, per-node logs, reduced evidence, attribution decisions, candidate policies, and diffs for user review and later verification.
  Do not redundantly retain reproducible representations such as raw resource dumps, merged logs, filtered outputs, or exit codes. After confirmation, submit the same reviewed
  policy file rather than assembling temporary YAML or directly constructing creation commands.
- Use an independent run directory per policy/task; filename prefixes identify generating steps. Never overwrite another task's policy or evidence.
  Task records belong in a persistent task directory, outside phase artifacts. They are mutable state indexes; referenced snapshots, inventories, and
  per-round artifacts remain immutable.
- Choose shell safeguards according to command structure. Complex pipelines or sequential writes may use `set -euo pipefail`, and sensitive temporary files may
  use `umask 077`; explicit exit-code checks, `&&`, restricted directories, or atomic publication are equally valid alternatives.
  Do not mechanically prefix every simple query or narrate routine shell setup. Regardless of approach,
  successful later commands such as chmod must not mask earlier failures. Collection blocks containing arrays or here-strings require Bash;
  simple commands are shell-independent.
- In a new shell, restore context, directories, and the fixed window from task records. Restore reviewed hashes from confirmation records rather than recalculating
  and presenting them as the original reviewed values. Read the baseline RV from local current YAML instead of reassigning it from the live cluster.
- Time reads are internal evidence; do not announce each clock synchronization. Establish a fixed window when creating the task.
  Incremental scripts record read intervals and final draining without per-scan model clock reads. For phase-two snapshot fallback, confirm once
  that the window ended, then record `COLLECTION_STARTED_AT` only once for the entire node batch and reuse it.
  Discuss time only when agreeing on a window, before it ends, or when time evidence is abnormal.

| Phase | Retained artifacts |
|---|---|
| One | `1.1.3-draft.yaml`, `1.2.1-normalized.yaml`, `1.7-policy-snapshot.json`, `1.7-agent-inventory.json` |
| Two | `2.1.1-current.yaml`, `2.1.2-agent-inventory.json`, `2.1.3-logs/*.log`, `2.1.4-pre.json`, `2.1.5-catalog.json`, `2.1.5-attribution.json`, `2.1.6-post-seccomp.yaml`, `2.1.6-candidate.yaml`, `2.1.6-guard-diff.json`, `2.1.6-analysis.md`, `2.1.8-post-replace.yaml` |

Retain `2.1.6-seccomp-plan.json` only when Seccomp matches, retention decisions, or ambiguity decisions exist.
Incremental tasks also retain `collector.json`, `collector.sqlite`, `transfer-ledger.json`, and limited startup diagnostics. The journal transactionally stores cursors and raw records;
node logs exported at expiry feed the existing analysis chain. See [incremental collection](../references/incremental-collection.md).
Suggested task-record location: `<task-root>/varmor-policy-optimization/<cluster-context-safe>/`, using:

- VP: `vpol-<namespace>-<name>--<start>--<plannedEnd>.json`
- VCP: `vcpol-<name>--<start>--<plannedEnd>.json`

The user, workspace, or execution environment may determine `<task-root>`. The model may choose another persistent location and equivalent naming, provided it stably
distinguishes cluster, policy, and originally planned window, with absolute paths available to later entry points. Avoid temporary directories or a round's `RUN_DIR`.
For `<cluster-context-safe>`, replace filename-unsafe context characters with `_`.

Name files using the originally planned window; early closure does not rename them. Always retain the task record as the common entry point for cross-session recovery and every
trigger. Schedulers, reminders, and manual continuation reference only its absolute path. Update status to `observing`,
`collecting` (snapshot collection), `collected`, `collection-failed`, `analyzing` (incremental analysis),
`awaiting-decision`, `candidate-ready`, or `completed` as reached; do not backfill unvisited states. Phase-two claims are handled
atomically by local monitor claim/release. Recover claims left by interruptions through authorized force-release as documented in the incremental reference, preserving
analysisClaimHistory rather than letting two triggers independently read-modify-write the task file. Remove
analysisClaim when entering awaiting-decision; ignore stale fields in later states when evaluating claims.

- Perform cluster discovery/read-only checks only for user-selected preflight items, authorized observation-period incremental collection, or phase-two snapshot collection. Select
  kubectl commands from actual outputs; examples are reliable starting points, not mandatory copies when naming, labels, or installation differ.
- Node agents write directly to host `/var/log/varmor` through hostPath. Copy directly through an existing read-only node channel;
  otherwise default to incremental reads through the agent hostPath view. Snapshot fallback exports once; do not create privileged Pods or broaden node permissions.
- Read NetworkProxy version/runtime log branches only when the policy includes it; see
  [violation-log.md](../references/violation-log.md). Other policies do not need those checks.
- Scripts handle complex data reduction, deterministic transformations, and write-boundary validation. Model-generated JSON/YAML is reviewable material, not automatically
  trustworthy evidence because of its format, markers, or number of intermediate layers.
- Raw violation logs contain sensitive metadata such as application paths, processes, images, and network destinations. Create run directories with
  `install -d -m 700 "$RUN_DIR"`. After each file batch is written and before displaying anything to the user, run
  `find "$RUN_DIR" -type d -exec chmod 700 {} +` and
  `find "$RUN_DIR" -type f -exec chmod 600 {} +`. If using `umask`, treat it only as additional protection for the current shell,
  never a substitute for explicit permission restriction. Do not paste raw logs, full URLs, HostPaths, or resource JSON directly into
  conversations or reports.
- **Distinguish local files from conversation output**: Retain the complete CRD YAML actually intended for submission locally for review through its path.
  In conversation, show only object identity, policy hash, rule summaries, and structured diffs. Any inline YAML/JSON view must remove
  `managedFields` and `status` and mask Annotation values; do not rewrite or replace the complete local file for this purpose.
- Retain raw logs until analysis, user review, and necessary rollback are complete. Then follow user/organization retention requirements; do not proactively delete
  without user confirmation. When cleanup is needed, delete only this run directory and retain requested redacted reports/policy files.
  The sole exception is temporary copy directories for this run: after successfully publishing complete node logs, duplicate copies may be cleaned up. On failure retain diagnostic material
  and do not publish formal node logs.

## 3. Change boundaries (one confirmation process, no risk tiers)

This skill is **read-only** for violation logs, nodes, and application resources. Only the **current VP/VCP CRD** changes:

- Phase one: Submit a new VP/VCP.
- Phase two: Update an existing VP/VCP's rules (potentially triggering workload rollout/restart).

Before any change, including resulting workload restarts, require:

1. Successful deterministic script validation.
2. Successful `kubectl ... --dry-run=server`.
3. The **complete local CRD path + content hash**, plus a redacted policy summary and structured diff in conversation
   (deleted sources/content, enforcers, associated evidence, unmatched and ambiguous events).
4. Explicit user confirmation of the **target cluster + change content**.

Never apply without confirmation. Do not delete/recreate application Pods on the user's behalf; for Pod targets or disabled rollout settings, explain that recreation is needed.

After phase-two attribution, first show matches, unmatched events, ambiguity, implicit-baseline cases, and relaxation impacts; ask whether the user wants deletion, retention,
or further observation. Generate post-Seccomp, candidate, and guard diff only after deletion scope is decided; then still follow
steps 1-4 above for final confirmation.

## 4. Evidence record format

Every key conclusion must be traceable. Record these fields in the analysis report:

```text
target policy    kind / namespace / name (namespace empty for VCP)
window           start / end (user-provided fixed closed interval; retain original timestamps)
rule identity    source + rule(+context.targets)
enforcer         Actual event enforcer
evidence         How event fields correspond to rule restrictions
match            Established associations (possibly multiple); unmatched; ambiguous
```

Discipline:

- Use task-record `eventTimestamp` epoch bounds. Before formal collection, explicit user instructions may end observation early:
  retain `plannedEnd` and update actual `end`. Do not modify after snapshot collection starts. Running incremental tasks close early through a close request
  and collector confirmation; scope is fixed once final attribution starts. Never infer scope from log contents.
- Remove only atomic rules already present in the current policy; do not change mode/target/enforcer/control switches.
- Retain unmatched results on insufficient evidence; do not attribute from frequency, similar rule names, or subjective risk.
- Explicitly handle invalid/incomplete logs or Seccomp ambiguity according to each playbook; never silently delete.

## 5. Fail closed

Stop without changes on missing dependencies, connection failures, missing policies, non-EnhanceProtect policies, phase-two policies not
atomized or not explicitly in observation mode, window starts before snapshots, snapshot copies before window end, incremental initialization after start or incomplete final
reads, policy or agent
topology drift during observation, start/end agents NotReady or missing, inconsistent expected collection-node sets, incomplete logs/retention evidence, uncertain
attribution, schema failures, diffs containing non-deletion changes, dry-run failures, live spec differing from candidate, or missing user confirmation. Ineligible NetworkProxy evidence
separately prohibits deletions from that source. Classify errors as
DEPENDENCY / CONNECT / NOT_FOUND / SCHEMA / VALIDATION / NOT_CONFIRMED; do not misread failed queries
or empty results as absence of behavior.
