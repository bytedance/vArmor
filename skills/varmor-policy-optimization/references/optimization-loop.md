# Policy Optimization Convergence Loop and Evidence Boundaries

## 1. Core approach

The user provides an `EnhanceProtect` policy to optimize in **observation mode**. During actual application execution,
violations are logged without blocking. Read violation logs from a fixed interval, attribute events to source rules in the Policy,
report to the user first, then remove rules according to the user's decisions so the policy gradually converges toward application needs.

Violation logs should **decrease over successive rounds**. Each optimization relies only on the **confirmed closed timestamp interval + start policy snapshot + current
policy**. The snapshot is a reviewable file proving policy identity/spec stability during observation; no hidden round state is required.
After successful activation and window confirmation, create an independent task record; later restore scope and evidence from that record.

## 2. Observation periods and task scheduling

Balance observation coverage, log retention, and analysis cost:

- Too short: May miss startup, release, scaling, failover, and infrequent scheduled tasks.
- Too long: `violations.log` may rotate away early events, and each analysis grows larger.
- Default to incremental preservation during observation, followed by automatic filtering, normalization, and aggregation at expiry. Preserve already-read data locally before rotation;
  do not rely on backups surviving beyond end. See [incremental collection](incremental-collection.md) for frequency, capacity, and gap boundaries.
- Prefer a representative application cycle; use shorter windows and multiple convergence rounds for high violation rates or short retention.
- For test applications whose main behaviors can be triggered actively, suggest roughly two hours initially, then adjust to actual activity and violation rates.

Propose a period based on application cadence, planned operations, and current log rate; the user confirms `start` and `end`. Usually suggest
3-5 cycles, but prioritize representative coverage and convergence rather than enforcing a fixed count.

Always generate a task record matching `templates/observation-task.json`, regardless of scheduling support. One-shot
scheduled tasks, reminders, and manual continuation are only triggers carrying the task-record path. The incremental script collects independently and produces preprocessed input at end;
automatic triggers can read that input and summarize
attribution, while the user separately decides deletion scope and final CRD updates.

### Difference from BehaviorModeling

The approaches are similar but follow different technical paths:

| Dimension | This approach (observation-log convergence) | BehaviorModeling |
|---|---|---|
| Mode | EnhanceProtect + observation switches | BehaviorModeling |
| Path | Read violation logs -> confirm attribution -> remove source rules | Collect full behavior -> generate model Profile |
| Cost | Lightweight, fewer prerequisites | Heavier, more prerequisites |
| Period | Can be long, with repeated convergence | Fixed modeling duration |
| Trend | Violation logs decrease each round | One-time APM output |

## 3. Two phases

These are independently enterable asynchronous capabilities; they need not run sequentially in one invocation. One invocation may establish tasks for several policies
or converge several existing tasks; every task retains an independent window and evidence.

1. **Establish observation tasks**: Validate and normalize user policies, submit VP/VCP after confirmation, and save a task record for each policy/window.
2. **Periodic convergence**: Read the fixed closed-interval logs and report attribution, generate a candidate from user decisions, update the CRD after confirmation,
   and start another observation period if needed.

## 4. Evidence boundaries (mandatory)

- The window is the **closed interval `[start, end]`** from the task record. Before the first formal collection, the user may explicitly end observation early:
  retain original `plannedEnd`, set actual `end` to an already-reached time, and record why. Once collection starts, scope is fixed. Never infer scope
  from YAML, filenames, or log contents.
  For an active incremental task, submit a close request according to user instructions and let the collector confirm actual end. Once final attribution starts,
  do not modify the window or manually edit collector.json to rewrite collection evidence.
- A snapshot must record `capturedAt`, which must not be later than the window start, and bind policy UID, generation,
  spec hash, and profileName. Missing snapshots, invalid time ranges, or inconsistent validation make old windows read-only analysis inputs,
  ineligible for deletion candidates. Never fabricate a start snapshot after the window ends.
- Default incremental collection initializes every node before start and commits log lines/file positions transactionally. After end, each node needs two
  draining reads; the second starts at least one scan interval after the first completes, followed by automatic preprocessing. Unrecoverable gaps, topology drift,
  late initialization, process interruptions without verified continuity, undrained data, or missing confirmation reads make deletion ineligible. In snapshot fallback, every node log copy must begin
  after the window ends. Node logs carry collection start times and validate completion times for every file; the manifest records
  `collectedAt` and `manifestBuiltAt` separately. Never substitute preprocessing time for collection time. Both start/end agent inventories
  must be complete; collect the node union. Node additions/removals, agent Pod UID/DaemonSet identity changes, start/end NotReady,
  terminating, missing, or uncollected nodes block deletion. A single incremental read failure or NotReady with the same UID is initially suspected;
  resolve only if original active-file checkpoints remain, fingerprints are continuous, cursors catch up, and Ready recovers; retain the recovery basis.
  Collector restart requires per-node verification of pre-interruption checkpoints, original identities, and cursor continuity; newly created cursors cannot replace them.
  Node scaling and DaemonSet desired/current count changes still block deletion across the policy; original-node evidence remains available for read-only analysis.
  See [incremental collection](incremental-collection.md) for execution details.
- Apply the NetworkProxy version/runtime log matrix only when the policy includes it. Versions `<v0.10.3`, unknown versions, or micro-VM
  deterministically set `networkProxyEvidenceEligible=false`; later layers reject deletions from that source.
- Only **remove atomic rules already present in the current policy**. Do not add rules, rewrite rule contents, change mode/target/
  enforcer, or modify control fields such as `privileged`, `auditViolations`, `allowViolations`, or NetworkProxy
  `defaultAction`.
- Attribution requires actual atomic rules in the current policy, the actual enforcer in logs, and sufficient event fields.
  Similar rule names, apparently high-risk behavior, or subjective judgments do not justify attribution or deletion.
- One event may match multiple rules; association does not imply immediate deletion. Deterministic deletion-eligibility and diff checks remain mandatory.
- Retain unmatched results (`matches=[]`) when evidence is insufficient; do not force attribution or delete.
- Violation logs describe recorded runtime behavior, not every possible behavior of the workload. Absence of logs does not establish
  absence of behavior.

## 5. Two responsibility layers

| Layer | Owner | Responsibility |
|---|---|---|
| Deterministic | scripts/ | Structure parsing, catalog, enforcer compatibility, rule atomization, Seccomp plans, deletion-only diffs, schema |
| Model | Primary model | Custom-rule interpretation and evidence-based attribution from aggregated events to current atomic rules |

The model must not generate and submit YAML without script validation; reparse, validate, and obtain user confirmation before every write.
