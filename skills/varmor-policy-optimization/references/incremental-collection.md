# Incremental Collection During Observation

New observation tasks default to `scripts/monitor_violations.py`. The model discovers agent scope once, confirms log
mounts and existing read-only authorization, starts the collector, and checks readiness. A local process handles repeated log reads and preprocessing at expiry.
This changes collection only; attribution, deletion decisions, candidates, and CRD updates retain the same workflow.

## Input and startup

Input remains the existing task record: context, policy identity, fixed closed interval, start policy snapshot, and start agent inventory.
First verify agent namespace, DaemonSet, container, and log directory; scope must match the start inventory. The collector
performs only policy GET, agent DaemonSet/Pod LIST, Pod identity GET, and read-only exec in existing agents within that scope.
It creates no resources and writes no remote files. Do not ask again when existing authorization covers these actions.

When agreeing on the window, reserve initialization time and place `start` after the collector's first reads finish.
Before start, initialize EOF cursors for existing complete lines instead of downloading all history; retain the reread
position for incomplete trailing lines. Read new files appearing after initialization from the beginning. Filter the event window using actual node eventTimestamp;
never use local read time to correct node clocks or fabricate event times.
Do not independently postpone or shorten the window due to slow startup. If start has already arrived on a new launch, reject before any cluster reads.
Complete every node's EOF baseline before start; stop immediately if serial initialization crosses start or incomplete trailing lines remain.
Do not switch later nodes to full-history downloads. Retain initialized evidence and renegotiate a new window or snapshot fallback when complete evidence is needed.
Empty logs can establish coverage by creating file cursors before start,
scanning continuously, and completing final reads after end; no fabricated violation predating start is required.

Use the execution environment's persistent background-process capability, or the Unix example below when unavailable. Use absolute script/task paths;
the model discovers and fills example variables without requiring users to learn the CLI. Never print raw logs to the terminal; startup.log retains startup
errors only, while collector.json records status and gaps:

```bash
install -d -m 700 "$RUN_DIR" || exit 1
(umask 077
 nohup python3 "$SKILL_DIR/scripts/monitor_violations.py" run \
   --task "$TASK_FILE" --output "$RUN_DIR" \
   --agent-namespace "$AGENT_NS" --daemonset "$AGENT_DS" \
   --container "$AGENT_CONTAINER" --log-directory "$AGENT_LOG_DIR" \
   --interval 30 --max-read-mb 4 --max-local-mb 512 --max-transfer-mb-per-minute 16 \
   --request-timeout 30 --final-read-seconds 60 \
   --network-proxy-evidence <not-applicable|eligible|ineligible> \
   --authorized-agent-read \
   > "$RUN_DIR/collector-startup.log" 2>&1 &)
```

Append `--allow-empty-selector` only for a previously confirmed empty-selector policy.
Determine NetworkProxy source eligibility using [violation-log.md](violation-log.md); do not expand collection to micro-VM sidecars.
Remote tools required: `sh/stat -L -c/tail/head`, plus `gzip/wc` for gzip backups. Reject log-file symlinks during both enumeration and reads;
do not skip them as empty files. The log directory and its mount path must remain the trusted paths verified during discovery.
If tools are unavailable, fail and preserve evidence;
do not install them automatically or switch to unbounded full reads. Tool support in the image can be checked first through narrowly scoped read-only queries.

The log directory must exist and be readable/traversable; absence of not-yet-created log files inside it is a valid empty state. vArmor v0.10.5
[auditor initialization](https://github.com/bytedance/vArmor/blob/v0.10.5/internal/auditor/auditor.go#L175-L183)
creates the directory and logger without precreating violations.log;
[lumberjack](https://github.com/natefinch/lumberjack/blob/v2.2.1/lumberjack.go#L44-L51)
creates the file on the first Write. Missing directories, denied enumeration, and incomplete transfers are not empty logs. If a previously observed active
file identity disappears and cannot be found in retained backups, record a gap.

Read local status once after startup:

```bash
python3 "$SKILL_DIR/scripts/monitor_violations.py" status --output "$RUN_DIR"
```

`readyForWindow=true` checks running phase, process, directory lease, recent heartbeat, and that the window has not ended.
Also verify every node has `coveredFrom < start` before claiming a complete collection start. An initializing process is not
ready. The user then runs the application; do not paste log bodies into context. Recheck current status when the user returns rather than using old
ready/heartbeat values to infer liveness. Survival across sessions, sleep, and tool exit depends on the host environment.

## Scan intervals and expiry actions

- Enumerate logs and read increments every 30 seconds by default, shortening to at most every 5 seconds when backlogged. Rotate the starting node each scan to prevent
  high-traffic nodes from monopolizing the budget. Read existing files only and preserve content already saved before rotation.
- Each scan processes up to 4 MiB of new logs by default, shared across all cluster nodes in the task. Decrement across nodes and reset only next scan;
  more nodes may mean a smaller share per node, without a fair-share guarantee. A separate persistent budget shared by all nodes allows
  **16 MiB of audit-exec stdout per rolling 60 seconds**,
  including listings, fingerprints, protocol headers, rereads, and conservative reservations for failed transfers. Restart does not reset the ledger; wait when exhausted
  rather than raising limits. Pod/policy API traffic and kubectl/TLS protocol overhead are excluded; this is not a hard network/CPU quota.
  Remote reads have per-scan timeouts; collection stops at 512 MiB of local data by default.
  Threshold checks and final export may add overhead; this is not a hard disk quota. Do not independently raise agreed limits.
- Always filter the event window by `eventTimestamp` in `[start,end]`. At end, automatically enter up to 60 seconds of final
  reads/draining and identity checks, then invoke existing `collect_violations` and `preprocess_aggregate`.
  Finalization requires two post-end draining reads per node, with the second starting at least one scan interval after the first completes.
  The default 60-second budget includes that interval, final reads, and identity checks; it must exceed the scan interval. Never omit confirmation when the budget expires.
  Final reads complete the same fixed event window without extending application observation. Drain timeout or incomplete tails make deletion ineligible.
  Two confirmations reduce missed late-write risk; they do not prove arrival of arbitrarily delayed queues or all events not yet written to disk.
- Outputs remain `2.1.1-current.yaml`, `2.1.2-agent-inventory.json`, `2.1.3-logs/*.log`, and
  `2.1.4-pre.json`; phase two uses them directly without refetching remote logs or repeating the same preprocessing.
- The collector does not call the model. Automatic expiry actions are collection, filtering, normalization, and aggregation; a later invocation performs semantic attribution.
  Notifications/wakeups are outside collector responsibility. For cross-session notifications, arrange read-only status tasks according to host capabilities; if unavailable, tell
  the user to return with the task path instead of claiming a notification was scheduled.

## Deduplication, continuity, and failures

`collector.sqlite` transactionally stores complete log lines with file cursors. Identity comprises node, device/inode, file
generation, and byte position; identical text does not cause real repeated events to be discarded. Final behavior normalization/aggregation reuses
existing scripts rather than reimplementing rule attribution. Raw lines remain only in restricted local files.

Ordinary rename rotation preserves cursors; disappearance of drained backups is not a gap. When gzip replaces a same-name backup, reuse its cursor only if decompressed content has
matching prefix/boundary fingerprints at the original byte boundary. Do not commit partial lines or advance their cursors; reread next scan.
For each active/changed file, one exec batches the prefix fingerprint, old byte boundary, and increment; the model does not orchestrate these reads.
Drained logger backups with unchanged identity and stat size/mtime/ctime require metadata checks only; do not repeatedly decompress gzip.
Batching is per file, not one exec for the entire node. Each node still requires one listing exec and pre/post-read Pod GETs;
assess API metadata cost at node scale. Inventory LIST and exec are not simultaneous. Pre-read GET narrows the window for reading a replaced same-name Pod;
post-read GET verifies UID again before committing the log transaction. Retain both checks for now.

Disappearance of files with unread data, lost active-file identities, truncation/fingerprint changes, actual topology/UID/termination changes,
and undrained data remain blocking. Mark a single read failure suspected and continue; stop after three consecutive failures.
Transient NotReady with the same UID may continue evidence collection, but start/end inventories must still be completely Ready.
Bind suspicions to active-file identity/generation/offset checkpoints present when they occur. Only when those original checkpoints remain,
prefix/boundary fingerprints are continuous, cursors catch up, and agent Ready recovers may suspected issues receive resolvedAt/recoveryBasis,
preserving history while restoring deletion eligibility. One successful command, lost files, changed identity, or missing original checkpoints cannot establish
recovery; later-created cursors cannot fabricate checkpoints. The collector and preprocessor still block hard gaps even with resolvedAt.
File fingerprints cannot detect every in-place rewrite, and file continuity cannot prove
that kernel/ALS events were not lost before disk writes; losslessness is not guaranteed. Under high traffic, shorten scans or use an existing log backend;
recommendations to increase frequency cannot hide gaps in this window.

Separate process locks on the task and run directory prevent duplicate collection. After abnormal exit, resume with the **same command** before original end,
retaining cursors, parameters, and the budget ledger. Record collector-interrupted suspicions for every original node. Resolve all interruption issues only when the policy snapshot and node/
agent identities remain consistent and every node's original pre-interruption checkpoints are verified continuous and drained.
An empty directory lacking original active-file checkpoints, any node verification failure, or resumption after end prevents restoration of deletion eligibility;
successful restart alone is not recovery. Do not restart collection for expired, completed, or failed
tasks. On failure, produce pre.json with gaps when possible; otherwise retain the journal and error categories for local diagnosis.
Any gaps, invalid logs, snapshot drift, or ineligible sources continue blocking related deletions; missing collection is not evidence of no violations.

This approach retains the policy-wide node-coverage gate: node additions/removals, agent replacements, and DaemonSet desired/current changes
block deletion across the entire policy for this window; existing-node evidence remains available for read-only analysis. Rule deletion affects all policy-covered nodes;
new nodes lack pre-start baselines, so ignoring them cannot justify deletion. Explain this when agreeing on the window. Windows requiring deletion eligibility
must span stable agent topology; establish a new window after scaling rather than reclassifying old gaps as eligible.

## Phase-two task claims

The collector sets task status to `collected` on completion or `collection-failed` on failure, recording collector lastTrigger.
Every new phase-two trigger first runs local `claim --task ABS_TASK`. The script generates a unique owner; continue only after
`claimed=true`. Under the task lock, it atomically persists the claim and transitions to analyzing (incremental) or collecting (snapshot).
Another trigger returns already-claimed with existingOwner/claimedAt. Save the returned owner for this invocation's release
or genuine resumption of the same invocation; pass `--owner` explicitly for that resumption. A new scheduled wakeup must not copy another owner to impersonate resumption.
Different sessions need not reconstruct the same owner. Do not reanalyze after awaiting-decision; remove
analysisClaim when entering that state. Ignore stale claims in later states rather than reentering or releasing the task through them.
On failure, release this invocation's incomplete analysis with `release --task ... --owner ...`; never release another owner's claim.

Persistent claims have no automatic TTL, preventing concurrent takeover of long analyses. If interrupted analysis leaves a claim, first confirm the old analysis
invocation has stopped. Explain the task, old owner, claim time, and residual artifacts, then obtain explicit authorization to release that claim before running:

```bash
python3 "$SKILL_DIR/scripts/monitor_violations.py" force-release --task "$TASK_FILE" \
  --expected-owner <verified-old-owner> --reason "User authorized: previous analysis session interrupted; release claim to resume analysis" \
  --authorized-analysis-reset
```

Like `--authorized-agent-read`, this flag only declares existing authorization; it does not verify user identity/external approval or grant
new system permissions. The executor must obtain authorization as documented; the script cannot infer it. Under the task lock, the command rechecks
expected-owner and incomplete status, restores pre-claim status, and records owner, time, and reason in analysisClaimHistory,
retaining intermediate artifacts.
A new invocation then claims the task and reviews existing inputs/artifacts. Treat old-owner attribution as incomplete regardless of parseability:
ignore old `outputs.attributionFile`, rerun 2.1.5 from verified current/pre inputs,
rebuild, validate, and report attribution before updating the reference. Do not skip attribution because a file exists or reuse its unfinished decisions.
Force-release does not validate old attribution or deletion decisions, restart a failed collector, or change evidence eligibility.
Claims prevent duplicate execution only; user review and final confirmation remain required.

## User-requested early closure

When the user explicitly requests early analysis, do not kill the process and refetch old logs. Submit a close request to the same collector:

```bash
python3 "$SKILL_DIR/scripts/monitor_violations.py" close --output "$RUN_DIR" \
  --reason "User confirmed application operations complete and requested early observation closure"
```

Requests use only already-reached times. At the next safe point, the collector updates task.window.end, retains plannedEnd and the task path,
writes `endReason=user-closed-early` and `closeAppliedAt`, then performs final reads and preprocessing.
Successful submission does not establish application; check status confirmation before continuing with new end. Once final attribution starts, do not modify the window.
Automatic extension is unsupported; do not directly edit collector.json or change runtime limits.

## Legacy tasks and snapshot fallback

When no collector was started, the window has ended, or no persistent execution environment exists, use the original phase-two snapshot path. It retains
the requirements that every node copy starts after end, every file copies successfully, and the earliest retained event is no later than start.
A post-window snapshot cannot fabricate continuous collection evidence; fallback cannot clear existing gaps or guarantee recovery of overwritten logs.
