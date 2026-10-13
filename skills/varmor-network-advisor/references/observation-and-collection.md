# Bounded observation and collection continuity

Read this for live observation, before users create/recreate Pods, for long-running collection, or when troubleshooting rotation and collection failures. monitor is a local Python process; it calls no model and adds no cluster component. It requires kubectl, Pod LIST/watch, exec permission on the relevant log sources, and sh, stat (supporting `-c`), dd, head, and tail in their containers. Fail explicitly if tools are missing. A one-shot collect snapshot using cat is a fallback with weaker capabilities.

## Plan, handoff, and stopping

The default maximum duration is one hour from monitor startup. File scans run at 30-second intervals, Pod LIST recovery checks at five-second intervals, and Pod watch runs continuously. Deterministic analysis runs every five minutes when new events exist, with local analysis again at completion. Read/API latency increases actual periods; collector.json records round durations. Intervals do not guarantee execution at exact times. Users may specify an exact deadline, a short window, or a business cycle. For long windows, explain local capacity and process survival limits; prefer an existing log backend at larger scale. Never extend the deadline yourself or interpret stable/empty data as complete business coverage.

Recommend at least 10 minutes for the first interactive window, or 15 minutes for slow rollouts/multiple handoffs. This reserves preparation + user recreation + representative traffic + a final scan; it is not a hard minimum or coverage guarantee. Scheduled tasks can require a longer business cycle. An explicitly shorter window remains supported: explain the risk once and prepare all user-run commands before launch, minimizing unnecessary round trips. Do not recommend an even shorter retry after a timing failure unless changed work makes it feasible.

Select report language from the user's interaction, not the language of these instructions: prepare `observe --language zh-CN` for Chinese or `--language en` for English. `session.json.reportLanguage` is reused by periodic and final analysis. A manual `analyze --language zh-CN|en` persists a user-requested language change, including during active collection or after it stops. Keep evidence and policy values unchanged; do not restart observation merely to change report language.

After read-only checks and local policy drafting, save a complete reviewable plan and link it before asking for confirmation. Lead with a short business-language summary (target, duration, scenarios, material changes, next action). Put the technical table in the linked artifact, unless resources are a stated concern or the user requests detail. Label required confirmation clearly; a short summary without the complete plan is insufficient. Once confirmed, summarize only changes rather than presenting the same table again. User requirements take precedence; suggest defaults for unspecified items and label environment findings separately. Do not describe inferences as user requirements. Include at least:

- Context, namespace, target and matching labels, policy name and creation/reuse, retained system protection, and the change to updateExistingWorkloads=false; attach the reviewable policy file.
- Observation duration or an exact date, timezone, and deadline, plus startup, normal requests, scheduled tasks, and other scenarios to cover. Relative duration starts when monitor launches after confirmation; waiting for confirmation does not consume that duration. An absolute deadline does not move because confirmation is delayed. Observation has not started yet; do not say it is running.
- File scan, Pod LIST/watch, and analysis intervals. Explain that five-minute analysis is a local program updating reports when new data exists, not the model automatically notifying the user every five minutes.
- HTTP/TCP observation scope, actual MITM scope and HTTPS visibility, candidate path/method granularity, and separate TCP review. For reused policies, use their actual configuration rather than mechanically applying the no-decryption default.
- Log source selection and node access scope, sidecar sources that cannot yet be verified, exclusion of old Pods and the new Pod handoff, storage threshold, stopping conditions, process survival limits, and whether notifications across conversations have been arranged.

Invite users to confirm starting or revise duration, deadline, scenarios, and other options. While awaiting their reply, continue only preparation independent of confirmation; do not deploy, start collection, or ask them to recreate Pods early. Do not ask again when users explicitly request starting with the complete plan already shown or waive that confirmation. Execute the final plan after confirmation or revisions. If users confirm a revision without requesting startup, show the revised plan and wait for their start decision. If an absolute deadline has already passed at confirmation, establish a new time first rather than deploying with the expired plan or claiming startup. If final checks reveal a material change affecting authorization or execution, explain it and obtain the corresponding confirmation; do not silently expand scope.

```sh
python3 /ABS/SKILL/scripts/advisor.py monitor --session /ABS/SESSION
# Alternatively, set an explicit deadline with a timezone:
python3 /ABS/SKILL/scripts/advisor.py monitor --session /ABS/SESSION \
  --until '2026-10-11T15:00:00+08:00' --interval 30 --analysis-interval 300
python3 /ABS/SKILL/scripts/advisor.py stop --session /ABS/SESSION
```

Launch a persistent local process supported by the host tool, directing output to private files. Run the local `ready-check` immediately before handing off Pod creation/recreation, and again on the next user reply before requesting more work. If a relay delays delivery, check again at actual delivery. This verifies the process, held session/workflow leases, ready/observing phase, recent heartbeat, no stop request, and remaining time. It does not query the cluster or verify injection, effective rules, future liveness, or complete audit. State checkedAt and actual remaining time; do not treat an earlier readyAt as current readiness. Inspect the returned collectionHealth, resourcePressure and lastSuccessfulCollection too: local process health does not mean every source was read successfully. Disclose relevant collection issues and diagnose access limitations rather than assuming an unconfirmed PID is dead. The default auto source first verifies readable node files in the specified Agent scope and freezes existing namespace UIDs as the baseline. New micro-VM sidecars do not exist yet; prepare identity discovery now, but verify file readability only after injection. Explain this limitation. Short-lived sidecar files may still disappear before reading or when Pods are deleted.

```sh
python3 /ABS/SKILL/scripts/advisor.py ready-check --session /ABS/SESSION
# Only for an explicitly prepared short handoff; never changes its deadline:
python3 /ABS/SKILL/scripts/advisor.py ready-check --session /ABS/SESSION --min-remaining-seconds 0
```

The default handoff reserve is one file-scan interval plus one bounded read round; it is separate from the recommended interactive window. Exit 0 means ready at checkedAt; exit 2 returns reasons such as stale heartbeat, dead process, missing lease, elapsed deadline or insufficient remaining time. Override the reserve only when explicitly suitable for a prepared short action; never bypass process/lease/heartbeat/deadline checks. If the check fails, do not issue a fresh recreate/traffic instruction based on stale state. Explain current status and the evidence gap; preserve preparation and already granted scope. A stopped/expired phase needs a new confirmed window, not a silently extended deadline. If traffic already occurred, assess its actual capture window before interpreting results. This is a point-in-time check, not asynchronous supervision: crashes after a message is delivered remain possible.

Prepare lifecycle and representative business commands before monitor launch. Distinguish a user's total available time from the observation window, reserving time for checks, review, and validation. Once ready, immediately send a concise startup summary with the next user action and actual remaining time; attach the full plan for details. Avoid a long repeated parameter table while the clock runs. Read the actual deadline, scan/discovery/analysis intervals, and capacity from collector.json.plan. Use the session/policy and verified log sources to explain the target and actual visibility. Convert dates, deadlines, and remaining time to the user's timezone and distinguish verified from pending checks. Explain that preparation and waiting for recreation count toward the launched window, and list lifecycle and business coverage tasks for the user. Do not merely report "started" or repeat defaults. If startup fails or the deadline passes before readiness, explain that effective observation did not begin. The assistant must send this message; collector-ready program output does not establish that the user was notified.

Pod identity discovery continues from LIST resourceVersion through watch. Retain identities and nodes for new UIDs only after finding this policy's annotation and an actual proxy container. For audit arriving before UID verification, store only normalized, query-stripped evidence in pending_pods and exclude it from candidates until watch confirms identity. Exclude old UIDs even if they keep sending requests after readyAt. Keep verified identities after new Pods are deleted. Refuse startup without watch permission. Report suspected discovery gaps for watch interruption or queue overflow; LIST recovery does not prove every short-lived Pod was discovered.

Observation ends at the fixed deadline, on user stop, at the storage threshold, on configuration/identity change, or after an unrecoverable failure. Do not start new cluster reads at expiry. Already running Kubernetes subprocesses are bounded by remaining time. The final state includes the planned deadline, readyAt, actual duration, last successful read, unread backlog, and stop reason. Final local analysis and process cleanup may finish later without extending cluster collection. stop is cooperative and is handled after the current bounded read returns.

The policy remains in observation configuration with updateExistingWorkloads=false. Do not automatically change workloads, delete evidence, or enable enforcement. An ended session cannot run monitor again.

## User-requested changes to a running deadline

Users may explicitly shorten or extend an observation that is still running and has not expired; the original one-hour default is not a limit on requested changes. "Observe for another 30 minutes" counts from this request; "extend by one hour" adds to the current deadline; "observe for two hours total" uses collector.startedAt. Interpret exact dates in the user's timezone. Clarify ambiguous or past times; use stop for "end now". An explicit change request is authorization, so do not reconfirm it. Explain capacity and business coverage implications of an extension. Never extend observation yourself.

```sh
# Assistant interfaces; users need not invoke them. duration is remaining seconds from submission.
python3 /ABS/SKILL/scripts/advisor.py reschedule --session /ABS/SESSION \
  --duration 1800 --reason 'User requested another 30 minutes'
python3 /ABS/SKILL/scripts/advisor.py reschedule --session /ABS/SESSION \
  --until '2026-10-11T16:00:00+08:00' --reason 'User requested a later deadline'
```

reschedule submits a local request only. It does not change policies/workloads, restart the collector, or reset baseline UIDs, cursors, or evidence. deadline-change-requested acknowledges submission. Check the same requestId in collector.json.lastDeadlineChange; report that the change took effect only when status=applied and plan.until contains the new deadline. Show the old and new deadlines, actual remaining time, and that other parameters retain their planned values. For status=rejected, explain the reason and current state. If no acknowledgment exists, report pending application; do not present a requested time as the effective plan. Wait for acknowledgment before another request; never overwrite a pending request. If native notification scheduling has its own end time, synchronize it with the user's request yourself; the collector does not change that schedule.

Changes are processed at a safe point after the current collection/analysis round, so application may be delayed. Shortening to a time that is about to expire does not guarantee immediate interruption of the current round. Once applied, no new reads start beyond the new deadline. A request cannot revive observation after the old deadline; even a request submitted before expiry may be rejected if it was not applied in time. User stop takes priority over a pending extension. Changes are retained in collector.json.deadlineChanges. Recovery uses the latest applied deadline, without extending it because of new monitor arguments or pending requests.

Do not claim successful continuous extension if the deadline has passed, phase=stopped, or the collector is dead. An interrupted but unexpired session may first resume with a suspected gap disclosure, then accept the user's change request. Expired/ended observation requires a new session: explain the gap, retain old results, confirm a new plan, and hand off recreation only after the new collector is ready. Do not bypass these boundaries by editing collector.json or restarting monitor.

## File cursors, capacity, and recovery

Each round obtains the device/inode/size for violations*.log and tracks renamed rotation files. Record events by source, file identity, generation, and byte position. SQLite commits events, normalized pending evidence, and cursors together. Do not advance past a partial line; reread it next round rather than treating it as a malformed record. Cursors retain offsets and trailing fingerprints only, not raw fragments containing queries. A file shrinking or a changed trailing fingerprint starts a new generation and reports a suspected continuity gap.

The default incremental processing budget is 4 MiB per round. Rotate source order so busy nodes do not always go first. Batched node prefetch may run concurrently, while the main thread commits SQLite changes. Trailing checks, block alignment, and rereads after resets add transport bytes; this budget is not an exact bandwidth limit. Known backlog shortens the next interval only to the agreed minimum (default five seconds), never below it. This guarantees neither throughput nor lossless collection: shared node audit can rapidly fill retained files, and exec latency, network, and local storage are finite. The default session storage stop threshold is 512 MiB; adjust with --max-session-mb / --max-read-mb. Thresholds are checked between rounds, so the current batch and final report can exceed them. They are not hard disk quotas; never delete old evidence to make room. An anomalous record exceeding 1 MiB without a newline is explicitly recorded as a local discard to prevent unbounded buffering.

After a crash, monitor may resume the same session only before the latest applied deadline. Reuse the applied source configuration, intervals, and capacity settings; new arguments must not automatically extend observation. Do not classify new Pods present at recovery as baseline Pods. Reject deadline requests that had not been acknowledged as applied before the crash; if still needed, resubmit after recovery readiness. Report a suspected interruption gap. Retained files may allow catch-up, but overwritten logs cannot be guaranteed recoverable. Host sleep, restart, or tool process termination can interrupt observation. Check collector.json update times and process state; historical readyAt alone does not prove it is running now.

Both the absolute wall deadline and monotonic phase budget are checked before
new work; a backward clock change cannot extend the monotonic budget. After
resuming past the absolute cutoff, do not start another read or accept a pending
extension of the expired window. In-flight work may have been interrupted;
never claim host sleep was observed. `elapsedSeconds` is wall duration, while
`observedSeconds` is sampled collector runtime, excludes detected discontinuities
and does not measure continuous request capture or complete business coverage.
Clock/monotonic disagreement over two seconds or a heartbeat interval exceeding
the maximum of 60 seconds and round limit plus 30 seconds creates a suspected
timing gap. The entire uncertain interval is conservatively excluded. Old
sessions without runtime samples cannot have their elapsed history reconstructed.

monitor and manual analyze use separate process leases/round locks; only one monitor is allowed per session. Do not mix snapshot collect, offline, and incremental data. Historical --since sessions do not enter new-Pod observation mode. One-shot collect/cycle reads all retained rotated files by default but has no cursor continuity assessment; its report is not-assessed.

If snapshot cat encounters a specific exec stream read error, it tries chunked rereads using stat/dd. Retries must not bypass permission errors. Rotation or truncation during chunked reading causes rejection of the mixed snapshot; suggest retrying or using monitor. This remains a snapshot and does not provide continuous collector gap detection.

## Gap classification and reporting

| State | Evidence and interpretation |
|---|---|
| confirmed-gap | Known unread file bytes disappeared and the file identity is absent from retained files, or oversized anomalous records were explicitly discarded locally. This confirms a log-source gap; whether target events were affected and how many may be unknown. |
| suspected-gap | An active file identity disappeared, a file reset occurred, reading/discovery was interrupted, a process resumed, or unread backlog remained at completion. Continuity is at risk; do not assert specific event loss. |
| identity-incomplete | Collected evidence has unverified Pod UIDs and is temporarily excluded from candidates. Unresolved identity is not equivalent to file loss. |
| no-detected-gap | No gap was detected within the assessable scope; event completeness is still not guaranteed. |
| not-assessed | Snapshot/offline input was not checked for file continuity. |

A normal rename with the file retained is not loss. Expiry of a fully read, inactive rotation file does not automatically trigger an alert. Even perfectly continuous files cannot reveal event drops before writing. Without reliable generation/receipt/persistence sequence numbers or drop metrics, do not claim end-to-end ALS loss detection. Use the last successful read and detected anomaly to describe a detection window. Do not guess the exact loss time or assume every event timestamp equals its log write time.

report.md, analysis.json, and collector.json show collection state alongside business coverage limits. Gaps may still permit reviewable candidates based on verified evidence; disclose incompleteness and suggest that the user rerun affected startup, normal-request, or scheduled-task scenarios. Do not automatically broaden permissions, deploy enforcement, recreate Pods, or extend observation. No new traffic, 100% replay coverage, and stable candidates do not prove complete business coverage.

## Enforced resource budgets

Use monitor for both observation and separate enforcement evidence windows. The
confirmed resource plan includes --min-interval (default min(5, regular interval)),
--max-read-mb (default 4 MiB new-data processing per round, 2..64),
--max-transfer-mb-per-minute (default 16 MiB, rolling audit exec stdout),
--max-concurrent-reads (default 2, 1..8), --max-round-seconds (default 30, 1..120),
and --max-session-mb (default 512 MiB local stop threshold).

The rolling byte ledger counts response framing, fingerprint overlap and fallback
reads, conservatively charging reserved bytes after a failed transfer. It is
shared by the original observation and its enforcement phases, so phase changes
do not refill the quota. A workflow lease permits only one collector. Reads wait
for in-flight reservations or report quota pressure; no automatic cap increases.
After target UIDs identify nodes, only relevant/historical sources are read;
preflight still checks Agent sources before user recreation.

The byte quota is not total network bandwidth: API/LIST/watch, TLS and kubectl
protocol overhead are excluded. Concurrency, fixed discovery intervals and
Kubernetes round deadlines bound requests; no hard CPU/RAM percentage is claimed.
Local storage is a stop threshold, not an OS disk quota; SQLite transactions and
bookkeeping may add bounded overhead before the next check. Analysis cadence
stays independent of collection. Do not promise a resource or lossless guarantee
beyond these measured boundaries.

collector.json.resources reports windowBytes, totalBytes, limitedAttempts,
peakConcurrentReads and quota scope; resourcePressure/nextScanDelaySeconds explain
backlog and throttling. sourceCapturedAt records source read starts. Explain that
known backlog and limited reads can leave unseen newer bytes too. Do not infer
zero missing events from a zero *known* backlog. Reports put evidence limits and
resource pressure before replay coverage.

Resource caps are fixed for a running phase; reschedule changes only its deadline.
Do not edit the plan or restart the collector to obtain a fresh budget. If limits
are inadequate, retain evidence and stop with the gap disclosed; agree a future
plan or log backend instead of silently increasing reads.

A workflow with a resource plan rejects unbounded live collect snapshots, including
when initialization fails before readiness. Diagnose or start another bounded
phase with explicit user authorization; do not bypass the budget on recovery.

## Timeout diagnostics and concise recovery

A timed-out kubectl call records safe `errorDetails`: `stage`, original `exceptionType`, operation `command` summary, `timeoutSeconds`, `deadlineRemainingSeconds`, `deadlineBounded`, and timeout `kind`. The command omits context, credentials, request bodies and remote scripts; subprocess output/stdin is not copied. A fatal timeout before the overall deadline records these in collector.json and the observation-stopped gap. Recoverable source-discovery/read timeouts carry the same details in collection-health issues. An elapsed overall observation deadline remains a normal bounded stop. Legacy/native timeouts without a diagnostic may contain only type, stage and timeout; do not invent the missing command.

Tell the user whether collection stopped, which time window lacks evidence, and the next practical choice in a few sentences; offer the diagnostic artifact for detail. A timeout identifies the failed operation and bounds, not its root cause. Do not infer network/cluster load, increase caps, extend time, or repeat speculative retries automatically. Read-only diagnosis within scope can proceed; a replacement observation still needs its complete plan confirmed. Reuse unchanged target, policy draft and access scope rather than requiring the user to answer the same setup questions again.
