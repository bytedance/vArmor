# Phase Two: Converge Observation Tasks

Restore context from task records and complete "collection -> attribution report -> user decision -> candidate -> confirmed update". This phase may run
asynchronously after phase one or be entered independently in a new invocation or session.

Input is the absolute path to one or more task records. One invocation may process multiple tasks or read multiple node logs for one task;
restore policy identity, context, window, and start evidence independently, with separate run directories and reports. Scheduled tasks,
reminders, and manual actions are different entry points without reliance on conversation memory. Automatic triggers may collect, analyze, and summarize attribution; if deletion scope
is undecided, stop at 2.1.5 rather than filling user decisions or automatically updating CRDs.

Choose failure checks and file-permission safeguards according to the [execution contract](README.md), restoring this run's variables. A failed command
does not become successful because a subsequent chmod succeeds.

## 2.1 Single-task workflow

### 2.1.0 Read the task and determine the effective window

First read the task record; verify `status`, `clusterContext`, policy identity, `window`, snapshot paths, and start inventory.
Normal expiry, scheduled triggers, and manual triggers follow the same path.

**Identify collection mode first**: If `outputs.collectorDirectory` is nonempty, follow
[incremental collection](../references/incremental-collection.md) and read local state using `monitor_violations.py status`.
Continue observation while running, or wait for final reads to complete; do not repeat exec/cp. If `phase=finished` and the pre.json window matches the task,
reuse that directory and existing current/inventory/pre. Gaps or `collectionComplete=false` permit read-only analysis only.
On collection failure, explain error categories and available evidence; snapshot fallback cannot erase gaps.

If, before the first formal collection, the user explicitly states application operations are complete and requests early analysis, treat that message as confirmation to end
the window early. Read current epoch once (or use an explicitly supplied already-reached time), keep `plannedEnd` unchanged, and set
`window.end` to that time, `endReason=user-closed-early`, and `updatedAt` accordingly. Effective `end`
must not precede `start`; update before collecting. Do not suggest a separate future short window.

Direct updates above apply to snapshot tasks with no collector started. For running incremental tasks, submit the same user request through `monitor_violations.py close`
and confirm `closeAppliedAt` and actual task end before continuing; do not directly edit state files or terminate the process.

Claim only after expiry/early-closure handling. Incremental tasks must wait for collector completion with status collected/collection-failed
and collector-written lastTrigger; snapshot tasks still begin at observing and require actual end to have arrived.
Run `monitor_violations.py claim --task <absolute-task-path>`. The script generates and returns this invocation's owner; continue only after
claimed=true and retain the owner. End duplicate triggers on already-claimed or awaiting user decision. Genuine resumption of the same invocation
may explicitly pass its original owner; new scheduled wakeups must not copy it. Release stale claims using the authorized force-release
workflow in the incremental reference, without manual JSON edits or automatic age-based takeover. Claims atomically enter analyzing (incremental) or collecting (snapshot). On this invocation's failure,
release the incomplete task without overwriting another invocation's claim. Failed-collection pre.json remains read-only; successful
claiming does not grant deletion eligibility. If pre.json is missing, report collection failure before attribution.

When reclaiming after force-release, ignore old `outputs.attributionFile` and rerun
2.1.5 using verified current/pre inputs. Rebuild, validate, and report attribution before updating the reference. An existing parseable old file cannot justify skipping attribution
or reusing unfinished user decisions.

Once formal collection starts, the snapshot task's effective `end` is fixed for this round. Incremental-task scope becomes fixed upon final attribution.
Any earlier exploratory snapshot export preceding effective `end`
is not a formal collection artifact; recollect after effective `end`. Task state prevents duplicate execution by scheduled and manual
entry points. Snapshot claim writes `lastTrigger` and enters `collecting`; the collector completes the incremental log stage,
then claim enters analyzing without collecting again. Tasks already in later states do not repeat collection.
On early manual triggering, cancel external scheduled tasks where supported; otherwise later triggers read task state and exit.

### 2.1.1 Fix scope and verify the baseline

Use epoch seconds from the task record, filtering by `eventTimestamp`. Convert user ISO8601 once and
retain the original value. Verify effective `end` has arrived, context exactly matches the record, and actual agent/manager versions; select
applicable branches from 2.2. Each snapshot-fallback round uses a fresh directory recorded as `outputs.latestRunDirectory`;
incremental mode uses the independent directory already created by the collector.

**Incremental mode**: Locally revalidate collector `2.1.1-current.yaml` with `validate_policy --require-observation
--require-atomic-capabilities` and `hash_policy verify-snapshot --window-start`, restoring
RV from that file. Verify window, nodes, and source eligibility agree across collector/pre/task, then go directly to 2.1.5. Skip remote
exports below and 2.1.2-2.1.4. Preserve collector evidence. Still verify live RV before final replace.
Reuse empty-selector opt-in only if confirmed in phase one. If current RV is stale due to status changes, rebind the baseline through the normal review
workflow rather than replacing a reviewed value directly with a new remote RV.

**Commands in 2.1.1-2.1.4 below are snapshot fallback for legacy tasks**; see the incremental reference for new-task startup and automatic preprocessing.

```bash
EXPECTED_CTX="<clusterContext from this task record>"
CTX="$(kubectl config current-context)" || exit 1
test -n "$CTX" || exit 1
test "$CTX" = "$EXPECTED_CTX" || exit 1
kubectl --context "$CTX" cluster-info || exit 1
RUN_DIR="<independent run directory for this task and round>"
install -d -m 700 "$RUN_DIR" || exit 1

kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
  -o yaml > "$RUN_DIR/2.1.1-current.yaml" || exit 1
chmod 600 "$RUN_DIR/2.1.1-current.yaml" || exit 1

python3 scripts/validate_policy.py --file "$RUN_DIR/2.1.1-current.yaml" \
  --require-atomic-capabilities --require-observation \
  --quiet-notices > /dev/null || exit 1

RV="$(python3 scripts/hash_policy.py verify-snapshot \
  --file "$RUN_DIR/2.1.1-current.yaml" \
  --snapshot <absolute-start-policy-snapshot-path> \
  --window-start <start> --resource-version-only)" || exit 1
test -n "$RV" || exit 1
```

Validation must establish:

- The object retains the same UID, generation, `status.profileName`, and spec hash;
- `start >= policySnapshot.capturedAt`;
- Aggregate capability rules are expanded;
- `auditViolations=true` and `allowViolations=true`;
- Only `EnhanceProtect` is processed, without changing target, mode, enforcer, or control switches.

Status-only `resourceVersion` changes do not block, but `$RV` binds the round's baseline and must be compared again before final apply.
Do not persist snapshot-validation output separately; record findings in `2.1.6-analysis.md`.
RV is the local current version; restore it from that file across shells, never overwrite the baseline with a new remote RV.

### 2.1.2 Generate the end inventory

Confirm agent DaemonSet, namespace, and container as in phase one. Generate inventory directly from standard
mixed Kubernetes List input without saving raw DaemonSet/PodList dumps:

```bash
(set -o pipefail
 kubectl --context "$CTX" get daemonset,pods -n "$AGENT_NS" -o json \
   | python3 scripts/build_agent_inventory.py \
       --cluster-snapshot - \
       --daemonset-name "$AGENT_DS" \
       --daemonset-namespace "$AGENT_NS" \
   > "$RUN_DIR/2.1.2-agent-inventory.json") || exit 1
chmod 600 "$RUN_DIR/2.1.2-agent-inventory.json" || exit 1
```

Start/end inventories compare DaemonSet UID/generation/desired/current/ready, every owned Pod, node,
Pod UID, Ready, and terminating state. Node changes, Pod replacement, or incomplete inventory at either endpoint block deletion.

### 2.1.3 Export logs node by node in batches

Use this section only for snapshot fallback; the script handles node reads for default incremental tasks.

After verifying actual hostPath mappings, collect serially from the union of start/end nodes. Do not filter nodes by Ready.
Use an existing read-only node channel or authorized agent exec/cp. Set `L4_AUTHORIZED=yes` according to session authorization;
do not enter privileged containers without it. Avoid repeated grep/cat inside containers; `kubectl cp` does not expand globs.
Before traversing nodes, read epoch once as the batch collection start and confirm the window ended. Subsequent nodes reuse that value without repeated
clock reads. Complete enumeration, exact-path retention, copying, and publication for each node within the same Bash invocation:

```bash
test "$L4_AUTHORIZED" = yes || exit 1
WINDOW_END=<end>
COLLECTION_STARTED_AT="$(date +%s)" || exit 1
test "$COLLECTION_STARTED_AT" -ge "$WINDOW_END" || exit 1
# Traverse nodes in this same Bash invocation; the node block below reuses the same COLLECTION_STARTED_AT.
REMOTE_OUTPUT="$(
  [ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec \
    -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
    sh -c 'test -r /var/log/varmor/violations.log &&
      find /var/log/varmor -maxdepth 1 -type f \
        \( -name "violations.log" -o -name "violations-*.log" \
           -o -name "violations-*.log.gz" -o -name "violations.log.*" \) -print'
)" || exit 1
test -n "$REMOTE_OUTPUT" || exit 1
REMOTE_FILES=()
while IFS= read -r remote; do
  test -n "$remote" && REMOTE_FILES+=("$remote")
done <<< "$REMOTE_OUTPUT"
printf '%s\n' "${REMOTE_FILES[@]}" \
  | grep -Fx '/var/log/varmor/violations.log' >/dev/null || exit 1
STAGING="$(mktemp -d "$RUN_DIR/.copy-XXXXXX")" || exit 1
LOG_ARGS=()
for remote in "${REMOTE_FILES[@]}"; do
  local_file="$STAGING/${remote##*/}"
  kubectl --context "$CTX" cp "$AGENT_NS/$AGENT_POD:$remote" \
    "$local_file" -c "$AGENT_CONTAINER" || exit 1
  # kubectl cp may preserve the remote mtime; record local copy completion.
  touch "$local_file" || exit 1
  LOG_ARGS+=(--file "$local_file")
done
python3 scripts/finalize_node_log.py "${LOG_ARGS[@]}" \
  --output "$RUN_DIR/2.1.3-logs/$NODE.log" \
  --window-end "$WINDOW_END" --started-at "$COLLECTION_STARTED_AT" || exit 1
rm -r -- "$STAGING"
```

The script processes local copies only, requiring collection start no earlier than `window.end` and each file completion no earlier than collection start.
It validates JSON/timestamps, decompresses and preserves content, then atomically publishes a 0600 node log carrying collection start; existing files cannot be overwritten.
On failure retain temporary material without publishing formal logs. Do not save exit-code files or permanent `raw/` directories.

After each batch is written, run:

```bash
find "$RUN_DIR" -type d -exec chmod 700 {} + || exit 1
find "$RUN_DIR" -type f -exec chmod 600 {} + || exit 1
```

### 2.1.4 Generate `pre.json` in one step

`preprocess` handles the manifest, node-log merging, fixed-window/profileName/optional policy-identity
filtering, cleaning, and aggregation in memory, without generating `manifest.json`, `merged.log`, or `collected.json`:

```bash
python3 scripts/preprocess_aggregate.py preprocess \
  --start-agent-inventory <absolute-start-agent-inventory-path> \
  --end-agent-inventory "$RUN_DIR/2.1.2-agent-inventory.json" \
  --window-start <start> --window-end <end> \
  --node <n1> --log "$RUN_DIR/2.1.3-logs/<n1>.log" \
  --node <n2> --log "$RUN_DIR/2.1.3-logs/<n2>.log" \
  --policy "$RUN_DIR/2.1.1-current.yaml" \
  --network-proxy-evidence <not-applicable|eligible|ineligible> \
  > "$RUN_DIR/2.1.4-pre.json" || exit 1
chmod 600 "$RUN_DIR/2.1.4-pre.json" || exit 1
```

Derive filter identity directly from current kind/namespace/name/status.profileName to avoid using another policy's copied parameters.
`2.1.4-pre.json` is the only collection input for later steps and embeds:

- `collectionManifest`: Window, start/end topology, per-node earliest/latest, read and retention evidence;
- `collectionCounts`: Matched, outside-window, identity-mismatch, parse-error, and other filter counts;
- `collectionComplete`, `retentionCovered`, `seccompSyscalls`, `aggregatedEvents`.

The manifest derives `collectionStartedAt/collectedAt` from node-log collection-start metadata, recording
`manifestBuiltAt` separately. Every node must
be collected after end; preprocessing runtime cannot substitute for collection time. Only `collectionComplete=true` permits
candidate generation. Every node must retain an event no later than start;
empty logs or earliest events after start make retention unknown. For `matched=0`, first diagnose
`profileMismatch/policyIdentityMismatch/missingIdentity` rather than assuming no violations.
See [violation-log.md](../references/violation-log.md) for log envelopes.

### 2.1.5 Build and report attribution

First generate the non-Seccomp attribution catalog:

```bash
python3 scripts/preprocess_aggregate.py catalog \
  --file "$RUN_DIR/2.1.1-current.yaml" \
  > "$RUN_DIR/2.1.5-catalog.json" || exit 1
```

Also run the Seccomp plan, initially inspecting stdout without saving it. Initial output lists pending candidates only and causes no deletions:

```bash
python3 scripts/seccomp_plan.py \
  --policy "$RUN_DIR/2.1.1-current.yaml" \
  --pre "$RUN_DIR/2.1.4-pre.json" || exit 1
```

Using `2.1.4-pre.json.aggregatedEvents` and `2.1.5-catalog.json.ruleCatalog`, write
the structure in [attribution.json](../templates/attribution.json) to
`$RUN_DIR/2.1.5-attribution.json` (a plain array, without an outer wrapper object):

- Initially write only `eventId`, `summary`, and `matches`; do not fill `decision` on the user's behalf;
- Add a match only when event fields, rule restrictions, and enforcer definitely align;
- One event may match multiple rules; inspect every candidate rather than stopping at the first;
- Copy RawRule catalog coordinates verbatim; targets require full executable-path/Profile evidence;
- When a capability atom corresponds to multiple application-semantic rules, the event proves only its direct semantics; retain unmatched results if evidence is insufficient;
- With `networkProxyEvidenceEligible=false`, NetworkProxy matches must be empty.
- When current policy `privileged=false`, the catalog still contains only explicit atoms. Also read
  [implicit-baseline semantics](../references/enhance-protect-semantics.md#3-implicit-baseline-important-blind-spot) and check
  whether `matches: []` events are definitely attributable to RuntimeDefault. If so, record them only as baseline-originated in the report;
  do not fabricate catalog matches or deletion coordinates. Keep unmatched when evidence remains insufficient.

Validate event IDs, exact coordinates, and enforcers first, without saving stdout:

```bash
python3 scripts/validate_attribution.py \
  --pre "$RUN_DIR/2.1.4-pre.json" \
  --catalog "$RUN_DIR/2.1.5-catalog.json" \
  --attribution "$RUN_DIR/2.1.5-attribution.json" > /dev/null || exit 1
```

Attribution must cover every eventId in `aggregatedEvents` exactly once. Even without an established association, write
`matches: []` rather than omitting the event.

#### Attribution report

After attribution validation, organize and show:

- Window, collection completeness, node coverage, and retention findings;
- Matching events grouped by application semantics, rule coordinates, Enforcer, and matching rationale;
- Events matching several rules, Seccomp ambiguity, and the scope relaxed by deletion;
- Unmatched events, insufficient evidence, implicit-baseline sources, and items suggested for further observation;
- Seccomp pending candidates, explicitly stating no candidate has been generated and no cluster changes have occurred.

Established attribution means application behavior triggered a rule, not that the user agreed to removal. After reporting, ask whether the user wants deletion, retention, or continued
observation. Set task status to `awaiting-decision`, record `outputs.attributionFile`, and remove
`analysisClaim`. Ignore stale claims in later states rather than treating them as active. Stay in this section until the user provides
the deletion scope; do not generate post-Seccomp, candidate, or guard diff beforehand.

Once the user understands attribution, group Seccomp pending candidates and all established matches by application impact and ask for individual
or group decisions:

- Seccomp: Explicit remove/keep for each built-in rule and each custom syscall atomic group;
  separately confirm acceptance of broader allowance when ambiguous;
- Each non-Seccomp match: `remove`, `keep`, or `observe`.

After confirmation, write non-Seccomp decisions to each match's `decision` and rerun
validation with `--require-decisions`. Decisions must agree when the same rule coordinates occur in multiple events.
`2.1.5-attribution.json` serves as both attribution evidence and user-decision record; do not generate separate `removal-decision.json`
or `removals.json`. Enter 2.1.6 if confirmed deletions exist; if everything is kept or under observation, record the outcome and set the task
to `completed`. Establish a new task via 2.1.8 if further observation is needed.

### 2.1.6 Generate the candidate and run the strict guard

Generate the post-Seccomp baseline from user decisions. Every candidate requires an explicit decision; a missing parameter yields
`decisionsComplete=false`, failing both apply and guard. If Seccomp matches, retention decisions, or ambiguity decisions exist, save
the final plan as `2.1.6-seccomp-plan.json`; otherwise generate only post-Seccomp YAML:

```bash
python3 scripts/seccomp_plan.py \
  --policy "$RUN_DIR/2.1.1-current.yaml" --pre "$RUN_DIR/2.1.4-pre.json" \
  [--remove-seccomp-rule <rule> ...] [--keep-seccomp-rule <rule> ...] \
  [--remove-seccomp-syscall <syscall> ...] [--keep-seccomp-syscall <syscall> ...] \
  [--allow-ambiguous] \
  > "$RUN_DIR/2.1.6-seccomp-plan.json" || exit 1  # When matches/retention/ambiguity decisions exist

python3 scripts/seccomp_plan.py \
  --policy "$RUN_DIR/2.1.1-current.yaml" --pre "$RUN_DIR/2.1.4-pre.json" \
  --apply [--remove-seccomp-rule <rule> ...] [--keep-seccomp-rule <rule> ...] \
  [--remove-seccomp-syscall <syscall> ...] [--keep-seccomp-syscall <syscall> ...] \
  [--allow-ambiguous] \
  > "$RUN_DIR/2.1.6-post-seccomp.yaml" || exit 1
```

`SCMP_ACT_ALLOW/LOG` belongs only in the ignored list, never deletion candidates. `customRemovals` must retain complete RawRule
atoms. `unmatchedSyscalls` produces no decisions. Decide custom rules by whole syscall group, without partial selection within a group;
use independent rule parameters for built-ins. Retaining one candidate does not establish others; any remaining deletion for an originally multi-rule syscall
still requires `--allow-ambiguous`.

Both candidate and guard derive coordinates directly from attribution decisions:

```bash
python3 scripts/apply_removals.py \
  --baseline "$RUN_DIR/2.1.6-post-seccomp.yaml" \
  --pre "$RUN_DIR/2.1.4-pre.json" \
  --attribution "$RUN_DIR/2.1.5-attribution.json" \
  > "$RUN_DIR/2.1.6-candidate.yaml" || exit 1

python3 scripts/guard_removal.py \
  --baseline "$RUN_DIR/2.1.1-current.yaml" \
  --candidate "$RUN_DIR/2.1.6-candidate.yaml" \
  --pre "$RUN_DIR/2.1.4-pre.json" \
  --attribution "$RUN_DIR/2.1.5-attribution.json" \
  [--remove-seccomp-rule <rule> ...] [--keep-seccomp-rule <rule> ...] \
  [--remove-seccomp-syscall <syscall> ...] [--keep-seccomp-syscall <syscall> ...] \
  [--allow-ambiguous] \
  > "$RUN_DIR/2.1.6-guard-diff.json" || exit 1
```

The guard recomputes Seccomp/non-Seccomp deletions from original current + pre, requires exact full equality with the expected candidate,
and rejects additions, rewrites, control-field changes, or unapproved deletions. The model must not manually edit YAML.

Write the report using [optimization-analysis.md](../templates/optimization-analysis.md) to
`$RUN_DIR/2.1.6-analysis.md`, covering snapshots/topology/retention, attribution, user decisions, unmatched events, the Seccomp plan, and
guard diff. Finally restrict permissions and compute the candidate hash:

```bash
find "$RUN_DIR" -type d -exec chmod 700 {} + || exit 1
find "$RUN_DIR" -type f -exec chmod 600 {} + || exit 1
CANDIDATE_SHA256="$(python3 scripts/hash_policy.py fingerprint \
  --file "$RUN_DIR/2.1.6-candidate.yaml" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')" || exit 1
```

Copy this hash verbatim into the analysis review record; restore `CANDIDATE_SHA256` from that reviewed record in new shells.
Set task status to `candidate-ready` and record `outputs.candidateFile`.

### 2.1.7 Dry-run, final confirmation, and replace

Run server dry-run first. Since the candidate expresses deletions through complete-object semantics, phase two uses `replace`; do not repeat hash
or resourceVersion checks here because dry-run makes no changes:

```bash
kubectl --context "$CTX" replace \
  -f "$RUN_DIR/2.1.6-candidate.yaml" --dry-run=server || exit 1
```

Provide local candidate/analysis paths, `CANDIDATE_SHA256`, redacted summaries, guard diff, target
context, and activation boundaries. After a second explicit confirmation of cluster and final changes:

```bash
RV="$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["metadata"]["resourceVersion"])' \
  "$RUN_DIR/2.1.1-current.yaml")" || exit 1
CURRENT_RV="$(kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
  -o jsonpath='{.metadata.resourceVersion}')" || exit 1
test -n "$RV" && test "$CURRENT_RV" = "$RV" \
  && python3 scripts/hash_policy.py verify \
       --file "$RUN_DIR/2.1.6-candidate.yaml" --hash "$CANDIDATE_SHA256" \
  && kubectl --context "$CTX" replace -f "$RUN_DIR/2.1.6-candidate.yaml"
```

This command guards against remote policy drift while waiting for confirmation, accidental local candidate edits, and wrong-file selection. kubectl
resourceVersion conflicts remain the final concurrency safeguard.

### 2.1.8 Verification and the next window

First read the updated object and verify live `spec` equals candidate:

```bash
kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
  -o yaml > "$RUN_DIR/2.1.8-post-replace.yaml" || exit 1
python3 scripts/guard_removal.py --verify-live \
  --candidate "$RUN_DIR/2.1.6-candidate.yaml" \
  --live "$RUN_DIR/2.1.8-post-replace.yaml" > /dev/null || exit 1
```

Then follow phase-one 1.6 to inspect VP/VCP and ArmorProfile loading counts and failure conditions. AppArmor/BPF rely on actual
Profile-loading results; Seccomp/injection changes require new containers. `updateExistingWorkloads=true` primarily applies to
policy creation/deletion; do not assume rule updates automatically roll out. Required recreation must be performed by the user or separately authorized before
starting another window. See [lifecycle and activation boundaries](../references/policy-crd-lifecycle.md).

Once updates and required new Pods actually take effect, create snapshots, start inventories, and tasks in a new round directory as in phase-one 1.7,
then agree on the next fixed window. Persist read-only/no-deletion reports using the template too, marking unexecuted diff/update steps N/A.
Usually suggest 3-5 cycles, but judge by application coverage and violation convergence rather than a hard count.

## 2.2 Branches and exceptions

| Condition | Action |
|---|---|
| Missing start policy snapshot | Read-only analysis; no candidate. Create a new snapshot of the current policy and restart the window |
| Missing start inventory | Node coverage unproven; no deletion; restart the window |
| Incremental collection finished with complete pre.json | Reuse local input; skip snapshot collection and repeated preprocessing |
| Incremental initialization later than start | Reject new startup immediately; stop initialization crossing start without downloading all history |
| Unrecoverable log gaps, interruptions, or unconfirmed final draining | Read-only analysis; no deletion; retain evidence and agree on another window |
| Single read failure, same-UID transient NotReady, or collector restart before end | Verify original pre-issue checkpoints/identities; restore eligibility only after every node continuously catches up, preserving recovery history |
| No collector started and window ended | Use original snapshot fallback without fabricating incremental continuity |
| Empty selector | Pass `--allow-empty-selector` only for policies separately confirmed in phase one |
| v0.10.0 | Incompatible only if `copy-fail-mitigation` is actually used |
| v0.10.1-v0.10.5 | Catalog `verificationEvidence` verifies identical implementations; do not reject patch-version mismatches |
| Other/unknown versions | Mark only actually used built-in rules compatibility unknown; manual verification required |
| No NetworkProxy | Pass `--network-proxy-evidence not-applicable`; skip its version branches |
| NetworkProxy `<v0.10.3` or unknown version | Pass `ineligible`; prohibit deletion only from this source |
| NetworkProxy `v0.10.3+` + runc node logs | Pass `eligible` when the evidence chain is complete |
| NetworkProxy + micro-VM | Pass `ineligible`; read-only analysis |
| `kubectl cp`/tar unavailable | Use 2.2.1 single streaming export; publish after local validation, never formal logs on failure |
| Seccomp matches multiple rules | Block by default; pass `--allow-ambiguous` only after the user confirms broader allowance |
| Seccomp candidates exist | Explicit remove/keep for every built-in rule/custom syscall group; identical parameters in all three steps |
| No confirmed deletions | Do not generate/apply candidates; record analysis and start the next observation window |

Compatibility export still reads every enumerated rotated file exactly once. Unreadable files, decompression failure, or stream interruption
fail closed. Check exit codes directly in the current command instead of saving `<node>.exit`.

### 2.2.1 Export without tar

Choose only before copying starts and after confirming tar is unavailable; do not reread the same batch through this path after a mid-copy failure.
This branch reuses `WINDOW_END` and `COLLECTION_STARTED_AT` established before node traversal in 2.1.3. Within the same Bash
invocation, re-enumerate and immediately read; write stdout only locally:

```bash
test "$L4_AUTHORIZED" = yes || exit 1
test "$COLLECTION_STARTED_AT" -ge "$WINDOW_END" || exit 1
REMOTE_OUTPUT="$(
  [ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec \
    -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
    sh -c 'test -r /var/log/varmor/violations.log &&
      find /var/log/varmor -maxdepth 1 -type f \
        \( -name "violations.log" -o -name "violations-*.log" \
           -o -name "violations-*.log.gz" -o -name "violations.log.*" \) -print'
)" || exit 1
test -n "$REMOTE_OUTPUT" || exit 1
REMOTE_FILES=()
while IFS= read -r remote; do
  test -n "$remote" && REMOTE_FILES+=("$remote")
done <<< "$REMOTE_OUTPUT"
printf '%s\n' "${REMOTE_FILES[@]}" \
  | grep -Fx '/var/log/varmor/violations.log' >/dev/null || exit 1
STAGING="$(mktemp -d "$RUN_DIR/.stream-XXXXXX")" || exit 1
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec \
  -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'set -eu
    test "$#" -gt 0
    for f do
      test -r "$f"
      case "$f" in *.gz) gzip -cd "$f";; *) cat "$f";; esac
      printf "\n"
    done' sh "${REMOTE_FILES[@]}" > "$STAGING/violations.log" || exit 1
python3 scripts/finalize_node_log.py --file "$STAGING/violations.log" \
  --output "$RUN_DIR/2.1.3-logs/$NODE.log" \
  --window-end "$WINDOW_END" --started-at "$COLLECTION_STARTED_AT" || exit 1
rm -r -- "$STAGING"
```

## 2.3 Fail-closed checklist

Stop without updating CRDs on any of:

- Context/dependency/connection errors, missing policy, or non-EnhanceProtect mode;
- Unexpanded aggregate capabilities or observation switches not explicitly enabled;
- Missing snapshots, window before snapshot, or UID/generation/profileName/spec drift;
- Incomplete start/end agent inventory, node changes, replaced Pod UID, NotReady, or terminating;
- Missing expected node logs, read/decompression/JSON parse failures, unfinished window, or unproven retention;
  incremental initialization after start, unrecoverable file gaps/interruptions, or unconfirmed final draining;
- Requested NetworkProxy rule deletions with ineligible evidence;
- Invalid attribution events, coordinates, enforcers, decisions, or conflicting decisions for the same coordinates;
- Unconfirmed Seccomp ambiguity or inconsistent keep/allow parameters across plan, apply, and guard;
- Guard detects non-deletion changes or a candidate not exactly equal to the recomputed result;
- Server dry-run failure, live spec differing from candidate, final resourceVersion/hash mismatch, or missing user confirmation.
