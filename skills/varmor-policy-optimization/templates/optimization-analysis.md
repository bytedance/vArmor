<!--
Optimization analysis report template. Each optimization depends only on the user-provided closed timestamp interval, start policy snapshot, and current policy,
not on hidden round state.
Replace placeholders with actual information. Write "none" for empty sections rather than deleting them.
-->

# vArmor Policy Optimization Analysis

## 1. Scope

- Target policy: <VarmorPolicy|VarmorClusterPolicy> <namespace>/<name> (namespace is empty for VCP)
- Time window: start=<original timestamp>, end=<original timestamp> (fixed closed interval)
- Collection completion: collectionStartedAt=<earliest node collection start>, manifestBuiltAt=<epoch>,
  windowComplete=<true|false>
- Collection mode: <incremental|snapshot>; incremental coveredFrom / lastReadStartedAt / lastDrainedAt,
  backlogBytes and collectionIssues per node: <summary; N/A for snapshots>
- Final incremental confirmation: <per-node firstCleanCompletedAt / confirmationReadStartedAt / scan interval; N/A for snapshots>;
  issue recovery: <resolvedAt / recoveryBasis or remaining blocking reason>
- Collection budget: <rolling audit-exec stdout limit and actual ledger summary; excludes API metadata/protocol overhead; N/A for snapshots>
- Target cluster / context: <cluster / context>
- Start policy snapshot: capturedAt=<epoch>, uid=<uid>, generation=<n>, resourceVersion=<rv>, specSha256=<hash>
- Start/end consistency: <consistent|drifted; report resourceVersion-only changes separately>
- Rule catalog source: catalogProvenance=<version@commit>
- Compatibility of rules actually used: <verified|unknown|incompatible>; basis: <verified version range or specific missing rules>

## 2. Log overview

- Raw logs: <n>; matching in-window: <n>; outside window: <n>; other policies: <n>; parse failures: <n>
- Start/end Agent inventory: <capturedAt and desired/current/ready>; topology changes: <node additions/removals/Pod UID/DS, or none>
- Start/end node union / actually collected nodes: <set summary>; node coverage: <complete|incomplete>
- NetworkProxy evidence: status=<not-applicable|eligible|ineligible>; mode=<node-central-runc|other>
- Per-node retention evidence: <node: earliest/latest/basis>; log retention coverage: <complete|unknown>
- Invalid logs (Envelope / event): <n>
- Aggregated non-Seccomp events: <n>; Seccomp syscalls: <deduplicated list>

## 3. Attribution conclusions

For each aggregated event, list eventId, an application-behavior summary, matches (source + rule + context.targets), and evidence
(how event fields correspond to rule restrictions; enforcer compatibility).

- Established associations:
  - <eventId>: <rule> (<evidence>)
- Multiple matches for one event: <eventId>: <rule A>, <rule B>
- Unattributed / insufficient evidence (empty matches): <eventId: missing evidence>

## 4. Rules removed in this update

User confirmation record: <2.1.5-attribution.json path; decision for every match; corresponding user confirmation message/time>.
Final reviewed hash: <candidate SHA256; read this record when restoring shell state rather than regenerating the review value>. Guard-computed structured
diff (deletions only):

- <source>: <rule> (enforcer=<...>, associated event=<eventId>)
- Total: <n> rules

## 5. Seccomp ambiguity and broader-allowance risks

- Syscalls matching multiple rules: <syscall: original matching rules>; outcome: <all retained|user confirmed some/all deletions and ambiguity>.
- Built-in rule decisions: <builtinRemovals / keptBuiltinRules; none if no candidates>.
- Custom syscall-group decisions: <customRemovals / keptSyscalls / keptCustomRules>.
- Rebuild parameters: <confirmed remove/keep-seccomp-rule, remove/keep-seccomp-syscall, allow-ambiguous values>.
- Ignored nonrestrictive RawRules: <complete SCMP_ACT_ALLOW/LOG rules; excluded from deletion candidates>.
- Unmatched syscalls: <list>

## 6. Baseline-originated events (rule deletion ineffective)

Events attributed to the implicit RuntimeDefault baseline rather than any atomic policy rule:
- <event>: Rule deletion cannot remove the cause; user decision required (accept / consider policy `privileged=true` to remove the AppArmor/BPF baseline). Assess Seccomp separately from generated AP content and actual container security context; this policy flag alone does not prove Seccomp is disabled.

## 7. Further observation needed

Rules/behaviors retained this round due to low frequency, intermittency, insufficient coverage, or unclear application semantics:
- <description: reason for continued observation>

## 8. Risks

Whether the window covers startup/release/scaling/scheduled tasks; rule-removal impacts potentially broader than a single event; correlations across enforcers;
version differences, etc.:
- <risk>

## 9. Verification and rollback

- Changed object and method: <apply one VP/VCP CRD>
- Activation boundary: Verify actual AppArmor/BPF Profile loading; Seccomp/injection changes require new containers.
  `updateExistingWorkloads=true` does not guarantee rollout for rule updates.
- Verification: Observe <policy status / new Pods / application behavior> after update; suggested next-window start: <timestamp>.
- Rollback: Retain pre-change YAML as the basis for rule restoration. Its resourceVersion is stale; do not apply it unchanged.
  Reread the current object, restore rules through a separately confirmed rollback workflow, run server dry-run, review the diff, then execute.

## 10. Next observation task

- Task record: <absolute path to the next task record>
- Suggested window: start=<timestamp>, end=<timestamp>; basis: <application cycle / log rate / retention capability>.
- Trigger: <one-shot scheduled task | reminder | manual user continuation | stop observation after this round>
- Automation boundary: Automated tasks may at most collect logs and summarize attribution. Wait for the user to decide the deletion scope before generating a candidate policy;
  CRD updates still require final confirmation.

## 11. Data handling

- Run directory: <local directory; permissions 0700>
- Redaction: <application paths, processes, and network destinations omitted or generalized in the report>
- Retention and cleanup: <retention period or cleanup arrangement after user confirmation>
