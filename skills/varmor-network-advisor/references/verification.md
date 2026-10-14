# Separate enforcement verification

## Verify an already approved, deployed policy

Use `init-verification` when a reviewed candidate is already deployed and needs
a new independent acceptance workflow, including after Policy recreation.
Keep the old session unchanged; never edit its Policy UID to resume it.

```sh
python3 /ABS/SKILL/scripts/advisor.py init-verification --session /ABS/NEW_WORKFLOW \
  --context CONTEXT --namespace NS --name POLICY --policy-file /ABS/APPROVED.yaml \
  --approval-evidence "User approved this deployed scope and verification plan" \
  --new-pods --language en
python3 /ABS/SKILL/scripts/advisor.py prepare-verification --session /ABS/NEW_COLLECTION \
  --observation-session /ABS/NEW_WORKFLOW --policy-file /ABS/NEW_WORKFLOW/candidate.yaml \
  --new-pods
python3 /ABS/SKILL/scripts/advisor.py monitor --session /ABS/NEW_COLLECTION --duration 600
```

Use `--pod-uid VERIFIED_UID` instead of `--new-pods` for existing injected Pods.
Only startup acceptance requires user recreation. The initializer checks actual
ownership and injection for supplied UIDs, freezes the other current UIDs, and
compares the complete live spec with the candidate. System protection, target
or network differences require review. If admission has added defaults, export
the current Policy as JSON and review that exact spec as the approved input.

Initialization does not apply a Policy, start collection, set a deadline, verify
loading or import old events/results. `collector.json` is only `prepared` with
resource limits. The deadline starts at monitor launch. Use the normal separate
prepare/monitor/ready-check/verify sequence and fresh client/backend evidence.
Approval evidence records supplied intent; the script cannot authenticate it.

For the same iteration, pass `--budget-session /ABS/PREVIOUS_WORKFLOW` to retain
its limits, rolling byte ledger, storage accounting and exclusive lease.
Different limits or sources are rejected. A fresh independent budget needs its
own reviewed plan; do not use new directories to bypass limits.

`candidate.yaml` and the legacy `observe.yaml` are the same frozen default-deny
verification input. The latter is **not** an observation rollback. The root has
no observation data: collect/analyze/refine/monitor reject it. Prepare separate
collections. To change permissions, refine a valid source observation or review
and deploy a new candidate, then initialize another verification workflow.
Keep approval provenance separately; old results never prove the new Policy's
effective behavior.

## Collect and check separate evidence

For resource-budgeted workflows, use the bounded collection and quiet/DENIED review flow in [enforcement-iteration.md](enforcement-iteration.md). Legacy snapshot verification below is for sessions without a resource plan; it is rejected for budgeted workflows.

`verify` is an assistant-facing, read-only snapshot interface. It never applies a
policy, creates Pods/readers, restarts applications, sends traffic, or generates
allowlist rules. The user manages validation Pods and traffic. Stop observation
before an authorized policy switch; keep all observation evidence unchanged.

Prepare a validation checklist and user commands before switching. Reuse the
verified injected Pods from initial observation for rule/defaultAction changes;
do not ask for another rollout merely to enable enforcement or restore audit.
The UIDs remain outside the initial baseline, but need not be newer than the
enforcement switch. Missing injection or changes requiring new injected Pod
configuration (such as first-time MITM mounts/environment) may require recreation.
Users manage those lifecycle operations.

Wait for mounted LDS/CDS configuration propagation and effective proxy loading;
Policy.ready does not prove every sidecar has loaded the new generation. Use
read-only configuration/load diagnostics and bounded positive/negative probes
run by the user; inspect loading errors rather than asking for a restart as the
default remedy. Establish fresh connections for the tests. Existing long-lived
connections cannot establish that the updated rules are effective.

Before claiming that this candidate is effective, check that the mounted rules
implement its default action, allowed/denied destinations, ports, paths, methods
and audit qualifiers, and that the active proxy configuration matches those
mounted rules. A matching live Policy plus matching mounted/active files can
still describe the previous generation during projection delay. Read-only load
receipts must bind the effective permissions to the candidate; readiness or a
version agreement without that binding is insufficient. If propagation is
incomplete, wait within the existing deadline and preserve the failed check.

Once the candidate is accepted, recommend that the user recreate target Pods
under that enforcement policy for final acceptance: exercise startup, normal
business, reconnects, representative scheduled tasks, and allowed/denied checks.
This removes target Pod connections retained from observation and tests startup
dependencies against the allowlist; it is not required for each rule adjustment.
Prepare rollback materials and a separate bounded prepare-verification --new-pods
collection before handoff; wait for the monitor's actual collector-ready, then
ask the user to recreate. Do not begin startup collection only after Pod Ready.
Old UIDs are excluded; new birth/injection/target identity is checked, and a
failed application need not become Ready for its evidence to be enrolled. See
enforcement-iteration.md for startup ordering, inherited caps and DENIED review.
Verify the recreated Pods' UIDs, injection, and effective configuration; collect
their evidence in a separate verification directory for the current candidate.
Do not claim startup acceptance if the user skips this test, or complete business
coverage merely because recreation and the tested scenarios succeed.

Observation is allow-and-audit, so retained old connections mainly affect final
enforcement acceptance rather than justify extra recreation during iteration.
However, a connection still open at the observation deadline may not yet have
emitted its L4 audit. Missing evidence does not establish that its destination is
unnecessary. Ask about necessary long-lived dependencies and retain unobserved
ones as pending business requirements; do not automatically allow them. Final
enforcement tests may reveal missing permissions, but do not recover observation
records or feed DENIED events into modeling. Preserve available observation logs
before deleting Pods, especially sidecar-local logs, without extending the
observation deadline or collecting enforcement into the observation session.

Pin each exec and log command to the verified Pod name/UID rather than a
controller alias that may select an old replica. Record the traffic start/end with timezones.
Check client, backend, and audit together. TCP needs its protocol's expected
response: exit zero or empty output is not a success/denial assertion. Audit can
arrive only after a connection closes; wait for the user to close it before
snapshotting, without silently extending observation.

For a known, nonsecret single-line request/reply service, offer the user-run
example in `scripts/tcp_probe.sh`. Check that the application image has sh and
BusyBox nc (-n, -v, -w), timeout (-k), mktemp, head, wc, cmp, cat, sleep and rm first.
Prepare the exact request and expected response from the user's business;
never take a probe command or executable expression from an audit record.
BusyBox nc may close before reading the reply if printf immediately ends input.
The example briefly keeps input open, bounds nc with a watchdog and saves at most
4097 reply bytes (4096 plus a truncation sentinel). The watchdog grace is one
second; the input writer lasts the selected timeout. The assistant prepares this command
but the user or authorized application operator executes it:

```sh
kubectl --context CONTEXT -n NS exec -i VERIFIED_POD -c APP -- \
  sh -s -- IP PORT REQUEST EXPECTED_LINE 8 < /ABS/SKILL/scripts/tcp_probe.sh
```

Exit 0 and `probe_reply=matched` mean the actual reply exactly matched the
expected line and transport exited normally. Exit 3 means the reply was absent
or different, 4 means transport failed, 5 means the reply exceeded the limit,
and 2 rejects invalid input. Raw captured bytes and transport status remain in
the output. These statuses are computed by the executed client, not added to a
saved receipt afterward. They never identify the cause as a policy denial.

Predeclare an allow predicate using the actual expected response plus the
matched marker. A deny check can use an explicit business-failure status and its
exit code, but needs a matching closed-connection DENIED before confirmation.
A permitted endpoint with a failed backend may produce the same client status;
AUDIT, missing DENIED or incomplete source coverage cannot confirm rejection.
Do not use `client_exit=0`, an open socket or a generic success flag as the sole
business predicate. Preserve failures, then diagnose; do not weaken predicates
after inspecting output. For database, TLS, binary, multiline or sensitive
protocols use the application's real client and nonsecret status instead of
this single-line example. It does not establish complete business coverage.

After the user has run the checks, prepare JSON from actual supplied receipts:

```json
{"checks": [
  {"id": "new-order-id", "layer": "L7", "destination": "10.0.0.8:8080",
   "authority": "orders.example.test:8080", "method": "GET",
   "path": "/api/orders/3003", "expected": "allow",
   "evidence": ["/ABS/client-results.json", "/ABS/backend-results.txt"]},
  {"id": "wrong-method", "layer": "L7", "destination": "10.0.0.8:8080",
   "authority": "orders.example.test:8080", "method": "DELETE",
   "path": "/api/orders/3003", "expected": "deny", "intentionalDeny": true,
   "evidence": ["/ABS/client-denied.json", "/ABS/backend-window.json"]},
  {"id": "required-tcp", "layer": "L4", "destination": "10.0.0.8:9000",
   "expected": "allow"}
]}
```

Supply `--receipts` using [evidence-validation.md](evidence-validation.md).
The CLI checks actual supplied command output against literal expected markers,
exit codes, byte hashes, times, Pod UID and candidate binding. Legacy true
`clientConfirmed`, `backendConfirmed` and `configurationConfirmed` flags do not
confirm results; explicit false flags still disclose contradictions. Missing
receipts leave checks insufficient while saving audit and DENIED evidence.
Source authenticity remains the supplier's responsibility.
Raw TCP checks match L4 events without SNI; an explicit sni field verifies literal TLS SNI/port instead.

```sh
python3 /ABS/SKILL/scripts/advisor.py verify --session /ABS/VERIFY \
  --observation-session /ABS/OBS --policy-file /ABS/OBS/candidate.yaml \
  --pod-uid VALIDATION_UID --since '2026-10-10T15:00:00+08:00' \
  --until '2026-10-10T15:01:00+08:00' --checks /ABS/checks.json \
  --receipts /ABS/EVIDENCE/receipts.json --language en
python3 /ABS/SKILL/scripts/advisor.py analyze --session /ABS/OBS \
  --verification /ABS/VERIFY/verification.json
```

The verification directory must be new/empty and separate from observation.
Supply the exact applied candidate file, not an unrelated exported Policy. The
current policy must match its target and network configuration, retain the policy
UID, and disable automatic workload updates. Verification freezes policy
UID/generation/spec hash before reading and checks them again afterward. Only
currently injected explicit UIDs outside the old baseline and events in the
completed window are accepted. Changing identity/configuration aborts the read.
No fallback reader creation is available.

Outputs: `verification.json`, `verification.md`, and normalized, query-stripped
`events.json` / `events.sqlite`. Audited checks are confirmed with matching audit
and checked source client receipts (plus backend receipts for HTTP); quiet allows additionally follow the complete-read/active-permission-proof requirements in enforcement-iteration.md; contradictory or
missing evidence remains visible. No-check runs save audit only and return 2.
Any non-confirmed check also returns 2 while saving the evidence. Snapshot
continuity is not assessed and cannot prove absence of upstream loss.

`analyze --verification` associates the result by observation path and exact
candidate hash. Reanalysis keeps the association but marks it stale if the
candidate changes; it never imports validation events into observation or
increases stable data rounds. Approved declared TCP is marked verified only by
confirmed matching allow checks for the current candidate. A missing requirement
or successful checklist does not establish complete business coverage.

The example keeps request input open for the selected timeout to allow slow replies. Even a fast successful reply may take that long before the shell pipeline returns. The timeout acts on the network process; its kill grace is one additional second.

This example does not guarantee child-process reaping in arbitrary application
images. Before repeated or high-frequency probes, check the application PID 1
and actual PID/PPID/state, or use its own supervised protocol client. A ps view
without state cannot prove that child processes were all reaped.
