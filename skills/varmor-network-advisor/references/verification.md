# Separate enforcement verification

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

For a known plaintext line-echo service, check the actual client's options before
giving a probe. BusyBox nc may close before reading the echo if printf immediately
ends its input. For variants with -v and -w, a bounded example is:

```sh
kubectl --context CONTEXT -n NS exec VERIFIED_POD -c APP -- sh -c \
  '{ printf "%s\n" "unique-echo-marker"; sleep 6; } | busybox nc -v -w 8 IP PORT; probe_rc=$?; printf "\nclient_exit=%s\n" "$probe_rc"; exit "$probe_rc"'
```

Adapt the wait and timeout to the service and client; this is an echo-service
example, not a database/TLS protocol test. Require the exact marker in returned
payload, then correlate the closed connection's audit. A connection diagnostic
alone is insufficient. Preserve an empty first result as a failed verification
attempt, diagnose it, and retest without inferring a policy denial.

After the user has run the checks, prepare JSON from actual supplied receipts:

```json
{"checks": [
  {"id": "new-order-id", "layer": "L7", "destination": "10.0.0.8:8080",
   "authority": "orders.example.test:8080", "method": "GET",
   "path": "/api/orders/3003", "expected": "allow",
   "clientConfirmed": true, "backendConfirmed": true,
   "evidence": ["/ABS/client-results.json", "/ABS/backend-results.txt"]},
  {"id": "wrong-method", "layer": "L7", "destination": "10.0.0.8:8080",
   "authority": "orders.example.test:8080", "method": "DELETE",
   "path": "/api/orders/3003", "expected": "deny",
   "clientConfirmed": true, "backendConfirmed": true},
  {"id": "required-tcp", "layer": "L4", "destination": "10.0.0.8:9000",
   "expected": "allow", "clientConfirmed": true}
]}
```

`clientConfirmed` means that inspected client results match that check's expected
outcome; `backendConfirmed` means that inspected backend records match it
(received for allow, absent for deny). False means contradiction; omission means
missing evidence. These assertions are supplied evidence, not independently
executed tests by this CLI. Keep source receipts and disclose this distinction.
Raw TCP checks match L4 events without SNI; an explicit sni field verifies literal TLS SNI/port instead.

```sh
python3 /ABS/SKILL/scripts/advisor.py verify --session /ABS/VERIFY \
  --observation-session /ABS/OBS --policy-file /ABS/OBS/candidate.yaml \
  --pod-uid VALIDATION_UID --since '2026-10-10T15:00:00+08:00' \
  --until '2026-10-10T15:01:00+08:00' --checks /ABS/checks.json --language en
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
and client assertions (plus backend assertions for HTTP); quiet allows additionally follow the complete-read/effective-configuration requirements in enforcement-iteration.md; contradictory or
missing evidence remains visible. No-check runs save audit only and return 2.
Any non-confirmed check also returns 2 while saving the evidence. Snapshot
continuity is not assessed and cannot prove absence of upstream loss.

`analyze --verification` associates the result by observation path and exact
candidate hash. Reanalysis keeps the association but marks it stale if the
candidate changes; it never imports validation events into observation or
increases stable data rounds. Approved declared TCP is marked verified only by
confirmed matching allow checks for the current candidate. A missing requirement
or successful checklist does not establish complete business coverage.
