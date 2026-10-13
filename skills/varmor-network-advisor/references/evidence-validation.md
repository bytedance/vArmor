# Mechanically checked enforcement evidence

These interfaces are for the assistant. Users run their application lifecycle
and business traffic; do not ask them to learn receipt files or these commands.
Save the actual supplied command results without rewriting failed output.
The checker verifies content and binding, not the authenticity of arbitrary
files or complete business coverage. Never invent a receipt to make a check pass.

## Active permission proof

For a compatible candidate, run a read-only check immediately before traffic:

```sh
python3 /ABS/SKILL/scripts/advisor.py active-config --session /ABS/OBS \
  --policy-file /ABS/OBS/candidate.yaml --pod-uid VERIFIED_UID \
  --output /ABS/EVIDENCE/config-before.json
```

Repeat after traffic into a new `config-after.json`. Check every tested UID.
The proof reads the real Envoy admin endpoint under the configured proxy UID,
pins Policy UID/generation/spec hash and Pod UID before/after the read, then
compares candidate permission scopes with active RBAC, default TCP denial,
HTTP normalization and audit-selection filters. It does not rely on version
agreement or parse a mounted file as proof of candidate propagation.
The admin response is bounded to 4 MiB and the remote read to 15 seconds.
Diagnostics are separate from audit-stdout quotas; do not repeatedly read
configurations without need. Only a permission projection is saved; the full
dump, Secrets and credential-bearing route/header configuration are not saved.
The sidecar needs bash, timeout, head and setpriv. If unavailable, keep the
proof incomplete and inspect read-only diagnostics; do not install software or
change the proxy image as a fallback.

Automatic scope: default deny, literal DNS host and exact port, at most one
method and one exact/prefix path per HTTP rule; host/port-only SNI permissions
also work. Default ports 80/443 retain both legal authority spellings.
Rules may be audited or silent. Raw TCP grants, MITM, wildcard hosts, ranges,
explicit deny constraints and unknown renderer shapes remain unsupported by
this automatic proof. This restriction does not remove their modeling or
audited traffic-verification support. Explain visibility and permission limits
when relevant, keep missing configuration evidence visible, and do not turn a
manual assertion into a passing quiet check. The proof does not validate all
CDS/TLS/routing settings, and two reads cannot rule out configuration changes
between them. Actual positive and negative business tests remain necessary.

## Source command receipts

The assistant or operator saves actual client output as JSON:

```json
{
  "kind": "NetworkProxyCommandReceipt",
  "checkId": "order-query",
  "podUID": "VERIFIED_UID",
  "startedAt": "2026-10-13T10:00:01+08:00",
  "endedAt": "2026-10-13T10:00:02+08:00",
  "exitCode": 0,
  "stdout": "HTTP 200\nunique-business-marker"
}
```

Record the verified UID at execution, real timezone-aware times, exit code
and unchanged stdout. Use protocol/status markers from the actual business;
Capture only the nonsecret output needed for that check, such as a status and
request marker; keep supplied source files private. Do not capture credentials
or a complete sensitive response merely to populate a verification receipt.
a generic empty response or TCP exit zero cannot prove the expected outcome.
Do not add requests, bodies, credentials or query strings merely to satisfy
the checker. A backend receipt uses the same fields for the supplied backend
log read, with output that can correlate a unique business request marker.
For denial it must also contain `coverageSince` and `coverageUntil` covering
the entire traffic window. This coverage declaration is supplied metadata,
not an independently proven guarantee of complete backend logging. If the
backend is inaccessible or its logs cannot establish absence, report missing
evidence instead of setting a confirmation flag.

Hash the saved file bytes with Python's hashlib. Build a source bundle:

```json
{
  "kind": "NetworkProxyCheckReceipts",
  "candidateHash": "CANONICAL_CANDIDATE_SHA256",
  "policy": {"uid": "POLICY_UID", "generation": 2, "specHash": "SPEC_SHA256"},
  "podUIDs": ["VERIFIED_UID"],
  "since": "2026-10-13T10:00:00+08:00",
  "until": "2026-10-13T10:01:00+08:00",
  "checks": [{
    "id": "order-query", "podUID": "VERIFIED_UID",
    "client": {
      "file": "/ABS/EVIDENCE/client.json", "sha256": "FILE_BYTES_SHA256",
      "exitCode": 0, "stdoutContains": ["HTTP 200", "unique-business-marker"]
    },
    "backend": {
      "file": "/ABS/EVIDENCE/backend.json", "sha256": "FILE_BYTES_SHA256",
      "exitCode": 0, "stdoutContains": ["unique-business-marker"]
    },
    "configuration": [
      {"file": "/ABS/EVIDENCE/config-before.json", "sha256": "FILE_BYTES_SHA256"},
      {"file": "/ABS/EVIDENCE/config-after.json", "sha256": "FILE_BYTES_SHA256"}
    ]
  }]
}
```

Candidate/spec hashes use the canonical JSON fingerprint used by analysis and
enforcement collection. File hashes use exact bytes. Every file must exist at
an absolute regular path, be at most 4 MiB and match its supplied byte hash.
Client execution must lie within the verification window; backend retrieval
must finish within five minutes after that window. Backend denial predicates
use `stdoutAbsent` with the unique request marker and the coverage fields.
Choose literal predicates before inspecting results; do not weaken them after
a failed attempt just to get a pass. Preserve the failed attempt separately.
TCP needs a meaningful returned protocol marker and matching closed-connection
audit; backend evidence is optional for L4 checks. Verification matches audit
from that check's receipt UID, not any other selected Pod.

For a quiet allow, config reads must bracket traffic, within five minutes of
its window, and have the exact same candidate and pinned policy identity.
The checker recomputes permission equality from the saved projection; a stored
`result:confirmed` or `configurationConfirmed:true` does not establish it.
Quiet checks also require a complete bounded audit read through the window,
no matching audit, and checked successful client/backend receipts.

Pass the bundle with `verify --receipts /ABS/EVIDENCE/receipts.json` alongside
the normal checks and bounded collection. Without source receipts, audit and
DENIED evidence are saved but checks remain insufficient. Legacy true
confirmation flags and `evidence` descriptions are not proof; explicit false
flags still disclose a contradiction. Never silently downgrade this requirement.

## Brief workflow handoffs

`workflow-status --session /ABS/OBS` writes `workflow-status.md` and JSON.
Enforcement collections prepared by the current Skill are registered locally;
use `--collection-session /ABS/COLLECTION` for older or explicitly chosen ones.
Associate verification with analyze as usual, or pass `--verification` here.
`--language zh-CN|en` selects the brief reply language; use analyze's language
option to persist a change for workflow reports. Preserve exact command times;
do not round a traffic-window start backward across its before-config check.
Use the summary's stage, next actor and next action for the main user reply.
Link detailed reports. When the next actor is the assistant, perform the already
authorized work; do not turn the summary into another user approval request.

This summary reads saved evidence and local collector readiness. It does not
query current cluster state. Never translate "saved checks passed" into
"the cluster is currently protected" without fresh effective-config evidence.
Candidate changes and altered saved audit data invalidate associated results;
incomplete or contradictory checks never become acceptance. Startup checks
are distinguished from rule-only checks, so do not ask users to rebuild at
every iteration. Preserve the current deadline and relevant visibility limits
in the short handoff, while leaving technical identity/lease details in links.
Legacy assertion-only verification is retained as history and marked as needing
source receipt checks, rather than promoted to mechanically checked acceptance.
Mark `intentionalDeny:true` only for a negative-control check the user intends
to keep blocked. A confirmed such check is retained in audit evidence but does
not become a new business approval prompt. `expected:deny` alone is not this
decision: a blocked required request may still need DENIED review and permission
refinement. Existing explicit deny decisions also remain decided.
