# Rule review and repeated collection

## Review file

Use JSON, avoiding a YAML parser dependency. Example:

```json
{
  "default": {"path": "exact", "methods": true, "includeErrors": false},
  "requests": [
    {"host": "api.example.com", "port": 443, "method": "GET",
     "pathPrefix": "/v1/projects/", "path": "prefix", "depth": 2, "methods": true}
  ],
  "declaredTcp": [
    {"destination": "10.0.0.8:5432", "reason": "Required database", "approved": false}
  ],
  "approvedTcp": [],
  "excludedHosts": [],
  "excludedTcp": []
}
```

`requests` limits each decision to one literal host, port, method and either an exact `paths` list or a boundary-preserving `pathPrefix` ending in `/`. Other request groups retain their decisions. Overlapping scopes are rejected for matching evidence; resolve ambiguity. Translate user business intent rather than requiring numeric depth input. Legacy `domains` is supported but affects every path and port for that host; avoid it for a single family.

`prefix + depth=2` generalizes `/v1/projects/123` to `/v1/projects/`; `/v1/projects` remains exact. `host` removes the path restriction, and methods=false removes the method restriction. Explain that these choices permit additional requests. Describe path/method restrictions only for plaintext HTTP or user-approved MITM; passthrough supports host/port only. includeErrors=true accepts non-2xx/3xx AUDIT requests after the user confirms business need; it does not accept proxy DENIED events.

The current HTTPPathMatch API has only exact and prefix conditions. Neither the
review schema nor a prefix expresses "one numeric ID segment, excluding details
and admin." Show examples of additionally allowed paths before asking users to
accept a subtree. If they reject it, offer a finite exact list only with their
acceptance and keep the unmet dynamic-ID requirement explicit. Recheck the served
CRD if a later version introduces another condition; never invent regex fields.

`declaredTcp` persists necessary business connections with their user-provided reason, including missing audit evidence. Set approved=false until the user authorizes the entire literal IP/port; approved=true generates a rule without implying it was observed or verified. Reports list origin, observation, approval and separate verification. Preserve unresolved requirements as pending and describe the candidate as partial. Generation always writes the single candidate.yaml; never hand-edit a second candidate for missing TCP evidence. Legacy approvedTcp without usable evidence remains pending until collected or explicitly declared.

`approvedTcp: ["10.0.0.8:5432", "[fd00::8]:5432"]` allows the entire IP/port without generalizing to CIDRs. If the same IP/port serves HTTP, L4 allow also permits other paths. Do not keep claiming that destination allows only the listed paths. The overlapsVisibleHTTP field in pendingTcp flags this overlap.

Put destinations the user considers outside legitimate business in excludedHosts (literal canonical hosts) or excludedTcp (IP:port). Subsequent generation excludes these inputs rather than repeatedly adding them just because they were observed. These settings do not generate explicit deny rules; an approved broad L4 permission may still cover the host, so assess blocking through the permission table and real tests. A TCP destination cannot be both approved and excluded. Passing --review saves the configuration to session/review.json; omitting it reuses saved user choices, and passing `{}` resets them. When updating decisions, preserve other existing choices unless the user requests replacing them.

## One-shot and repeated analysis

```sh
python3 /ABS/SKILL/scripts/advisor.py collect --session /ABS/SESSION \
  --source auto
python3 /ABS/SKILL/scripts/advisor.py analyze --session /ABS/SESSION --review /ABS/review.json
```

`cycle` runs collect followed by analyze; collection failure prevents analysis from advancing. `events.sqlite` retains deduplicated, query-stripped events and collection rounds. healthyRounds in `analysis.json` counts only rounds with actual new events and healthy parsing; offlineRounds is separate. stableDataRounds increases only when a candidate is unchanged and a new healthy data round exists. Repeated analysis of old data does not increase stable rounds. These metrics are guidance, not automatic enforcement thresholds.

Keep live and offline data in separate sessions. report.md lists each candidate rule's host/IP, port, path, method, authorization granularity, and uncovered behavior. collectionIssues lists parsing/identity issues separately. excluded counts inputs excluded during rule generation, whereas replayUncovered counts events the candidate does not actually cover. An error response excluded from generation may still be covered by a rule generated from a successful request, so the counts need not match. If no acceptable rules exist, candidate.yaml is not produced; candidate.previous.yaml is not the current recommendation.

Use monitor for actual live observation. See [observation-and-collection.md](observation-and-collection.md) for plans, UID isolation, cursors, gap states, and stopping conditions. collect/cycle above are one-shot snapshot interfaces; they include rotated files by default but do not assess file continuity. Do not present sparsely scheduled cycle calls as continuous collection. cycle accepts --until with a timezone; after expiry it stops accessing the cluster, and reads already started are also bounded by remaining time.

Repeated collection should cover startup, normal requests, low-frequency tasks, retries, failover, error handling, and all replicas. Users confirm the business scenarios; event coverage and stable rounds describe existing evidence only. On completion, monitor retains all verified evidence, unresolved identities, and gap explanations without automatically enabling enforcement.

## Codex / Claude Code scheduling

Both use the same Agent Skills package. Codex supports user-level `~/.codex/skills/` or project `.agents/skills/`; Claude Code uses user-level `~/.claude/skills/` or project `.claude/skills/`. The installer supports project installation. Consult each tool's official documentation for current discovery behavior.

Local monitor continuously collects and generates analysis.json / report.md according to the plan. Create native automation only when notifications across conversations are requested. A notification job reads collector.json / analysis.json for the fixed session and checks process liveness, update times, permission changes, gaps, and the stop reason. It must not start a second monitor, collect again, extend observation on its own, or change policies/workloads. When the user explicitly changes a running deadline in the main conversation, submit and verify the change using observation-and-collection.md. If notification scheduling is bound to the old end time, synchronize it with the user's new request and have it read the latest applied plan. Once the collector stops, read the final report and end the notification job. Stay quiet when unchanged; notify only for new destinations, permission changes, failures, completion, or decisions needed.

Prefer the host's native automation tools and follow their schemas. Use an execution location that can access the local session. If no tool exists, provide a runnable local alternative; do not write private configuration and claim automation was created. Whether collection survives across conversations and notifications arrive at the deadline depends on the host runtime. Starting a local process alone does not establish automatic notifications. Check collector liveness before handing off to the user and again when they return.

Official references: [Codex scheduled tasks](https://learn.chatgpt.com/docs/automations?surface=app), [Codex skills](https://learn.chatgpt.com/docs/build-skills), [Claude skills](https://code.claude.com/docs/en/skills), and [Claude scheduled tasks](https://code.claude.com/docs/en/scheduled-tasks).

Cloud product reference: [Container Hardening Agent (Chinese)](https://docs.volcengine.com/docs/CloudSecurityCenter/container-hardening-agent?lang=zh) provides policy templates and diagnostics and describes a planned evolution through observation, analysis, optimization, and convergence. This tool borrows that interaction loop; it does not require a VKE account or claim to implement the cloud product's automatic switching capabilities.

## Reviewed enforcement gaps

DENIED remains separate from successful observation. For precise pending scopes,
explicit approval/rejection, preserved evidence, quiet confirmed permissions and
regeneration of the same candidate.yaml, use [enforcement-iteration.md](enforcement-iteration.md).
Do not enable includeErrors to ingest proxy DENIED or invent a successful AUDIT.
