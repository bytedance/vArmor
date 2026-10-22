# Phase One: Establish Observation Tasks

This phase accepts policies, validates and submits them, and creates task records for later asynchronous recovery. One invocation can handle one or more
policies; use an independent run directory and task record for each policy, without sharing validation results, hashes, or confirmations.

Policy processing has two steps:

- **Assembly**: The model may assemble a complete CRD from **user-confirmed** information.
- **Validation**: The model **must not independently fix errors**; only fixed script normalization is allowed, or return to the user for renewed confirmation.

## 1.0 Entry conditions

- When introducing the Skill, briefly explain "receive/assemble -> local validation -> optional preflight -> dry-run -> confirmed submission";
  expand command steps only once the user is ready to process a policy.
- When the user supplies YAML for inspection, save a working copy as in 1.1.1, then start local validation at 1.2. Do not add rules
  or reselect the Enforcer.
- When the user requests a new policy without YAML, enter 1.1 and assemble from user-provided fields and rules.

Policy content should come primarily from the user. Explain fields, identify missing/conflicting information, validate normalization, and suggest corrections.
Preflight verifies policy settings; it does not extend into designing a complete rule set. Cluster support for an Enforcer establishes possible availability, not
a reason to select it.

Choose failure checks and file-permission safeguards according to the [execution contract](README.md). Restore this run's variables rather than relying on previous
shell state.

## 1.1 Input / assembly

### 1.1.1 Receive policy input

Prefer existing YAML or a local file path from the user. Restate object identity, target, Enforcer, control
switches, and rule sources to confirm understanding. Do not query the cluster or expand rules on the user's behalf yet. Phase one handles copies in a restricted run directory,
without rewriting the user's original file:

```bash
RUN_DIR="<independent run directory for this policy>"
install -d -m 700 "$RUN_DIR" || exit 1
SOURCE_POLICY="<user-provided local YAML path>"
install -m 600 -- "$SOURCE_POLICY" "$RUN_DIR/1.1.3-draft.yaml" || exit 1
```

For directly supplied YAML, write the original content to the same `1.1.3-draft.yaml`. For assembly from scratch, generate that file in 1.1.3
without running the copy command above.

### 1.1.2 Collect assembly information

Collect these items only for users explicitly requesting creation from scratch; do not ask again about information already clear:

1. Policy type: VarmorPolicy or VarmorClusterPolicy.
2. `metadata.name`; VP also requires namespace.
3. `target.kind` (Deployment/StatefulSet/DaemonSet/Pod).
4. Target selection: `target.name` or `target.selector` (exactly one).
5. `target.containers` (empty means all application containers).
6. `policy.enforcer` (user-selected; support probing must not choose on their behalf).
7. Desired built-in/custom rules (user-provided; stop and ask if unspecified rather than adding rules automatically).
8. **`updateExistingWorkloads` (explicit confirmation required)**: If true and manager enables workload updates,
   policy creation rolls out existing Deployment/StatefulSet/DaemonSet objects; explain and confirm the impact.
9. **`privileged` (explicit confirmation required; defaults to false)**: Selects the AppArmor/BPF RuntimeDefault/AlwaysAllow baseline; it does not set container privileges.
   Verify Seccomp separately from the deployed generator, AP, and actual container security context; see [implicit-baseline semantics](../references/enhance-protect-semantics.md#3-implicit-baseline-important-blind-spot).
10. **Only when match-all is selected (empty selector)**: Confirm separately as high risk; 1.2.1 requires
    `--allow-empty-selector`, followed by a second confirmation after showing the actual matched-object list.

### 1.1.3 Assemble the CRD

Using user-confirmed information and
[templates/observation-policy-skeleton.yaml](../templates/observation-policy-skeleton.yaml)
as a reference, assemble the complete CRD. Fill only confirmed content; do not invent rules. Persist the assembled artifact to
`$RUN_DIR/1.1.3-draft.yaml`. Subsequent
validation, review, and submission must use the file; do not create policies through temporarily assembled commands.

`spec.target` is immutable after creation; ensure the user verifies the target during assembly.

## 1.2 Deterministic validation (no independent model fixes)

### 1.2.1 Script validation + fixed normalization

```bash
python3 scripts/validate_policy.py \
  --file "$RUN_DIR/1.1.3-draft.yaml" > "$RUN_DIR/1.2.1-normalized.yaml" || exit 1
chmod 600 "$RUN_DIR/1.1.3-draft.yaml" "$RUN_DIR/1.2.1-normalized.yaml" || exit 1
POLICY_SHA256="$(python3 scripts/hash_policy.py fingerprint \
  --file "$RUN_DIR/1.2.1-normalized.yaml" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')" || exit 1
```

- Redirect stdout for pure YAML; read adjustments/notices from terminal stderr and relay them to the user.
- On validation failure, return **all** errors together or return to 1.1.2 for renewed confirmation; do not independently alter rule contents.
- The script checks optimization constraints and obvious structural errors, **not the complete CRD schema**. Target-cluster `--dry-run=server`
  is authoritative for schema; script valid=true alone does not establish full policy validity.
- Automatic normalization (each reported as an adjustment): Set `auditViolations/allowViolations=true`; expand
  `disable-cap-all/-privileged/-except-net-bind-service` into atomic `disable-cap-[CAP]`
  rules (preserving the NET_BIND_SERVICE exemption).
- Only `validate_policy.py` may expand aggregate capability rules using the catalog; the model must not enumerate them manually.
  The expanded `1.2.1-normalized.yaml` is the policy used for user review, fingerprint binding, and actual submission.

### 1.2.2 Model validation of RawRules structure (blocking)

Inspect RawRules in `1.2.1-normalized.yaml`; do not repeat the script's deterministic validation of the three built-in categories:


- **Required reading**: [references/raw-rules-syntax.md](../references/raw-rules-syntax.md).
- If no RawRules exist, record `result=true` and `reason=not applicable`, then proceed without empty analysis.
- **Checklist**:
  - appArmorRawRules: rule text, trailing commas, globs, targets paths, deny/audit semantics;
  - bpfRawRules: field hierarchy, qualifiers, and pattern constraints for files/processes/network/ptrace/mounts;
  - syscallRawRules: syscall names, valid actions, args structure;
  - networkProxyRawRules: egress structure, qualifiers;
  - Presence of the corresponding enforcer for every RawRules type.
- **Result**: Record `result` and specific issues/checked items in the review summary; do not produce extra self-attestation JSON.
  Server dry-run is authoritative for CRD structure, but this step must still inspect internal RawRules text syntax, actions, and application impacts;
  server dry-run does not compile AppArmor or other Profiles.
- **Content fingerprint**: Retain and display `POLICY_SHA256` from 1.2.1 even when no RawRules exist.
- **Blocking**: Any unchecked item, malformed structure, insufficient evidence, or `result=false` **blocks dry-run/submission**.
- **Binding**: Do not repeat fingerprint verification for dry-run within the phase; verify once immediately before create. If the file changes beforehand,
  prior conclusions are invalid; rerun 1.2.1 and 1.2.2.

## 1.3 Pre-submission preflight

After local validation, if the user is ready to submit, proactively explain risks beyond dry-run coverage before final confirmation
and suggest these checks:

| Preflight item | Purpose |
|---|---|
| Context and vArmor status | Confirm target cluster, CRDs, manager/agent, and actual version |
| Existing policies and Profiles | Check same-name VP/VCP, policies already affecting targets, ArmorProfile status, and potential conflicts |
| Target and containers | Verify workloads, selectors, container names, Annotations, and actual match scope |
| Enforcer capabilities | Verify availability of user-selected AppArmor/BPF/Seccomp/NetworkProxy |
| Activation and rollout impact | Verify `updateExistingWorkloads`, existing Pods, and potential rollout/recreation impacts |

Ask the user to choose all checks, selected items, or skip, then run the corresponding queries according to that choice. Mark facts already supplied and confirmed
as `user-provided` without requerying; mark skipped items `not-checked`. Use results to identify incompatibility, conflicts,
and risks, not to rewrite policy contents. Submission still requires context confirmation, script validation, server dry-run,
diff/hash review, and final confirmation.

Pin context before any selected cluster preflight; include it explicitly in subsequent kubectl commands:

```bash
CTX="$(kubectl config current-context)" || exit 1
test -n "$CTX" || exit 1
kubectl --context "$CTX" cluster-info || exit 1
```

Query manager/agent images only when actually used rules have compatibility questions and the user selected version checks. Catalog
provenance is not an exact-version gate; NetworkProxy has separate version boundaries.

Choose queries by object type; key branches (not an exhaustive command list):

- **VP (namespace-scoped)**: Query with `-n <ns>`.
- **VCP (cluster-scoped policy)**: Use `-A` for cross-namespace target queries; omitting `-n` selects only the current namespace, not the entire cluster.
- **Controllers (Deploy/STS/DaemonSet)**: Read PodTemplate `.spec.template.spec.containers[*].name`.
- **Pod (no template)**: Read `.spec.containers[*].name`, not `.spec.template...`.

```bash
# vArmor availability: CRDs installed
kubectl --context "$CTX" get crd -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep varmor

# For "context and vArmor status": list only component identities, images, and readiness; do not export full resources
kubectl --context "$CTX" get deploy,ds -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.readyReplicas,IMAGE:.spec.template.spec.containers[*].image'

# For "existing policies and Profiles": list identities, modes, and status, then query relevant objects precisely
kubectl --context "$CTX" get vpol -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,MODE:.spec.policy.mode,PHASE:.status.phase,PROFILE:.status.profileName'
kubectl --context "$CTX" get vcpol \
  -o custom-columns='NAME:.metadata.name,MODE:.spec.policy.mode,PHASE:.status.phase,PROFILE:.status.profileName'

# Target object (controller). Choose one scope; do not blindly copy -n:
#   VP:  -n <ns>      VCP: -A
kubectl --context "$CTX" get <deploy|sts|ds> <target> -n <ns> \
  -o jsonpath='{.spec.template.spec.containers[*].name}{"\n"}'
# VCP by name: namespaced GET cannot span namespaces; use list + field-selector with ns/name output
kubectl --context "$CTX" get <deploy|sts|ds> -A \
  --field-selector metadata.name=<target> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}'
# Pod by name: VP may use direct GET; VCP requires a cross-namespace list, not NAME combined with -A
kubectl --context "$CTX" get pod <target> -n <ns> \
  -o jsonpath='{.spec.containers[*].name}{"\n"}'
kubectl --context "$CTX" get pods -A --field-selector metadata.name=<target> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'

# PodTemplate Annotation keys only, no values (VP: -n / VCP: -A)
kubectl --context "$CTX" get <workload> [-n <ns>|-A] \
  -o go-template='{{range $k,$v := .spec.template.metadata.annotations}}{{$k}}{{"\n"}}{{end}}'
```

After finding relevant Annotation keys, write complete workload YAML only into the local run directory with permissions `0700`; evaluate
values such as `unconfined` locally. Report only boolean conclusions and relevant keys in conversation, not Annotation values or complete resource JSON.
Process selector-required label values locally too; show only matched-object identities and counts.

Also read actual target-container SecurityContext. For controllers inspect
`.spec.template.spec.{securityContext,containers[*].securityContext}`; for Pods inspect
`.spec.{securityContext,containers[*].securityContext}`. Compare declarations with the policy for static conflicts:

- Compare `capabilities.add` against `disable-cap-*`. For example, explicit `SYS_ADMIN` together with
  `disable-cap-sys-admin` should be highlighted separately during final confirmation.
- `runAsUser: 0` establishes root execution only, not a requirement for a specific capability.
- Static conflicts are risk notices, not automatic rule deletions or universal blockers in observation mode. Explain two convergence paths: remove unnecessary workload
  capabilities and retain rules, or establish real application need from later runtime evidence before removing the corresponding rule.
- Separately explain impacts of `privileged: true`, existing Seccomp/AppArmor settings, and unconfined overrides.

Locate vArmor agents on actual Pod nodes. Do not guess labels or pass multiple Pod names obtained solely by
`nodeName` directly to `kubectl exec`:

```bash
# Discover the agent DaemonSet first. Upstream Helm defaults the component label to varmor-agent, but the name is configurable.
kubectl --context "$CTX" get ds -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,CONTAINERS:.spec.template.spec.containers[*].name,IMAGE:.spec.template.spec.containers[*].image'

# After confirming AGENT_NS/AGENT_DS, list Pods and owners on target nodes.
# Do not manually convert DaemonSet LabelSelector to -l, which could omit matchExpressions.
kubectl --context "$CTX" get pods -n "$AGENT_NS" \
  --field-selector spec.nodeName=<node> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].kind}{"/"}{.metadata.ownerReferences[0].name}{"\t"}{.status.containerStatuses[*].ready}{"\n"}{end}'
```

`kubectl` JSONPath supports equality filters such as `?()`, not regex filters. Always delimit output, whether using JSONPath, label selectors,
or field selectors. Accept only Pods whose owner exactly matches
`DaemonSet/$AGENT_DS` and verify exactly one Ready agent remains. Read the actual
container name from the DaemonSet; explicitly use `-c "$AGENT_CONTAINER"` for later `exec`.

Probe capabilities separately. Interpret each command as `supported`, `unsupported`, or `unknown`; one unreadable path
must not invalidate evidence for other capabilities:

Before entering a privileged agent, set `L4_AUTHORIZED=yes` according to existing session authorization. Without authorization, use an existing read-only node channel
or record capability as unknown. Do not skip an unset environment variable and then claim successful probing.

```bash
# AppArmor: Y=supported, N=unsupported, unreadable file=unknown
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'printf "apparmor="; if [ -r /sys/module/apparmor/parameters/enabled ]; then cat /sys/module/apparmor/parameters/enabled; else echo unknown; fi'

# BPF LSM: readable and contains bpf=supported; readable without bpf=unsupported; unreadable=unknown
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'printf "lsm="; if [ -r /sys/kernel/security/lsm ]; then cat /sys/kernel/security/lsm; else echo unknown; fi'

# Seccomp: readable actions_avail is stronger kernel-support evidence; otherwise use current process status as weaker fallback evidence
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'if [ -r /proc/sys/kernel/seccomp/actions_avail ]; then printf "actions_avail="; cat /proc/sys/kernel/seccomp/actions_avail; else printf "actions_avail=unknown\n"; fi; awk '\''/^Seccomp:|^Seccomp_filters:/{print}'\'' /proc/self/status 2>/dev/null || true'
```

Node-enforcer capability interpretation:

- AppArmor: `parameters/enabled` must be `Y`; directory existence alone does not establish enablement.
- BPF: `/sys/kernel/security/lsm` must include `bpf`, and agent BPF enforcer must be enabled; kernel version alone is insufficient.
- Seccomp: Readable `actions_avail` listing actions establishes kernel Seccomp-filter support; `/proc/self/status`
  `Seccomp` indicates only whether the current agent process is in Seccomp mode. A value of `0` does not establish lack of kernel support.
- Report any `unknown` honestly. Do not treat query failure as `unsupported` or overwrite other established
  AppArmor/BPF evidence.
- Probe results verify user-selected Enforcer availability; they must not choose an Enforcer or expand rules on the user's behalf.

Verify each item:

- Name/selector selects target objects (**explicitly report zero matches**); `containers` names actually exist in PodTemplate/Pod.
- No target `unconfined` annotation override; confirm vArmor activation labels if needed.
- Agent Ready on hosting nodes, with evidence above supporting the declared enforcer.

For **observation-mode** policies, zero matches/uncertainty lead to **warnings + user confirmation**, rather than universal blocking.
If submission could appear successful while protecting no containers, explain that consequence first; do not report readiness.

## 1.4 Prevent overwrite (creation semantics)

First check for an existing same-name object (VP includes `--context "$CTX" -n <ns>`; VCP omits namespace):

```bash
kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>]
```

- **Absent (genuinely new)**: Use `kubectl create` to avoid overwrite by `apply`.
- **Present**: Stop. This is a phase-two update scenario; ask the user to explicitly choose the update workflow instead of overwriting here.

## 1.5 Dry-run, review, confirmation, and creation

If preflight pinned `$CTX`, restore that value from the confirmation record instead of replacing it with the new current context. If the user skipped preflight,
read and confirm the target context here. Server dry-run makes no changes; use the validated normalized file without repeating
hash verification:

```bash
if [ -z "${CTX:-}" ]; then
  CTX="$(kubectl config current-context)" || exit 1
fi
test -n "$CTX" || exit 1
kubectl --context "$CTX" cluster-info || exit 1
kubectl --context "$CTX" create \
  -f "$RUN_DIR/1.2.1-normalized.yaml" --dry-run=server || exit 1
```

Show the user:

- The complete local `1.2.1-normalized.yaml` path and `POLICY_SHA256`; show only a redacted policy summary in conversation, omitting
  Annotation values, `managedFields`, and `status`;
- **Structured diff / change summary** (creation: object, rule list, and activation scope);
- Adjustments, notices, RawRules inspection results, and preflight findings;
- Preflight evidence sources (cluster-verified / user-provided / not-checked);
- Destination cluster (`$CTX`) / namespace / name.

**Observation-mode wording**: **Built-in rules and the baseline** enter observation mode (log without blocking); **custom RawRules retain
their original action semantics**. `deny`, blocking Seccomp actions (anything beyond `ALLOW/LOG`, including ERRNO/KILL*/TRAP/
TRACE/NOTIFY), and NetworkProxy defaultAction=deny can still block. Highlight and confirm these blocking RawRules separately
with the user.

After explicit confirmation of cluster and content, verify the hash and create at the sole actual mutation point:

```bash
python3 scripts/hash_policy.py verify \
  --file "$RUN_DIR/1.2.1-normalized.yaml" --hash "$POLICY_SHA256" \
  && kubectl --context "$CTX" create -f "$RUN_DIR/1.2.1-normalized.yaml"
```

## 1.6 Verify submission results (handle VP/VCP separately)

1. Read returned policy identity and `status.profileName` (VP with `-n`, VCP without):
   ```bash
   kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
     -o jsonpath='{.status.profileName}{"\n"}{.status.phase}{"\n"}{.status.conditions}'
   ```
2. Query same-name ArmorProfile by `profileName` in the **exact namespace**; avoid `-A | grep` mismatches:
   - VP: policy namespace.
   - VCP: policy has no namespace; ArmorProfile is in the **vArmor system namespace**.
   ```bash
   kubectl --context "$CTX" get armorprofile <profileName> -n <ap-namespace> \
     -o jsonpath='{.status.desiredNumberLoaded}{"/"}{.status.currentNumberLoaded}{"\n"}{.status.conditions}'
   ```
3. **Poll explicitly**; do not use `kubectl wait --for=condition=Ready`, since ArmorProfile may lack a
   Ready condition when all nodes succeed, causing wait to time out. Require all of:
   - `desiredNumberLoaded > 0`
   - `currentNumberLoaded == desiredNumberLoaded`
   - No failing node conditions
   - Treat `0/0` as unknown/not actually loaded, not success.
4. Explain activation boundaries: Control-plane creation success does not establish protection of existing Pods. Pod targets or disabled
   `updateExistingWorkloads` require manual user recreation; Seccomp/injection changes need new Pods.
5. Guide the next step: Exercise the application sufficiently (startup/release/scaling/scheduled tasks), then enter phase two to converge using violation logs.

## 1.7 Establish the task record

Once the policy is actually loaded and required new Pods are ready, read the actual object from the API Server and create the observation-start snapshot. The script
records local epoch `capturedAt`; window `start` must not precede it:

```bash
(set -o pipefail
 kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] -o yaml \
   | python3 scripts/hash_policy.py snapshot \
   > "$RUN_DIR/1.7-policy-snapshot.json") || exit 1

(set -o pipefail
 kubectl --context "$CTX" get daemonset,pods -n "$AGENT_NS" -o json \
   | python3 scripts/build_agent_inventory.py \
       --cluster-snapshot - \
       --daemonset-name "$AGENT_DS" \
       --daemonset-namespace "$AGENT_NS" \
   > "$RUN_DIR/1.7-agent-inventory.json") || exit 1
find "$RUN_DIR" -type d -exec chmod 700 {} + || exit 1
find "$RUN_DIR" -type f -exec chmod 600 {} + || exit 1
```

The snapshot records `capturedAt`, kind/namespace/name, UID, generation, resourceVersion,
`status.profileName`, and spec hash. resourceVersion may change only because status was written back; phase two records that
change but uses UID, generation, and spec hash to detect attribution-relevant policy drift during observation, enforcing
`start >= policySnapshot.capturedAt`. The start agent inventory also records DaemonSet identity, scheduling counts,
all owned Pods/nodes/UIDs, and its own `capturedAt`; `start` must not precede that time either. Then agree on fixed
`end` with the user. Store `start/end` as epoch seconds in the task record; if the user presents ISO8601, preserve
the original value but convert once with a time zone:

- Too short a period may miss startup, release, scaling, failover, or infrequent scheduled tasks.
- Too long a period may lose logs to violations.log rotation and increases analysis volume.
- For test applications with actively triggerable main behaviors, initially suggest roughly two hours. Extend for low activity or infrequent tasks;
  shorten for high violation rates or approaching rotation capacity. Offer concrete evidence-based recommendations; the user confirms the final window.
- Usually suggest 3-5 observation cycles, but finish earlier if representative behaviors are covered and recent cycles yield no new established deletions;
  continue longer if coverage remains insufficient.

Once the start inventory is complete, `start` is no earlier than either `capturedAt`, and the user confirms the window, save the record using the
[task template](../templates/observation-task.json). Suggested convention:

- VP: `vpol-<namespace>-<name>--<start>--<plannedEnd>.json`
- VCP: `vcpol-<name>--<start>--<plannedEnd>.json`

```bash
TASKS_DIR="<task-root>/varmor-policy-optimization/<cluster-context-safe>"
install -d -m 700 "$TASKS_DIR" || exit 1
TASK_FILE="$TASKS_DIR/<task-id>.json"
```

Adjust location/naming to the environment while keeping the path persistent, `taskId` stable, and cluster, policy, and original
planned window distinguishable. With this convention, `taskId` equals the filename stem; early closure changes content only, never filename
or path. If the task ID exists, read it instead of overwriting it with a new task. Recommended permissions: `0700` for task directories,
`0600` for records.

Initially `plannedEnd` equals `end`, status is `observing`, and the record references absolute snapshot/start-inventory paths
in the policy run directory. Successfully persisting the task record establishes this optimization task; give its full path to the user. For batch processing,
create a separate record per policy and window.

Default new tasks to the local collector described in [incremental collection](../references/incremental-collection.md).
Reserve initialization time when agreeing on start. Keep the confirmed window and let the user run agreed application activity only after the script is ready before start.
Explain that node scaling, agent replacement, or DaemonSet desired/current changes block policy-wide deletion for this window;
existing evidence remains available read-only. Establish another window after topology stabilizes if complete deletion eligibility is needed.
Briefly explain collector scope/limits; do not seek repeated approval when existing authorization covers agent read-only access. It writes the run directory to task
`outputs.collectorDirectory`, reads appended logs every 30 seconds, and automatically generates `outputs.preFile` at end. The model need not
fetch logs node by node or wait for a scheduled trigger to fetch all history. If persistent local execution is unavailable, explicitly use legacy snapshot fallback with its
rotation-retention limits. The collector must initialize every node before start; immediately stop if a new launch begins at/after start or initialization crosses
start. Renegotiate the window or explicitly choose snapshot fallback; do not claim complete observation evidence.

The task record is a mutable state index; referenced snapshots/inventories are immutable start evidence. Later scheduled tasks,
reminders, or manual triggers read the same task record:

- With one-shot scheduling support, trigger phase two after `end` with the task path, first confirming the collector completed
  final reads and automatic preprocessing. Read pre.json for attribution without starting a second collector;
- If only reminders are supported, include the task path in the reminder;
- If neither is supported, the user may continue manually at any time using the task path.

Record the trigger in `trigger` as entry-point metadata only; it does not determine task existence. Incremental expiry automatically produces preprocessed input only; automatic triggers can read it and summarize
attribution. Explain attribution and obtain the user's deletion-scope decision before generating a candidate policy; never apply automatically.
