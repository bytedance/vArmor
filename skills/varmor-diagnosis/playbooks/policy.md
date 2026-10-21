# Policy Chain Queries (Policy)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Verify policy compilation along the object chain: VP/VCP -> status.profileName -> AP with the same name -> node conditions. Confirm manager acceptance, AP generation, and node processing.

## When to use
- Policy READY=False / PHASE=Error/Failed
- Policy Ready=True but the target has no protection
- AP absent or Pending for an extended period
- AP not loaded on some nodes

## Prerequisites
- Known policy type: VP (namespace-scoped) or VCP (cluster-scoped)
- Known policy name, policy namespace (VP only), and namespace of the target being verified
- profileName from the overview, if available

The commands below select scope by policy type. `TARGET_NAMESPACE` always denotes the Workload/Pod namespace under verification; never implicitly conflate it with the VP namespace.

```bash
POLICY_KIND=vp                  # Only vp or vcp is allowed
POLICY_NAME=<policy-name>
POLICY_NAMESPACE=<policy-namespace>  # Ignored for VCP
TARGET_NAMESPACE=<target-namespace>

case "$POLICY_KIND" in
  vp)
    POLICY_RESOURCE="varmorpolicies.crd.varmor.org"
    POLICY_NS_FLAG="-n $POLICY_NAMESPACE"
    ;;
  vcp)
    POLICY_RESOURCE="varmorclusterpolicies.crd.varmor.org"
    POLICY_NS_FLAG=""
    ;;
  *) echo "ERROR: POLICY_KIND must be vp or vcp"; return 1 2>/dev/null || exit 1 ;;
esac

policy_get() {
  kubectl $POLICY_NS_FLAG get "$POLICY_RESOURCE" "$POLICY_NAME" "$@"
}

policy_describe() {
  kubectl $POLICY_NS_FLAG describe "$POLICY_RESOURCE" "$POLICY_NAME"
}
```

---

## 1. VP/VCP policy object

### 1.1 Policy status summary

```bash
policy_get -o jsonpath='KIND={.kind}\tNAME={.metadata.name}\tREADY={.status.ready}\tPHASE={.status.phase}\tGEN={.metadata.generation}{"\n"}PROFILE={.status.profileName}{"\n"}'
```

**Key fields:**
| Field | Interpretation |
|---|---|
| `READY=true` | Required Agents have processed the Profile; **does not establish Pod injection or execution** |
| `READY=false` | Inspect conditions and phase for the cause |
| `PHASE=Error/Failed` | Policy compilation failed |
| `PHASE=Pending` | Distinguish normal waiting from persistent failure using creation/update times, conditions, and reconcile logs |

The current public VP/VCP status API does not include `observedGeneration`; generation comparison cannot prove that manager processed the latest spec. Correlate `metadata.generation`, condition update times, phase/profileName changes, events, and manager reconcile logs.

### 1.2 Condition details

```bash
policy_get -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

**Condition types and meanings:**
| Condition Type | Meaning of True | Investigation when False |
|---|---|---|
| `Created` | AP created | Manager reconcile failure, CRD issue, RBAC |
| `Updated` | AP synchronized to the latest version | AP not updated after policy change |
| `Ready` | Required Agents responded | Nodes have not loaded it; inspect AP node conditions |

### 1.3 Policy spec validation

```bash
# Target configuration (inspect exact matching criteria)
policy_get -o jsonpath='TARGET_KIND={.spec.target.kind}{"\n"}NAME={.spec.target.name}{"\n"}SELECTOR={.spec.target.selector}{"\n"}CONTAINERS={.spec.target.containers}{"\n"}'

# Policy mode and enforcer
policy_get -o jsonpath='ENFORCER={.spec.policy.enforcer}{"\n"}MODE={.spec.policy.mode}{"\n"}'

# Unconfined annotations or bypass settings on the target
# Note: unconfined is set on the target Workload/Pod, not the policy
```

**Target-validation checklist:**
1. Is `kind` one of Deployment/StatefulSet/DaemonSet/Pod?
2. Are `name` and `selector` mutually exclusive, with exactly one present?
3. Is `selector` valid Kubernetes label selector syntax?
4. Does the VP namespace match the target Workload namespace?
5. Could a VCP overlap the VP in that namespace? The current injector checks VCPs first and selects one matching policy; do not assume rule merging. Confirm behavior against the deployed version.
6. Does the target Workload/Pod have the `<webhook-object-label>` label (default matching label; use actual deployment configuration)?

### 1.4 Policy events

```bash
# Describe using the actual VP/VCP scope; do not force a cluster-scoped VCP into a namespace
policy_describe | grep -A30 "Events:"

# Structured event queries preserve more complete sorted results; query across namespaces because VCP events may occur in different namespaces
POLICY_UID=$(policy_get -o jsonpath='{.metadata.uid}') ||
  { echo "POLICY_QUERY_FAILED: cannot read policy UID"; return 1 2>/dev/null || exit 1; }
case "$POLICY_KIND" in
  vp)
    EVENT_KIND=VarmorPolicy
    EVENT_SCOPE_FLAG="-n $POLICY_NAMESPACE"
    ;;
  vcp)
    EVENT_KIND=VarmorClusterPolicy
    EVENT_SCOPE_FLAG="-A"
    ;;
esac
kubectl $EVENT_SCOPE_FLAG get events \
  --field-selector "involvedObject.uid=$POLICY_UID,involvedObject.kind=$EVENT_KIND,involvedObject.name=$POLICY_NAME" \
  --sort-by='.lastTimestamp' ||
  echo "EVENTS_QUERY_FAILED: inspect RBAC, API connectivity, and event availability"
```

Kubernetes Events have limited retention, and vArmor versions may not emit an Event for every reconcile. Empty results do not establish absence of policy errors; prioritize conditions, phase/profileName changes, and manager logs.

---

## 2. ArmorProfile (AP) execution object

### 2.1 Does the AP exist with correct status?

Obtain the AP name from policy status.profileName. In the official implementation, a VP AP is typically in the policy (application) namespace,
and a VCP AP in the vArmor component namespace. Prefer targeted queries along that relationship and reuse existing results.
If the actual namespace is unknown, query name-filtered summaries across namespaces and confirm using policy identity and object relationships:

```bash
kubectl --context <context> get armorprofiles.crd.varmor.org -A \
  --field-selector 'metadata.name=<profile-name>' \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid'
```

This is a list query, not `get … -A <name>`. Never blindly select the first of multiple same-name results. Preserve discovery gaps
on permission or query failures instead of interpreting them as AP absence. If scope is unclear, use API discovery or query the specific CRD;
scope establishes whether a namespace is required, not which namespace to use.

```bash
# For namespaced APs, use the confirmed namespace; omit -n for cluster-scoped APs.
kubectl -n <confirmed-ap-namespace> get armorprofiles.crd.varmor.org <profile-name> -o json
```

A single read can provide loading counts, conditions, and policy association for local extraction. Fill AP_NS_FLAG and PROFILE_NAME
in later examples from those same object facts. Distinguish NotFound, Forbidden, and connection failures.

**Interpretation:**
- AP absent -> manager has not created it, or a residual policy remains after deletion
- `DESIRED=0` -> zero agents are currently expected to respond; correlate agent coverage, reconcile, and target/injection evidence rather than inferring a target mismatch from this value alone
- `CURRENT < DESIRED` -> some nodes have not loaded it; record the affected nodes
- `CURRENT = DESIRED` -> expected successful-report count reached; still inspect AP failure conditions and the owning VP/VCP status. AP has no `status.ready` field, and `0/0` alone does not establish successful loading.

### 2.2 AP node conditions (locate failing nodes)

```bash
# List all failed node conditions using the confirmed AP scope
kubectl $AP_NS_FLAG get armorprofiles.crd.varmor.org "$PROFILE_NAME" -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.nodeName}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}' | grep -v True
# Or select status=False conditions more precisely
kubectl $AP_NS_FLAG get armorprofiles.crd.varmor.org "$PROFILE_NAME" -o json | python3 -c "
import sys, json
ap = json.load(sys.stdin)
for c in ap.get('status', {}).get('conditions', []):
    if c.get('status') != 'True':
        print(f\"NODE={c.get('nodeName','N/A')}\tTYPE={c.get('type')}\tSTATUS={c.get('status')}\tREASON={c.get('reason','')}\tMSG={c.get('message','')}\")
"
```

**Failure categories inferred from actual reason/message and agent logs** (these are not fixed API Reason values):
| Category | Investigation |
|---|---|
| AppArmor load failure | Node AppArmor LSM, Profile syntax, securityfs mounts |
| BPF load failure | Kernel version/architecture, BTF, BPF LSM, map/program resources |
| Seccomp write failure | Kubelet path permissions, Profile contents, runtime support |
| Profile processing failure | Agent processing error; inspect agent logs |

### 2.3 AP and policy version consistency

```bash
# Inspect AP owner identity and resource version (using the confirmed AP scope)
kubectl $AP_NS_FLAG get armorprofiles.crd.varmor.org "$PROFILE_NAME" -o jsonpath='{.metadata.ownerReferences}{"\n"}{.metadata.resourceVersion}{"\n"}'
# Correlate the actual policy spec, generated AP spec, condition times, and manager reconcile evidence.
```

The current implementation copies policy labels to AP; it does not guarantee a policy-generation label or VP/VCP `status.observedGeneration`. AP creation time alone cannot prove that an update was reconciled.

---

## 3. Matching validation (does target select the intended objects?)

Prefer existing policy and target objects to establish actual matching. For complex selectors, use the script below or an equivalent API query. First restrict to the single resource type in `target.kind`, then distinguish `target.name` from `target.selector`. The selector is a standard `metav1.LabelSelector`, potentially containing `matchLabels` (multiple key=value pairs) and `matchExpressions` (In/NotIn/Exists/DoesNotExist set operations); never assume a single key=value.

```bash
# Run from the Skill root. The script reads one policy and computes actual matches in the explicitly supplied TARGET_NAMESPACE
# using target.kind/name or the full LabelSelector; it does not proceed to AP, Pod, or node queries.
if [ "$POLICY_KIND" = "vp" ]; then
  python3 scripts/match-policy-target.py \
    --kind vp \
    --name "$POLICY_NAME" \
    --namespace "$POLICY_NAMESPACE"
else
  python3 scripts/match-policy-target.py \
    --kind vcp \
    --name "$POLICY_NAME" \
    --target-namespace "$TARGET_NAMESPACE"
fi
```

The script's `POLICY` and `TARGET` lines retain policy identity, container scope, and original matching criteria. `CANDIDATE` lines report whether API candidates satisfy the full selector, with `failed` identifying unmet conditions; `MATCH` lists final matches. `SUMMARY` retains candidate, matched, and unmatched counts. `ERROR` indicates query, structure, or selector-parsing failure, not zero matches. The script does not check Webhook matching labels, unconfined, or VP/VCP overlap; verify these separately below.

**Key checkpoints:**
1. Whether target.kind/name/selector actually selects the intended objects of that type
2. Whether the target Workload/Pod has the vArmor matching label
3. Whether the target container is included in `spec.target.containers` (empty means all containers)
4. Whether explicit bypass annotations such as `<unconfined-annotation>` exist
5. Whether VCP/VP overlap handling matches actual version semantics

---

## 4. Conflict analysis for configured built-in rules

For an `EnhanceProtect` policy requiring explanation of rule conflicts, loading failures, or affected application behavior, first compare actual rules with the corresponding enforcer semantics; use the script for complex conflict metadata. It reads built-in rules already configured in one existing VP/VCP; it does not add, delete, or recommend rules or output policy templates.

Reading policy metadata is L0; assess related APM behavior samples as L1 based on scope and sensitivity. No new behavior collection is triggered. The script outputs only matching dimensions, counts, and executable basenames; full file paths are always redacted.

```bash
# Read one VP online; for VCP use --kind vcp --name <name> and omit --namespace
python3 scripts/analyze-built-in-rules.py \
  --kind vp \
  --namespace "$POLICY_NAMESPACE" \
  --name "$POLICY_NAME" \
  --features "mount-sth,require-sa" \
  --capabilities "sys_admin" \
  --apm-name <apm-name> \
  --apm-namespace <apm-namespace>

# Offline analysis requires JSON exported with kubectl -o json; APM is optional
python3 scripts/analyze-built-in-rules.py \
  --policy-file <policy.json> \
  --apm-file <apm.json> \
  --features "" \
  --capabilities ""
```

Omitted `--features` or `--capabilities` means unknown context; an empty string means the corresponding set is confirmed empty. Do not infer features/capabilities from image names. APM is a time-bounded behavior sample, not a complete allowlist. The script outputs only matching dimensions, counts, and executable basenames; file paths are always redacted.

Status interpretation:

| Status | Meaning |
|---|---|
| `CONFLICT_DECLARED` | Explicit features/capabilities intersect the catalog conflict metadata |
| `CONFLICT_OBSERVED` | The supplied APM sample matches a capability/syscall/execution/file conflict |
| `NO_CONFLICT_OBSERVED` | No match in the supplied APM sample; this is sample-limited and cannot establish absence of conflicts |
| `APM_DATA_UNAVAILABLE` | The rule has behavioral conflict conditions but no APM was supplied; do not present this as no conflict |
| `APPLICABILITY_NOT_ESTABLISHED` | Explicit context does not establish the rule's applicability conditions |
| `UNSUPPORTED_BY_ENFORCER` | The policy enforcer has no intersection with rule enforcers declared by the advisor catalog |
| `UNASSESSED` | Rule absent from the advisor catalog, or required context/metadata missing |
| `SUPPORTED` | No conflict established within the supplied evidence, and no further behavior evidence required |

`CONCLUSION status=REVIEW_REQUIRED` or `INTERPRETATION rule_layer=NOT_EXCLUDED` means the rule layer has not been ruled out; do not report that the issue is outside the rule layer or that rule configuration is conflict-free. The catalog's pinned source and commit are recorded in `scripts/built-in-rule-conflicts.json`. The runtime may support newer rules absent from the catalog; output `UNASSESSED` for them rather than inventing conflict conditions. `CONCLUSION status=NO_CONFLICT_ESTABLISHED` only means the supplied evidence establishes no conflict, not a guarantee of policy safety or application compatibility.

---

## Optional summary points
A policy-chain summary may include:
1. Basic policy state: READY/PHASE/GEN consistency
2. Abnormal Conditions (reason + message)
3. AP existence and DESIRED/CURRENT differences
4. Failing nodes and their failure reasons
5. Actual target kind/name/selector matching results
6. Configured-rule conflict status, when applicable, and evidence limitations
7. The precise breakpoint: matching, compilation, AP generation, or node response
8. Next direction
