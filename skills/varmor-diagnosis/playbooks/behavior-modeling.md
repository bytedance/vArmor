# BehaviorModeling-Specific Checks (Behavior Modeling)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Investigate the behavior-modeling chain: collection -> normalization -> reporting -> aggregation -> persistence. Modeling describes observed behavior; it establishes neither completeness nor an automatically safe allowlist.

## When to use
- Policy mode=BehaviorModeling but no data
- Modeling never completes
- APM (ArmorProfileModel) absent or empty
- Mode switch fails after modeling completes
- Classifier unhealthy

## Prerequisites
- Known policy type (VP/VCP), policy name, VP namespace, and vArmor component namespace
- Known modeling duration and start time
- Target Workload is running and generating behavior

APM shares the name in `status.profileName`; locate it in the discovered AP namespace. For VP this is usually the policy namespace,
and for VCP the vArmor component namespace. If unknown, first locate AP using policy.md section 2.1, then query APM in the same
namespace. Adapt the scope examples below to existing results; CRD scope alone does not establish the object namespace.

When modeling with the BPF enforcer, executing commands inside target application containers may introduce additional behavior samples. Prefer API queries and existing
logs. Explain the sample impact of necessary exec operations; do not treat diagnostic activity as original application behavior.

```bash
POLICY_KIND=vp                  # Only vp or vcp is allowed
POLICY_NAME=<policy-name>
POLICY_NAMESPACE=<policy-namespace>  # Ignored for VCP
VARMOR_NAMESPACE=<varmor-namespace>

case "$POLICY_KIND" in
  vp)
    POLICY_RESOURCE="varmorpolicies.crd.varmor.org"
    POLICY_NS_FLAG="-n $POLICY_NAMESPACE"
    APM_NAMESPACE="$POLICY_NAMESPACE"
    ;;
  vcp)
    POLICY_RESOURCE="varmorclusterpolicies.crd.varmor.org"
    POLICY_NS_FLAG=""
    APM_NAMESPACE="$VARMOR_NAMESPACE"
    ;;
  *)
    echo "ERROR: POLICY_KIND must be vp or vcp"
    return 1 2>/dev/null || exit 1
    ;;
esac

policy_get() {
  kubectl $POLICY_NS_FLAG get "$POLICY_RESOURCE" "$POLICY_NAME" "$@"
}
```

---

## 1. Modeling prerequisites

### 1.1 containerd and BTF

Use the confirmed target Pod nodeName to inspect relevant node runtimes. For multi-node issues, start with failing nodes and expand based on evidence.
Validate node capabilities such as BTF through targeted [node.md](node.md) checks. Prefer collection errors in AP/agent logs; if needed, inspect
one known BTF file rather than performing a complete node inspection for a modeling failure.

```bash
kubectl get node <target-node> -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}{"\n"}'
```

Confirm the agent through the relevant DaemonSet owner, node, and container. Unready state does not prevent status/log evidence collection.
Fill NODE_NAME, AGENT_POD, and container in later examples from existing facts.

### 1.2 classifier deployment

```bash
# Check whether the shared classifier Deployment exists
CLASSIFIER_DEPLOY=$(kubectl -n "$VARMOR_NAMESPACE" get deploy <classifier-deployment-name> -o name 2>&1)
if [ $? -eq 0 ]; then
  echo "$CLASSIFIER_DEPLOY"
  # Replica availability and shared Service endpoints; no per-node classifier is required
  kubectl -n "$VARMOR_NAMESPACE" get deploy <classifier-deployment-name> -o jsonpath='DESIRED={.spec.replicas}{"\t"}READY={.status.readyReplicas}{"\n"}'
  kubectl -n "$VARMOR_NAMESPACE" get endpoints <classifier-service-name> -o wide
  kubectl -n "$VARMOR_NAMESPACE" get pods -l <classifier-pod-selector> -o wide
else
  printf '%s\n' "$CLASSIFIER_DEPLOY"
  echo "CLASSIFIER_QUERY_FAILED: inspect the kubectl error; distinguish NotFound from permission or connectivity failures"
fi
```

The official Chart enables classifier with BehaviorModeling. Confirm its actual Deployment and Service from installation resources. Agent preprocessing calls the Service for random-path classification; failed calls currently retain the original path, so classifier absence alone does not prove no data can be reported.

### 1.3 Audit source configuration

```bash
# Check whether audit/behavior collection is enabled in agent configuration
# Inspect relevant agent startup arguments; read necessary nonsensitive switches and redact credentials/endpoints as needed
kubectl -n "$VARMOR_NAMESPACE" get ds <agent-daemonset-name> -o go-template='{{range .spec.template.spec.containers}}{{$name := .name}}{{range .args}}{{$name}}{{"\t"}}{{.}}{{"\n"}}{{end}}{{end}}' |
  grep -iE 'audit|behavior|model|bpf' |
  sed -E 's/(--[^=[:space:]]+)=.*$/\1=<redacted>/'
# Check agent ConfigMap presence and key names only; do not output data, which may contain internal endpoints, certificates, or credentials
kubectl -n "$VARMOR_NAMESPACE" get cm -l <agent-pod-selector> -o go-template='{{range .items}}{{.metadata.name}}{{":"}}{{"\n"}}{{range $k,$v := .data}}  {{$k}}{{"\n"}}{{end}}{{end}}'
# If a specific setting is needed, confirm the key and query it directly:
# kubectl -n "$VARMOR_NAMESPACE" get cm <confirmed-cm-name> -o jsonpath='{.data.<confirmed-config-key>}'
```

---

## 2. Policy modeling status

```bash
# Modeling policy status
policy_get -o jsonpath='KIND={.kind}\tREADY={.status.ready}\tPHASE={.status.phase}{"\n"}DURATION={.spec.policy.modelingOptions.duration}{"\n"}PROFILE={.status.profileName}{"\n"}'

# conditions
policy_get -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

**Modeling phase meanings:**
| Phase | Meaning |
|---|---|
| `Pending` | Waiting for modeling to start or prerequisites unmet |
| `Modeling` | Collection in progress |
| `Completed` | Modeling complete and APM generated |
| `Error/Failed` | Modeling failed |

---

## 3. APM (ArmorProfileModel) checks

```bash
# APM has the same name as policy status.profileName
APM_NAME=$(policy_get -o jsonpath='{.status.profileName}') ||
  { echo "POLICY_QUERY_FAILED: cannot read status.profileName"; return 1 2>/dev/null || exit 1; }
if [ -z "$APM_NAME" ]; then
  echo "PROFILE_NAME_EMPTY: policy has not reported status.profileName; stop APM queries"
  return 1 2>/dev/null || exit 1
fi
echo "APM namespace/name: $APM_NAMESPACE/$APM_NAME"

APM_JSON=$(kubectl -n "$APM_NAMESPACE" get armorprofilemodels.crd.varmor.org "$APM_NAME" -o json) ||
  { echo "APM_QUERY_FAILED: inspect the kubectl error and verify the namespace against the actual object"; return 1 2>/dev/null || exit 1; }
printf '%s' "$APM_JSON" | python3 -c "
import json, sys
apm = json.load(sys.stdin)
status = apm.get('status') or {}
print(f\"DESIRED={status.get('desiredNumber','')}\tCOMPLETED={status.get('completedNumber','')}\tREADY={status.get('ready','')}\")
print(f\"STORAGE_TYPE={apm.get('storageType','')}\")
for condition in status.get('conditions') or []:
    print(
        f\"NODE={condition.get('nodeName','')}\tTYPE={condition.get('type','')}\t\"
        f\"STATUS={condition.get('status','')}\tREASON={condition.get('reason','')}\t\"
        f\"MESSAGE={condition.get('message','')}\tLAST={condition.get('lastTransitionTime','')}\"
    )
"
```

**APM storage considerations:**
- `storageType` is a top-level APM field; modeling data is under top-level `data`
- Large APM data may use local storage (`storageType=LocalDisk`) instead of residing entirely in the CRD
- In that case, queries to `armorprofilemodels.crd.varmor.org` may not expose the full model; interpret using manager storage configuration and logs

---

## 4. Investigate the three modeling stages

When modeling produces no data, verify these stages separately:

### 4.1 Stage 1: collection capability (node)

```bash
# Collection errors in target node agent logs
kubectl -n "$VARMOR_NAMESPACE" logs "$AGENT_POD" -c <agent-container> --since=<duration> --tail=300 | grep -iE 'modeling|audit|collect|bpf|behavior|error|failed'

# If logs are insufficient, inspect the identified BPF objects using node.md; do not enumerate all programs by default.

# Confirm the target Pod actually generates behavior (application running)
kubectl -n <namespace> get pod <target-pod> -o jsonpath='PHASE={.status.phase}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}READY={.ready}{"\t"}RESTARTS={.restartCount}{"\n"}{end}'
# A target Pod that never starts or continuously crashes may produce no behavior to collect
```

**Collection-layer issues:**
- BTF unavailable -> BPF collection program cannot load
- Behavior collection not enabled in agent -> inspect configuration
- Target Workload not running/no traffic -> no behavior data
- containerd version/configuration issue -> process identity correlation fails

### 4.2 Stage 2: agent preprocessing and reporting, with classifier assistance

Identify classifier instances from Service selectors and Deployment/ReplicaSet ownership, independently of the target node. Inspect container readiness, restarts,
lastState, and resources. Use failure time to investigate unhealthy or old instances during upgrades; a unique Ready instance is not required for log reads.

```bash
kubectl -n "$VARMOR_NAMESPACE" logs <classifier-pod> -c <classifier-container> --since=<duration> --tail=300
# If OOM is suspected, correlate lastState, resources, and events; use top for one Pod if metrics are available and needed.
```

**Preprocessing/reporting issues:**
- Agent-to-classifier Service failure or classifier OOM -> random-path classification may fail and original paths may remain in the model
- Agent preprocessing failure -> inspect audit/BPF parsing and agent resource errors
- Agent-to-manager status Service failure -> behavior-data reporting fails
- Agent authentication/authorization failure -> inspect token, TLS, manager status-service errors, and relevant RBAC; the classifier does not submit reports

### 4.3 Stage 3: aggregation and persistence (manager)

Prefer the manager Leader for reconcile/aggregation issues; discover its identity through component.md. If the Leader cannot be resolved,
seek evidence in bounded logs from a small relevant instance set without requiring manual user confirmation before proceeding.

```bash
kubectl -n "$VARMOR_NAMESPACE" logs <manager-pod> -c <manager-container> --since=<duration> --tail=300
```

When storageType=LocalDisk and logs indicate persistence failure, confirm the storage mount and target file first. Prefer metadata and
targeted readability checks rather than scanning the entire storage directory. Follow shared authorization conventions; an ordinary container identity is not automatically L4.

**Aggregation-layer issues:**
- Manager OOM -> insufficient memory for cross-node aggregation
- Storage permission issue -> APM cannot persist
- Manager reconcile error -> APM not created or updated

---

## 5. Validate completed modeling

Reuse existing APM_JSON; reread only when checking a status change.

```bash
# Check whether APM contains data after modeling completes
if [ -n "$APM_NAME" ]; then
  # Check only whether actual model fields are nonempty; do not output raw behavior data that may contain sensitive paths
  APM_JSON=$(kubectl -n "$APM_NAMESPACE" get armorprofilemodels.crd.varmor.org "$APM_NAME" -o json) ||
    { echo "APM_QUERY_FAILED: cannot inspect model data"; return 1 2>/dev/null || exit 1; }
  printf '%s' "$APM_JSON" | python3 -c "
import sys, json
apm = json.load(sys.stdin)
data = apm.get('data') or {}
dynamic_result = data.get('dynamicResult')
profile = data.get('profile')
print(f'APM has dynamicResult content: {bool(dynamic_result)}')
print(f'APM has profile content: {bool(profile)}')
"
fi
```

**⚠️ Completed modeling does not imply protection readiness:**
- Modeling describes only observed behavior, not completeness
- Short windows may miss periodic behavior such as scheduled tasks or infrequent operations
- Confirm successful mode switching to DefenseInDepth after modeling
- Do not use modeling results directly for Deny-by-Default policies without human review

---

## 6. Check post-modeling mode switching

```bash
# After switching from BehaviorModeling to DefenseInDepth
# 1. Check whether policy phase becomes Protecting
policy_get -o jsonpath='PHASE={.status.phase}{"\t"}READY={.status.ready}{"\n"}'

# 2. Confirm current Profile/AP and configuration changes; a name change is not required for a successful switch
policy_get -o jsonpath='{.status.profileName}{"\n"}'

# 3. Check successful AP loading
AP_NAME=$(policy_get -o jsonpath='{.status.profileName}')
# Locate the ArmorProfile namespace using policy.md section 2.1: prefer VP/VCP relationships; if unknown, query name-filtered summaries across namespaces
kubectl -n <confirmed-ap-namespace> get armorprofiles.crd.varmor.org "$AP_NAME" -o jsonpath='DESIRED={.status.desiredNumberLoaded}\tCURRENT={.status.currentNumberLoaded}{"\n"}'

# 4. Check whether new Pods receive the new Profile injection (rollout required)
```

---

## Optional summary points
A BehaviorModeling summary may include:
1. Prerequisite status (containerd/BTF/classifier/audit configuration)
2. Policy phase and modeling duration/start time
3. APM existence and completed-node count
4. storageType and its implications for data visibility
5. Which of the three stages is affected (collection/preprocessing and reporting/aggregation)
6. Error-log summaries from agent/classifier/manager
7. Whether the target Workload actually generates behavior
8. If complete: APM visibility, observation gaps, and mode-switch status
9. Next direction
