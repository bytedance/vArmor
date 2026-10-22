# Overview Queries (Overview)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Quickly determine the impact scope: global, one node, one policy, one workload, or one container. Set diagnostic priorities and avoid indiscriminate full-data collection.

## When to use
Use early in an investigation when the failure scope is unclear. If the symptom does not suggest an entry point, run this playbook to narrow the scope.

## Prerequisites
- Known target namespace (optional; omit for cross-namespace issues)
- Known vArmor installation namespace (<varmor-namespace>; discover it from actual deployment objects, Webhook Service references, or related controller objects; do not assume a fixed default)

---

## 1. vArmor component overview

Determine whether the control plane and data plane are broadly available.

```bash
# Inspect the confirmed component scope; add component selectors in a shared namespace to avoid unrelated application Pods
kubectl -n <varmor-namespace> get pods -l <varmor-component-selector> -o wide

# Inspect desired/ready counts for each component
kubectl -n <varmor-namespace> get deploy <manager-deploy-name> -o jsonpath='{.spec.replicas}/{.status.readyReplicas}/{.status.availableReplicas}' && echo
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.status.desiredNumberScheduled}/{.status.numberReady}/{.status.numberAvailable}' && echo
CLASSIFIER_STATUS=$(kubectl -n <varmor-namespace> get deploy <classifier-deployment-name> -o jsonpath='{.spec.replicas}/{.status.readyReplicas}/{.status.availableReplicas}' 2>&1)
if [ $? -eq 0 ]; then
  echo "$CLASSIFIER_STATUS"
else
  printf '%s\n' "$CLASSIFIER_STATUS"
  echo "CLASSIFIER_QUERY_FAILED: inspect the kubectl error and distinguish NotFound from permission or connectivity failures"
fi
```

**Key fields:**
| Field | Meaning |
|---|---|
| `STATUS` | Pod status (Running/Pending/CrashLoopBackOff/ImagePullBackOff) |
| `RESTARTS` | Restart count; correlate values >0 with lastState |
| `AGE` | Age; a short age may indicate a recent start or repeated restarts |
| `NODE` | Hosting node, useful for identifying node-specific failures |
| `spec.replicas/status.readyReplicas` | Desired/ready manager or classifier replicas |
| `desiredNumberScheduled/numberReady` | Desired/ready agent nodes |

**Interpretation:**
- manager 0 Ready -> global control-plane failure; start with the manager section of [component.md](component.md)
- agent numberReady < desiredNumberScheduled -> coverage gaps; the failure may be limited to unready nodes
- classifier absent -> abnormal only when BehaviorModeling is in use
- All components Ready does not establish functional health; continue downstream checks

---

## 2. Policy overview

Prefer the target namespace when known. Use the cross-namespace summaries below only when scope is unclear or evidence indicates a global problem; focus on specific policies once abnormalities are found.

```bash
# Summarize all VarmorPolicy objects (key status fields, not full YAML)
kubectl get varmorpolicies.crd.varmor.org --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.ready,PHASE:.status.phase,PROFILE:.status.profileName,AGE:.metadata.creationTimestamp'

# Summarize all VarmorClusterPolicy objects
kubectl get varmorclusterpolicies.crd.varmor.org -o custom-columns='NAME:.metadata.name,READY:.status.ready,PHASE:.status.phase,PROFILE:.status.profileName,AGE:.metadata.creationTimestamp'

# Inspect loading status for all ArmorProfile objects
kubectl get armorprofiles.crd.varmor.org --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,DESIRED:.status.desiredNumberLoaded,CURRENT:.status.currentNumberLoaded,AGE:.metadata.creationTimestamp'
```

**Key fields:**
| Field | Meaning |
|---|---|
| `READY` | VP/VCP readiness (bool); AP has no `status.ready` field |
| `PHASE` | Phase (Pending/Protecting/Modeling/Completed/Error/Failed) |
| `DESIRED/CURRENT` | Desired/current AP node-loading counts; a difference indicates nodes without the Profile loaded |

**Interpretation:**
- All policies Pending/Error -> global control-plane issue; return to component checks
- One policy READY=False -> policy-specific chain issue; open [policy.md](policy.md)
- AP CURRENT < DESIRED -> some nodes have not loaded it; record affected node names and open [node.md](node.md)
- All policies Ready but target Pod unhealthy -> injection or runtime issue; continue downstream

---

## 3. Webhook overview

Determine whether Webhook configurations exist and endpoints are available.

```bash
# Check for Mutating/Validating Webhook configurations
kubectl get mutatingwebhookconfigurations | grep varmor
kubectl get validatingwebhookconfigurations | grep varmor

# Check whether the Webhook Service exists and has Endpoints
kubectl -n <varmor-namespace> get svc | grep webhook
kubectl -n <varmor-namespace> get endpoints | grep webhook
```

A keyword miss only means no candidate was found. Confirm through Service references and the actual deployment before concluding absence.

**Interpretation:**
- Relevant Webhook configuration confirmed absent -> possible installation issue or upgrade residue
- Service exists but Endpoints are empty -> manager Pods unready or Service selector mismatch
- Webhook configuration and endpoints healthy -> label/rule matching issues remain possible; inspect [webhook.md](webhook.md)

---

## 4. Scope decision tree

Use these results to select the next step:

| Observation | Impact scope | Next step |
|---|---|---|
| manager CrashLoop/0 Ready | Global | -> manager section of [component.md](component.md) |
| agent unready on one or more nodes | Node | -> [node.md](node.md) |
| All policies Pending/Error | Global | -> [component.md](component.md) -> [policy.md](policy.md) |
| One policy READY=False | Policy | -> [policy.md](policy.md) |
| Policy Ready, AP fully loaded, target Pod Pending | Pod | -> [workload.md](workload.md) -> [webhook.md](webhook.md) |
| Policy Ready, Pod Running with abnormal behavior | Runtime | -> [workload.md](workload.md) -> [audit.md](audit.md) |
| Egress networking/proxy involved | NetworkProxy | -> [networkproxy.md](networkproxy.md) |
| Missing behavior-modeling data | Modeling | -> [behavior-modeling.md](behavior-modeling.md) |

---

## Optional summary points
Select relevant items from the evidence actually collected:
1. Which components are Ready and which are not
2. Counts of ready and unhealthy policies
3. Node coverage gaps for unhealthy APs
4. Whether Webhook configurations and endpoints exist
5. Initial impact scope and next direction

Do not collect complete logs, complete events, or describe every Pod during the overview.
