# Component Health Checks (Component)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Determine whether the vArmor control plane (manager), node data plane (agent), and modeling helper (classifier) actually work. Running does not imply functional health.

## When to use
- Overview checks reveal unready, restarting, or unhealthy components
- Policies are not distributed or APs are not created
- Webhook calls fail

---

## 1. manager control plane

### 1.1 Pod status and restart causes

```bash
# List manager Pods (<manager-pod-selector> is the full label selector, such as app.kubernetes.io/name=varmor-manager, obtained from the actual Deployment)
kubectl -n <varmor-namespace> get pods -l <manager-pod-selector> -o wide

# Inspect lastState and events for an unhealthy Pod (replace <pod-name>)
kubectl -n <varmor-namespace> describe pod <pod-name> | grep -A 20 "Last State\|Events:"

# Inspect the exit code and reason for recent restarts
kubectl -n <varmor-namespace> get pods -l <manager-pod-selector> -o jsonpath='{range .items[*]}POD={.metadata.name}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}STATE={.state}{"\t"}LAST_STATE={.lastState}{"\n"}{end}{end}'
```

**Key fields:**
| Field | Meaning |
|---|---|
| `lastState.terminated.exitCode` | A directional clue; correlate 137 with reason/events to confirm OOM, and interpret 1/2 using component logs |
| `lastState.terminated.reason` | OOMKilled/Error/Completed |
| `lastState.terminated.finishedAt` | Previous exit time, useful for identifying frequent restarts |
| `conditions[?(@.type=="Ready")].status` | Whether the Pod is actually Ready |
| `containerStatuses[*].ready` | Container readiness |

**Interpretation:**
- CrashLoopBackOff + exitCode=1 -> startup error; inspect logs first
- OOMKilled -> insufficient memory; check resources.limits and behavior-modeling data volume
- ImagePullBackOff -> image, registry, or network issue
- Running with Ready=False -> distinguish initialization from persistent failure using startup time, probes, events, and logs; briefly recheck if needed

### 1.2 Leader Election

Lease names and holderIdentity formats depend on the deployment. Query a known Lease directly; otherwise list
Lease summaries in the component namespace and confirm using manager configuration, Pod identity, and logs.

```bash
kubectl -n <varmor-namespace> get leases -o custom-columns='NAME:.metadata.name,HOLDER:.spec.holderIdentity,RENEW:.spec.renewTime,DURATION:.spec.leaseDurationSeconds'
```

The model may compare holderIdentity with candidate Pod names, UIDs, configuration, and logs; no particular string-parsing algorithm is required.
If the Leader is undetermined, mark it unknown and read bounded logs from a small set of relevant manager replicas. Startup, Webhook, and abnormal-exit
investigations need not wait for Leader identification. A missing matching Lease does not establish that no Leader exists: check whether election is enabled,
Lease naming/scope, read permissions, and renewals. Judge timeouts against the actual election configuration and observation time; do not use
fixed 15/10-second values or a fixed waiting period as a universal rule.

### 1.3 RBAC and permissions

```bash
# Inspect the manager ServiceAccount and RBAC
kubectl -n <varmor-namespace> get sa <manager-serviceaccount-name> -o yaml --ignore-not-found
kubectl get clusterrolebindings -o wide | grep <manager-serviceaccount-name>
kubectl get clusterroles | grep varmor
```

**Interpretation:**
- Missing RBAC -> manager logs contain `forbidden` or `cannot list/watch` errors

### 1.4 manager logs

Select the unhealthy instance or instances associated with the target policy/Admission request; prefer the Leader for reconcile issues.
If no single instance can be identified, collect evidence from a small candidate set over the same window and label each instance. Do not blindly choose the first item or require users to set variables manually.

```bash
kubectl -n <varmor-namespace> logs <manager-pod> -c <manager-container> --since=<duration> --tail=300
# Use --previous for restart-related issues; locally filter obtained excerpts for error/failed/panic or the target policy identity.
```

**Key log terms:**
| Term | Meaning |
|---|---|
| `Reconciler error` | Policy reconciliation failed |
| `failed to create/update ArmorProfile` | AP generation failed |
| `webhook` + `certificate`/`tls`/`x509` | Certificate issue |
| `cannot list`/`forbidden` | RBAC permission issue |
| `leader election lost` | Leadership lost; reelection may follow |
| `out of memory`/`OOM` | Insufficient memory |

---

## 2. agent data plane

### 2.1 DaemonSet coverage

```bash
# Inspect the agent DaemonSet status
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='DESIRED={.status.desiredNumberScheduled}\tREADY={.status.numberReady}\tAVAILABLE={.status.numberAvailable}\tUNAVAILABLE={.status.numberUnavailable}{"\n"}'

# Inspect Pod readiness, restarts, and scheduling; Running does not substitute for Ready
kubectl -n <varmor-namespace> get pods -l <agent-pod-selector> -o wide
```

### 2.2 Reasons for missing node coverage

```bash
# Inspect agent DaemonSet tolerations, nodeSelector, and affinity
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.tolerations}'
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.nodeSelector}'
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.affinity}'

# Inspect events on the target node (replace <node-name>)
kubectl describe node <node-name> | grep -A10 "Events:"

# Inspect events for unschedulable agent Pods
kubectl -n <varmor-namespace> get pods -l <agent-pod-selector> --field-selector=status.phase=Pending -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\t"}{.status.conditions[?(@.type=="PodScheduled")].message}{"\n"}{end}'
```

**Common reasons for missing coverage:**
- Untolerated node taints (such as `node-role.kubernetes.io/master` or `node.kubernetes.io/not-ready`)
- nodeSelector/affinity mismatch
- Insufficient node resources
- Failed hostPath mount (check whether the corresponding node directory exists)

### 2.3 Detect an agent that appears healthy but cannot enforce

A Pod may be Running while unable to load Profiles; this failure mode is easy to overlook:

First correlate the node-specific AP condition with agent logs, then inspect the relevant container security context and mounts.
Pair hostPath with volumeMount; generic terms can identify candidate volumes, but volume names alone do not establish kernel-interface visibility.
For AppArmor load failures, also compare the agent workload template with the actual Pod security settings. Follow the
[AppArmor load-failure guide](../references/troubleshooting/agent-apparmor-load-failure.md) to select a branch;
see [node.md](node.md#21-configuration-and-runtime-constraints-for-apparmor-load-failures) for targeted queries.

```bash
kubectl -n <varmor-namespace> get pod <agent-pod-on-node> -o jsonpath='{range .spec.volumes[*]}{.name}{"\t"}{.hostPath.path}{"\n"}{end}'
```

When the actual node view is needed, select targeted read-only checks from [node.md](node.md) and reuse the results. No fixed authorization variable
or complete mount inspection is required. Display only necessary, redacted path information in the conversation.

### 2.4 agent logs

```bash
# Read logs from the confirmed agent Pod on the specific node (obtain the Pod name from the node mapping in sections 2.1/2.3)
kubectl -n <varmor-namespace> logs <agent-pod-on-node> -c <agent-container> --since=<duration> --tail=200

# Filter Profile load failures for that node agent rather than aggregating every node
kubectl -n <varmor-namespace> logs <agent-pod-on-node> -c <agent-container> --since=<duration> --tail=500 | grep -iE 'failed|error|cannot load|profile|apparmor|bpf|seccomp'
```

**Key log terms:**
| Term | Meaning |
|---|---|
| `failed to load apparmor profile` / `LoadAppArmorProfile()` / `UpdateAppArmorProfile()` | Combine parser output with the AppArmor load-failure guide to distinguish rule, interface, permission, and compatibility issues |
| `interface file missing` / `unable to find a suitable fs` / `--subdomainfs` | Check AppArmor interface visibility and access constraints in the agent; do not immediately infer a missing kernel patch or mount |
| `failed to load bpf` / `invalid argument` | BPF program load failure, possibly due to kernel/BTF/architecture incompatibility |
| `failed to write seccomp profile` | Seccomp Profile write failure, possibly due to paths or permissions |
| `failed to process ArmorProfile` | AP processing failed |
| `permission denied` / `operation not permitted` | Insufficient permissions; check mounts and privileged settings |

---

## 3. classifier (BehaviorModeling only)

```bash
# Check whether classifier is deployed
CLASSIFIER_DEPLOY=$(kubectl -n <varmor-namespace> get deploy <classifier-deployment-name> -o name 2>&1)
if [ $? -eq 0 ]; then
  echo "$CLASSIFIER_DEPLOY"
  # Inspect replica availability and bounded logs; classifier is a shared service, not a per-node DaemonSet
  kubectl -n <varmor-namespace> get deploy <classifier-deployment-name> -o jsonpath='DESIRED={.spec.replicas}{"\t"}READY={.status.readyReplicas}{"\n"}'
  kubectl -n <varmor-namespace> get endpoints <classifier-service-name> -o wide
  kubectl -n <varmor-namespace> logs -l <classifier-pod-selector> --tail=200
else
  printf '%s\n' "$CLASSIFIER_DEPLOY"
  echo "CLASSIFIER_QUERY_FAILED: inspect the kubectl error; NotFound is normal only for non-modeling mode"
fi
```

**Interpretation:**
- No classifier when BehaviorModeling is disabled -> expected
- Classifier unready during modeling -> random-path classification may fail; correlate agent preprocessing errors and model contents rather than assuming all collection stopped

---

## Optional summary points
A component summary may include:
1. manager: replica count, Leader identity/status, restart causes if any, and key error-log summaries
2. agent: node coverage gaps, reasons if any, and whether the target node agent appears healthy while unable to enforce
3. classifier: deployment status (modeling only)
4. A clear next direction (for example, control plane healthy -> policy chain; node agent unhealthy -> node checks)
