# vArmor architecture and diagnosis map

## 1. System purpose

vArmor is a Kubernetes Operator-style cloud-native container hardening system. Users declare targets, enforcers, modes, and rules through VP/VCP. The manager compiles this intent into AP/Profiles; agents load them on nodes. Webhooks inject Profile and proxy settings into target workloads during admission.

Its security boundary combines workload-level, node kernel/runtime-level, and application egress controls; it is not a hardware-virtualized container.

## 2. Components and responsibilities

| Component | Role | Key responsibilities | Typical affected scope |
|---|---|---|---|
| `varmor-manager` | Control-plane Deployment | Watch VP/VCP, validate/reconcile policies, generate AP/Profiles, manage webhooks, process modeling results, and propagate NetworkProxy configuration | Cluster or policy |
| `varmor-agent` | Node data-plane DaemonSet | Watch APs, prepare AppArmor/BPF/Seccomp resources, report load results to the manager's status service, and emit audit events | One node and its target Pods |
| `varmor-classifier` | BehaviorModeling helper Deployment behind a Service | Classify random path elements for agent-side preprocessing; agents report results to the manager | BehaviorModeling only |
| Mutating Webhook | Admission mutation | Inject Profile references and NetworkProxy sidecar/initContainer into matching Workloads/Pods | Create/update requests |
| Validating Webhook | Admission validation | Validate policy targets, modes, enforcers, NetworkProxy configuration, and immutable fields | VP/VCP write requests |
| Kubernetes API/kubelet/runtime | Runtime pipeline | Store CRDs, schedule Pods, read SecurityContext, and load Localhost Profiles | Cluster/node/Pod |
| Linux kernel/LSM/audit | Enforcement | Apply AppArmor/BPF/Seccomp restrictions and auditing | Node/process |
| Envoy sidecar | NetworkProxy data plane | Transparently receive egress traffic and enforce L4/L7/SNI/HTTP/TLS MITM rules | Pod egress |

## 3. End-to-end object chain

```text
VP / VCP
  └─ spec.target + spec.policy
       │ manager reconcile / validating webhook
       ▼
status.profileName + ArmorProfile + manager-generated NetworkProxy Secret/config
       ├─ agent prepares AppArmor / BPF / Seccomp resources on nodes
       │  and reports results to the manager's status service
       │ mutating webhook adds references and, for NetworkProxy, init/sidecar/volumes
       ▼
Pod admitted → scheduled → kubelet/runtime creates container
       │
       ▼
node enforcement + audit event → agent/manager status and user-visible behavior
```

## 3.1 Workload lifecycle and observation points

Policies act on workload PodTemplates, but security settings ultimately reside in individual Pods. Understand runtime objects through this relationship:

```text
Deployment / StatefulSet / DaemonSet
  └─ PodTemplate
       └─ ReplicaSet or controller creates Pod
            └─ Final PodSpec after admission injection
                 └─ Scheduled to node -> kubelet/runtime creates containers
```

- Deployment, StatefulSet, and DaemonSet controllers create or replace Pods according to their update semantics. A successful policy update does not mean existing Pods were updated.
- If the PodTemplate is injected but actual Pods are not, check whether a rollout occurred, Pods belong to an old ReplicaSet, or Pods came from another template.
- If an existing Pod is injected but a new one is not, compare creation times, ownerReferences, template hashes, webhook scope, and policy activation time.
- A bare Pod has no higher-level workload controller. Policy updates/deletion or webhook recovery usually do not migrate its lifecycle for it.

To diagnose enforcement, inspect at least the policy, AP, workload PodTemplate, actual Pod, target node, and runtime events separately.

Common sources of confusion:

- AP is an internal enforcement object, not the user policy interface. AP node conditions are closer to node-preparation failures than VP Ready.
- A workload PodTemplate and an already running Pod are separate observation points. Without template injection, future Pods usually lack protection; an injected template may still leave old, unrecreated Pods using previous settings.
- Adding an enforcer to a policy does not automatically give existing workloads that enforcer. Verify actual Pod injection.
- Seccomp Profile changes require workload restart to affect running containers. Verify other updates according to the actual enforcer and Pod lifecycle too.

## 4. Assessing impact

- No available manager Leader: policy reconciliation and leader-only status/configuration processing are affected. Webhook servers run separately on manager replicas; assess their Service/endpoints and request errors independently of election state.
- A temporary failure in a non-Leader manager replica is usually handled by other replicas; do not infer a global outage directly.
- Missing webhook configuration, a Service without endpoints, mismatched TLS/CA, or selector mismatch can reject policy writes or leave workloads uninjected.
- A missing/unhealthy agent on one node primarily indicates a local failure. APs there may not be Ready, and target Pods may fail creation or lack hardening.
- Classifier failure usually affects only BehaviorModeling collection.
- NetworkProxy sidecar/initContainer/Secret/certificate-chain failures may prevent Pod creation, leave the proxy unready, break egress, or prevent HTTPS L7 enforcement.

## 5. Health baseline

1. A stable manager Leader with no persistent reconciliation errors;
2. Agents cover all intended nodes and can process APs;
3. When modeling is enabled, the classifier Deployment/Service is available to the agents that use it; a classifier Pod on every node is not required;
4. Mutating/Validating Webhook configuration, Services, endpoints, certificates, and matching scope agree;
5. VP/VCP `status.ready`, `conditions`, and `phase` match the intended stage;
6. AP `desiredNumberLoaded` equals `currentNumberLoaded`, with no failed-node conditions;
7. Target Workload/Pod selectors, labels, container scope, and explicit bypass settings match expectations;
8. Node kernel, LSM, BTF, containerd, kubelet, and Profile storage/mount capabilities meet the chosen enforcer requirements;
9. NetworkProxy target Pods have consistent sidecar, init, Secret, ports, UID, certificates, and proxy status.

## 6. Investigation priorities

1. Does the Pod exist and is it scheduled?
2. Does the Pod/Workload show vArmor injection?
3. Do VP/VCP target and policy match?
4. Does the AP for `profileName` exist, with complete node load counts?
5. Are the target node agent, kernel/LSM, and runtime healthy?
6. Do runtime denial events match the enforcer, Profile, Pod UID, and time?
7. For NetworkProxy, also verify sidecar, init, Secret, certificates, and egress rules.
