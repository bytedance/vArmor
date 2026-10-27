# VP/VCP Lifecycle and Kubernetes Activation Boundaries

## 1. Object responsibilities

| Object | Scope | Target range |
|---|---|---|
| `VarmorPolicy` (VP) | namespace | Workloads in the same namespace only |
| `VarmorClusterPolicy` (VCP) | cluster | Can select targets across namespaces |

Object chain:

```text
VP / VCP --manager reconcile--> ArmorProfile --node agent load--> underlying Profile
--admission injection--> Pod runtime configuration
```

VP/VCP is the user declaration; ArmorProfile is the internal execution object. They have different responsibilities.

## 2. target semantics

- `kind`: `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`.
- `name` and `selector` identify the Workload and are **mutually exclusive** (exactly one is required).
- `selector` follows Kubernetes LabelSelector semantics (matchLabels / matchExpressions).
- `containers` specifies application containers; an empty list typically means all application containers, excluding init/ephemeral containers.
- `unconfined` settings on a Workload/Pod may bypass the corresponding Profile.
- VP is restricted to its namespace; VCP can span namespaces. Both may select the same target; use the manager's actual
  reconciliation result, generated ArmorProfile, and actual Pod security configuration as the final evidence.

**Mutability**: `spec.target` is immutable after creation; rules within `spec.policy.enhanceProtect` may be modified repeatedly.
This skill changes only rules inside enhanceProtect, never target.

## 3. ArmorProfile status

- `desiredNumberLoaded`: Number of agents expected to process the Profile.
- `currentNumberLoaded`: Number of agents reporting successful Profile processing.
- `conditions`: Node-level loading results, reasons, and messages.
- VP/VCP `status.profileName` links the policy to ArmorProfile.
- VP/VCP `status.ready=true` indicates the relevant control-plane/node processing conditions are met; AP has no `status.ready` field. **Policy readiness does not mean** every existing Pod references the new Profile.

## 4. Activation boundaries (critical)

- Admission Webhooks usually inject security configuration **when a Pod is created**.
- After policy/ArmorProfile updates, **running containers do not repeat admission or automatically reload Seccomp**.
- Deployment / StatefulSet / DaemonSet must create new Pods to receive a new PodSpec; standalone Pods must be
  recreated.
- With `spec.updateExistingWorkloads=true`, vArmor rolls out Deploy/STS/DS on policy creation/deletion,
  provided manager enables `restartExistWorkloads`. If the switch is false or target is Pod,
  updates are not automatic and the user must recreate them. Updating EnhanceProtect rules alone does not guarantee a rollout;
  this switch alone cannot justify starting the next Seccomp observation window.
- Agents can update AppArmor/BPF Profiles. Editing a Profile file cannot replace an already loaded Seccomp filter;
  confirm the necessary new containers have started before recording the new observation start.

Verification basis: upstream `v0.10.5`
[policy_controller.go](https://github.com/bytedance/vArmor/blob/v0.10.5/internal/policy/policy_controller.go)
and [clusterpolicy_controller.go](https://github.com/bytedance/vArmor/blob/v0.10.5/internal/policy/clusterpolicy_controller.go)
invoke workload updates on add/delete paths, while ordinary rule-update paths update ArmorProfile.
Both controller files are unchanged in the `v0.10.6` release candidate revision recorded in the catalog; the links above retain the original verification basis.

After successful submission or update, explain that control-plane object updates do not establish activation of new Profiles in existing Pods;
Seccomp and injection changes usually require new Pods.

## 5. Change safety

VP/VCP CRDs are the only objects this skill modifies. Before any submission/update, including resulting workload restarts,
retain complete local YAML and provide its path and hash, display a redacted summary and structured diff, pass server
dry-run, and obtain explicit user confirmation of the target cluster and change. Fail closed: do not modify or submit on
submission failure, missing policy, observation-period policy drift, incomplete logs, uncertain attribution, schema failure, a diff containing changes beyond deletion,
or missing user confirmation.
