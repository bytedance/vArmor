# Workload/Pod Injection and Lifecycle Validation (Workload)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Verify that target Pods received vArmor injection. Distinguish a non-injected PodTemplate, an injected template with old Pods, an injected Pod whose Profile is not loaded, and injection overwritten by another mechanism. This is central to investigating ready policies without protection.

## When to use
- Policy/AP Ready but target Pods show no hardening
- Pod Pending/ContainerCreating with Profile errors
- Some Pods are protected and others are not
- Container crashes or permission errors of uncertain relation to vArmor

## Prerequisites
- Known target namespace and Workload type/name (kind must match the actual resource: deploy/statefulset/daemonset), or Pod name
- Known policy profileName (from [policy.md](policy.md))
- Known policy enforcer

---

## 1. Workload lifecycle validation

Existing Pods do not automatically receive new injection after a policy update. Distinguish PodTemplate state from actual Pod state.

### 1.1 PodTemplate injection checks

Read relevant SecurityContext, annotation, or container fields directly; use the optional script below for grouped extraction.
Analyze existing object JSON locally rather than querying again solely to call the script.

```bash
# Run from the Skill root; kind must be deployment/statefulset/daemonset.
# The script extracts only PodTemplate annotation keys, SecurityContext, containers, images, and volume references.
# For initContainers, it also reports AppArmor/Seccomp, privileged, and capability add/drop facts.
python3 scripts/inspect-injection.py \
  --namespace <namespace> \
  --kind <deployment|statefulset|daemonset> \
  --name <workload-name>
```

`INTERPRETATION status=NOT_EVALUATED` is expected: these are injection-related facts, not a script verdict on successful vArmor injection. Interpret them using the policy enforcer, profileName, actual Pods, and confirmed vArmor component names.

### 1.2 Actual Pod list and creation times

```bash
# Discover candidate Pods for the target Workload, then confirm ownership through ownerReferences
kubectl -n <namespace> get pods -l <workload-label-selector> -o wide --sort-by=.metadata.creationTimestamp

# Only Deployment manages Pods through ReplicaSets; use this to identify the template version of a Pod
kubectl -n <namespace> get rs -l <workload-label-selector> -o custom-columns='NAME:.metadata.name,DESIRED:.spec.replicas,CURRENT:.status.replicas,READY:.status.readyReplicas,AGE:.metadata.creationTimestamp'

# Extract creation time, the unique controller owner, and injection-related facts for the Pod under verification.
python3 scripts/inspect-injection.py \
  --namespace <namespace> \
  --kind pod \
  --name <pod-name>
```

Use label selectors to discover candidates and ownerReferences/controller relationships to confirm ownership; identical labels do not establish that every Pod belongs to the Workload.

**Lifecycle interpretation:**
1. An injected PodTemplate should result in injected newly created Pods.
2. If the template is injected but an actual Pod is not, compare Pod creation time with policy activation/template update time.
3. A Deployment Pod from an old ReplicaSet, or a StatefulSet/DaemonSet Pod predating the current template, may still use old configuration.
4. For a standalone Pod (no ownerReferences), policy updates or Webhook recovery do not automatically modify the existing Pod.

### 1.3 Compare PodTemplate and actual Pod injection

Compare equivalent template and Pod fields. When using the script, refer to `ANNOTATION_KEY`, `POD_APPARMOR`, `POD_SECCOMP`, `CONTAINER_SECURITY`, `INIT_CONTAINER`, `INIT_CONTAINER_SECURITY`, `CONTAINER`, and `VOLUME`:

- `UNSET` means the standard SecurityContext field is absent; it does not establish that the corresponding enforcer was not injected.
- Capabilities such as `NET_ADMIN` in `INIT_CONTAINER_SECURITY` are corroborating injection evidence, not proof that the initContainer belongs to vArmor.
- Annotations expose keys only. After confirming a vArmor key, read that specific value only if a Profile reference needs verification.
- `VOLUME source_type=hostPath source_name="REDACTED"` establishes only hostPath presence without exposing the node path.
- Containers, images, and volumes are corroborating evidence; generic terms such as `proxy` or `bpf` alone do not establish vArmor injection.

---

## 2. Pod injection evidence checklist

For each policy enforcer, inspect corresponding injection in actual Pods. Discover annotation candidates by key first, then read necessary nonsensitive values such as Profile references or switches; avoid unrelated or sensitive configuration.

### 2.1 AppArmor injection evidence

```bash
# Legacy annotation (standard Kubernetes API key; query its presence directly)
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}' | grep -i 'apparmor.security.beta.kubernetes.io'

# Newer SecurityContext (Pod and Container levels)
kubectl -n <namespace> get pod <pod-name> -o jsonpath='POD_APPARMOR={.spec.securityContext.appArmorProfile.type}{"/"}{.spec.securityContext.appArmorProfile.localhostProfile}{"\n"}'
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}CTR_APPARMOR[{.name}]={.securityContext.appArmorProfile.type}{"/"}{.securityContext.appArmorProfile.localhostProfile}{"\n"}{end}'
```

**Expected injected values:**
- Annotation: `container.apparmor.security.beta.kubernetes.io/<container-name>: localhost/<profile-name>`
- SecurityContext: `type: Localhost`, `localhostProfile: <profile-name>`

Use the complete AP/Profile name (normally already beginning with `varmor-`); do not prepend `varmor-` a second time.

### 2.2 Seccomp injection evidence

```bash
# Pod level
kubectl -n <namespace> get pod <pod-name> -o jsonpath='POD_SECCOMP={.spec.securityContext.seccompProfile.type}{"/"}{.spec.securityContext.seccompProfile.localhostProfile}{"\n"}'
# Container level
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}CTR_SECCOMP[{.name}]={.securityContext.seccompProfile.type}{"/"}{.securityContext.seccompProfile.localhostProfile}{"\n"}{end}'
```

**Expected injected values:** For modes using a local Profile, the current injector sets `type: Localhost`, `localhostProfile: <profile-name>`, and the agent writes that exact filename under its configured Seccomp directory. Do not assume a `varmor/` subdirectory or `.json` extension. In `RuntimeDefault`, the injector uses `type: RuntimeDefault` instead. Verify the deployed version and actual mount/path mapping.

### 2.3 BPF injection evidence

```bash
# BPF injection is marked with vArmor-specific annotations; keys vary by version/deployment.
# List all annotation keys first, then query selectively using AP profileName and deployment-known keys;
# generic terms such as bpf/sandbox can discover candidates but do not establish ownership.
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}'

# After confirming the exact BPF annotation key from AP or known deployment configuration, query only that value:
# kubectl -n <namespace> get pod <pod-name> -o jsonpath='{.metadata.annotations.<confirmed-bpf-key>}'

# If loading evidence points to LSM, select targeted checks from node.md; do not repeat node-capability checks merely to validate injection
```

### 2.4 Explicit Unconfined checks

```bash
# Check for explicit unconfined Pod annotations (list keys first, then filter)
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}' | grep -i unconfined
# Check labels for unconfined markers
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.labels}}{{$k}}{{"="}}{{$v}}{{"\n"}}{{end}}' | grep -i unconfined
```

**Unconfined semantics:** Unconfined annotations or the AppArmor `unconfined` value bypass policy; use annotation keys for the actual deployed version.

### 2.5 NetworkProxy injection evidence

See [networkproxy.md](networkproxy.md) for details; key checks follow.

```bash
# List relevant initContainers/containers/volumes for one Pod, optionally discovering candidates through keywords.
# The "proxy" keyword also matches other Service Mesh sidecars such as Istio (istio-proxy) and Linkerd (linkerd-proxy).
# Establish vArmor NetworkProxy injection using multiple corroborating signals:
#   1) Do initContainer/sidecar images come from the registry used by the vArmor deployment?
#   2) Do annotation keys contain vArmor-specific domains/prefixes (compare AP profileName and known deployment configuration)?
#   3) Do volume/secret names match Secrets/ConfigMaps from the vArmor deployment?
#   4) Is injection expected based on the actual policy enforcer and NetworkProxy configuration?
#   5) Use networkproxy.md for detailed distinctions.

# List every initContainer (name + image)
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.initContainers[*]}{.name}{"\t"}{.image}{"\n"}{end}'
# List every container (name + image)
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}{.name}{"\t"}{.image}{"\n"}{end}'
# List all annotation keys to identify vArmor-specific annotations
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}'
# List every volume (name + secretName)
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.volumes[*]}{.name}{"\t"}{.secret.secretName}{"\t"}{.configMap.name}{"\n"}{end}'
```

---

## 3. Pod events and status

```bash
# Inspect Pod events
kubectl -n <namespace> describe pod <pod-name> | grep -A30 "Events:"

# Pod and container status
kubectl -n <namespace> get pod <pod-name> -o jsonpath='PHASE={.status.phase}{"\t"}NODENAME={.spec.nodeName}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}READY={.ready}{"\t"}RESTARTS={.restartCount}{"\t"}LAST_STATE={.lastState}{"\n"}{end}'

# Reasons for Pod Pending/ContainerCreating
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

**Common vArmor-related reasons for Pending Pods:**
- `Profile not found` / `AppArmor profile not loaded` -> Profile not installed on the node; open [node.md](node.md)
- `Seccomp profile not found` -> node Seccomp file path not visible
- NetworkProxy init/sidecar startup failure -> certificate/Secret/resource issue; open [networkproxy.md](networkproxy.md)
- Scheduling failure -> general Kubernetes scheduling issue; first rule out causes unrelated to vArmor

---

## 4. Injection-state decision matrix

| PodTemplate | Actual Pod | Conclusion | Next step |
|---|---|---|---|
| Not injected | Not injected | Webhook did not inject: policy mismatch or Webhook failure | -> [webhook.md](webhook.md) / target validation in [policy.md](policy.md) |
| Injected | Not injected; Pod predates policy | Old Pod not updated; rollout required | Suggest Pod recreation after confirmation (authorization required) |
| Injected | Not injected; Pod created after policy | Injection overwritten or Webhook not called | -> [webhook.md](webhook.md) |
| Injected | Injected but missing Profile reference values | Incomplete injection; check Webhook version | -> [webhook.md](webhook.md) |
| Injected | Injected with correct Profile values | Injection succeeded; investigate node loading or runtime | -> [node.md](node.md) / [audit.md](audit.md) |
| Not injected (unconfined) | Any | Explicit policy bypass | Inspect unconfined settings |

---

## Optional summary points
A Workload summary may include:
1. PodTemplate injection state (present/absent/partial), with the actual workload kind
2. Target Pods, creation times, and ownerReferences; include ReplicaSet ownership for Deployment
3. Actual injection evidence per target Pod (AppArmor/Seccomp/BPF/NetworkProxy)
4. Any unconfined bypass
5. Pod events and container status (Pending/Crash/Running)
6. A clear conclusion from the matrix above
7. Next direction
