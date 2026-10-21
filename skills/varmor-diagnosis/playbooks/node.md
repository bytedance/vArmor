# Node enforcer inspection (Node)

Follow the [shared conventions](README.md) for execution and authorization. Start from an AP failed node or target Pod nodeName,
and select checks for the actual enforcer; a full node health check is not required.

## Objective

Distinguish missing/unhealthy agents, unmet kernel capabilities, Profile preparation/load failure, and loaded Profiles not used by containers.
For node NotReady, OOM, BUG/Oops/panic, prioritize existing API/log evidence and avoid adding node load.

## 1. Node and agent API evidence

```bash
kubectl --context <context> get node <node-name> -o jsonpath='READY={.status.conditions[?(@.type=="Ready")].status}{"\n"}KERNEL={.status.nodeInfo.kernelVersion}{"\n"}RUNTIME={.status.nodeInfo.containerRuntimeVersion}{"\n"}ARCH={.status.nodeInfo.architecture}{"\n"}'
kubectl --context <context> -n <varmor-namespace> get pods -l <agent-selector> --field-selector spec.nodeName=<node-name> -o wide
```

Confirm identity with DaemonSet ownership, Pod UID, creation/deletion times, and target agent-container Ready/restart state.
Multiple Pods may be old/new rollout instances. Keep relevant candidates and explain their roles. Unready Pods still provide status, events,
and logs; diagnosis need not wait for one uniquely Running+Ready Pod. Confirm one Pod and container before exec.

Prefer relevant AP node conditions, agent lastState, events, and bounded logs. Establish AP namespace through VP/VCP relationships in
[policy.md section 2.1](policy.md#21-does-the-ap-exist-with-correct-status) or a cross-namespace name-filtered
summary, reusing prior results. CRD scope alone does not identify the namespace.

```bash
kubectl --context <context> -n <confirmed-ap-namespace> get armorprofiles.crd.varmor.org <profile-name> -o json
kubectl --context <context> -n <varmor-namespace> logs <agent-pod> -c <agent-container> --since=<duration> --tail=300
# For restart-related issues, use --previous; distinguish no previous instance from authorization/connection errors.
```

Do not pass namespace for a cluster-scoped AP. Filter one AP's local JSON conditions by target nodeName.
Failure reason/message guides loading investigation; it does not directly prove the root cause.

## 2. Verify enforcer capabilities on demand

Node API version/architecture and agent load errors usually determine the next step. For complex version prerequisites, optionally use:

```bash
python3 scripts/check-enforcer-compatibility.py --context <context> --node <node-name> --enforcer <apparmor|bpf|seccomp>
```

The script is optional. A sufficient kernel version does not prove LSM enablement. Close `TO_PROVE/PARTIALLY_VERIFIED` with independent
evidence below. Use the specialized playbook for NetworkProxy. Check BTF only when BehaviorModeling, version requirements, or load errors
point to it; unverified BTF alone does not establish ordinary BPF-enforcer incompatibility.

For a node view, use short, targeted reads through confirmed mounts in an existing agent. Before exec, verify current authorization
covers that container, path, and read action; read-only does not automatically mean authorized. Do not ask again when authorization already covers it.
Select only relevant examples, specify the container explicitly, and bound exec duration with the execution tool:

```bash
# LSM: read one exact kernel-state file.
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /sys/kernel/security/lsm
# AppArmor enablement.
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /sys/module/apparmor/parameters/enabled
# BTF: test readability of the known file; do not read its entire contents.
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- test -r /sys/kernel/btf/vmlinux
```

For inaccessible files, distinguish mount view, permissions, and missing capability; do not automatically conclude unsupported. If mount information is needed, read
`/proc/self/mountinfo` once, filter locally, and reuse it. It describes only the agent's mount view.
Establish Seccomp paths from agent settings, volumes/volumeMounts, and logs; do not search the entire kubelet tree by default.

### 2.1 Configuration and runtime constraints for AppArmor load failures

Use the [specialized guide](../references/troubleshooting/agent-apparmor-load-failure.md) to interpret logs and version differences.
Compare the confirmed agent Pod and its corresponding template; application Pod settings cannot substitute for agent settings:

```bash
kubectl --context <context> -n <varmor-namespace> get pod <agent-pod> -o jsonpath='{.spec.securityContext}{"\n"}{range .spec.containers[*]}{.name}{"\t"}{.securityContext}{"\n"}{end}'
kubectl --context <context> -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.securityContext}{"\n"}{range .spec.template.spec.containers[*]}{.name}{"\t"}{.securityContext}{"\n"}{end}'
```

Exclude old instances by Pod creation time and template revision. Read the legacy AppArmor annotation for the actual container name, avoiding
a full annotations dump. If container fields are absent, check Pod inheritance and version-specific annotation compatibility before concluding confinement.
If fields are also missing from the live DaemonSet template, compare rendered installation manifests and investigate DaemonSet requests. If the template has them but the Pod
does not, investigate the corresponding Pod request. Do not mix security-context paths from these object levels.

When already authorized, select either read below as needed, retaining read errors:

```bash
# AppArmor state of the exec command itself; if this kernel lacks the dedicated path, optionally use /proc/self/attr/current.
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /proc/self/attr/apparmor/current
# For the actual management process, confirm PID from existing runtime/process information before a targeted read.
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /proc/<confirmed-agent-pid>/attr/apparmor/current
```

With hostPID, `/proc/1` may be the host init process; do not use it as the agent's state. If exec and agent/parser processes
transition between profiles, inspect them separately. Failed attribute reads do not mean `unconfined`.

For interface issues, reuse confirmed mounts and one `/proc/self/mountinfo` read to verify visibility and read-only status.
For permission evidence, inspect actual capabilities through confirmed-process `/proc/<pid>/status` or existing information,
then correlate bounded kernel audit by time, process, profile, operation, and path. Declared administrative capabilities cannot replace actual state.
Do not test permissions by loading Profiles or writing kernel interfaces such as `.load` or `.replace`.
Trace configuration changes using the specialized guide across creation and later updates; do not presume a webhook caused them.

When tracing a writer, filter existing audit channels by namespace, object name/UID, and time; reuse records already provided.
Retain auditID, stage, verb, objectRef (including subresource), requestURI, caller/impersonated identity, userAgent,
source, responseStatus, and relevant request/response field differences. Include legacy annotations and container/Pod fields as needed.
Request level may include request bodies; RequestResponse may include response bodies. Mark missing content as not collected rather than assuming availability.
Show only necessary redacted fields, not full bodies. Interpret full UPDATE and PATCH according to their own semantics, verify request
success, and correlate same-UID before/after versions. A logged request is not proof of persistence.
For suspected admission mutation, correlate webhook invocation and available patches within the same auditID. Check field deletion or replacement of
a parent object; a generic "mutation occurred" annotation does not prove AppArmor settings changed. State the gap if no patch is available;
matching scope or an old dependency version alone is not conclusive attribution. See section 4 of the specialized guide.

## 3. Was the target Profile prepared?

Start with AP node conditions and the relevant agent logs; add these checks only if evidence remains insufficient.

- **AppArmor**: Read the kernel Profile list when needed, match the confirmed name exactly,
  and reuse one result. `aa-status` is an optional alternative; both are not required. Absence from the list is meaningful only after a successful read.
- **Seccomp**: After confirming mount point and filename, use `test -r <exact-profile-file>` or `stat`.
  Search only when the filename is unknown, bounding directory, depth, and time rather than using unrestricted recursive `find`. Existence proves resource presence,
  not container use; readability is also specific to the current agent identity.
- **BPF**: Identify objects through logs, AP, and known bpffs references. If bpftool is needed, query known IDs/objects first;
  enumerate programs/maps only when no locator exists and necessary, after assessing node cost and bounding duration. Keywords discover candidates;
  no matching name does not establish "no vArmor program".

After successful loading, still verify actual Pod Profile references and runtime identity; see `workload.md` and `audit.md`.
Seccomp changes require new containers; file presence or AP Ready does not prove an old container was updated.

## 4. Kernel failure branch

Correlate node events, agent errors, and existing kernel logs by failure time first. For journal/kernel logs, bound
time and volume and prefer existing node-log channels. Do not create privileged debug Pods or enter host namespaces.
BPF loading coinciding with BUG/Oops/Call Trace establishes timing only. Recommend treating it as a node risk;
do not validate through repeated Profile loading. Node isolation, enforcer changes, and kernel upgrades are recommendations only.

## Optional summary points

Summarize current node/agent identity, failed AP conditions, relevant capability evidence, Profile preparation versus actual use,
node risk, unconfirmed points, and the smallest next probe. Include only collected facts relevant to the issue.
