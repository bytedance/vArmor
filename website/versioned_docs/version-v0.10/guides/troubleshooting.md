---
sidebar_position: 6
---

# Troubleshooting

:::tip Start with the varmor-diagnosis skill

Try [**varmor-diagnosis**](../skills/diagnosis.md) to investigate the cause of a policy or component failure. Give your AI assistant the symptom, affected workload or node, namespace and approximate failure time. The skill correlates configuration, status, events and logs through read-only investigation, distinguishing confirmed findings from possible causes and missing evidence.

For example: “Use varmor-diagnosis to investigate why the policy for Deployment checkout in namespace shop is not taking effect. The problem started after a policy update about ten minutes ago. Explain the evidence, likely cause and recovery recommendations.”

See the [installation and usage guide](../skills/diagnosis.md) to get started. You can also provide existing YAML, events and logs without connecting to a cluster. Use the checks below to supplement the investigation and verify recovery.

:::

Start with the affected workload, node and time window. Follow the chain from policy matching to generated ArmorProfile, actual Pod configuration, node loading and runtime behavior. A component being Ready, or a policy reporting success, does not by itself prove that the intended operations are protected.

## Find the failure stage {#find-the-failure-stage}

| Symptom | Check first | Next step |
| --- | --- | --- |
| Policy is not Ready, or ArmorProfile is missing | Policy conditions, target, mode, enforcer and Manager logs | Distinguish matching, validation and profile-generation failures |
| ArmorProfile is not loaded on some nodes | ArmorProfile node conditions, corresponding Agent and node capabilities | [Profile loading failures](#profile-loading-failures) |
| Policy is Ready but behavior is unexpected | Actual Pod references, creation time, policy mode and correlated audit events | [Policy matching and enforcement](#policy-matching-and-enforcement) |
| Pod is Pending or ContainerCreating | Scheduling, image, volume and runtime events before security-specific causes | [Workload startup and crashes](#workload-startup-and-crashes) |
| Container repeatedly crashes | Exit code/signal, previous logs, profile and denial evidence | [Workload startup and crashes](#workload-startup-and-crashes) |
| vArmor components are unhealthy | Pod conditions, restarts, last termination reason and events | [Component and API connectivity](#component-and-api-connectivity) |
| Failure persists after disk/network recovery | New Agent logs and current profile status | [Retry after correcting the cause](#retry-after-correcting-the-cause) |
| BPF update failed, but a retry now reports success | Application logs and actual enforcement, not only CR status | [BPF application failure](#bpf-application-failure) |
| NetworkProxy injection, forwarding or TLS fails | Init/sidecar state, configuration and actual requests | [NetworkProxy troubleshooting](enforcers/networkproxy/troubleshooting.md) |

## Collect a small, correlated evidence set {#collect-evidence}

Replace the example names below with the actual resources. `POLICY_NS` is the application policy namespace; `VARMOR_NS` is the installation namespace. For a VarmorClusterPolicy, use the cluster-scoped query instead of the VarmorPolicy query.

```bash
POLICY_NS=default
POLICY_NAME=example-policy
VARMOR_NS=varmor

kubectl -n "$POLICY_NS" get varmorpolicy "$POLICY_NAME" -o yaml
kubectl get varmorclusterpolicy "$POLICY_NAME" -o yaml
kubectl get armorprofiles -A
kubectl -n "$VARMOR_NS" get pods -o wide
```

Read the policy's `status.profileName`, then locate the matching ArmorProfile and verify its `ownerReferences`. A namespaced policy's ArmorProfile is in the policy namespace; a cluster policy's ArmorProfile is in the vArmor namespace. Do not guess the generated name or assume that every matching policy was selected.

```bash
AP_NS=default
AP_NAME=replace-with-status-profileName
AGENT_POD=replace-with-agent-on-affected-node
MANAGER_POD=replace-with-relevant-manager

kubectl -n "$AP_NS" get armorprofile "$AP_NAME" -o yaml
kubectl -n "$VARMOR_NS" describe pod "$AGENT_POD"
kubectl -n "$VARMOR_NS" logs "$AGENT_POD" --all-containers=true --since=30m --timestamps=true
kubectl -n "$VARMOR_NS" logs "$MANAGER_POD" --all-containers=true --since=30m --timestamps=true
```

Use `kubectl logs --previous -c <container>` when that container has restarted, and choose a time window covering the failure. For multiple Managers, identify the relevant leader and the instance that received the report; inspect additional instances when leadership or routing changed. Keep the profile name, node, Pod UID, container identity and timestamps together.

### What Status can and cannot establish {#status-limits}

- **Policy Status** summarizes generation and reported loading progress. Its message may direct you to ArmorProfile rather than contain the node-specific error.
- **ArmorProfile Status** records failed node conditions and reported loading counts. `currentNumberLoaded` counts reported successes; it is not a count of all responses or a live inspection of kernel state.
- **Agent logs** identify saving, parsing, loading, applying and reporting errors. **Manager logs** help distinguish receiving a report from persisting it to the API server.

Status is updated asynchronously. A successful report acknowledgement does not guarantee that either CR has already been updated. Reporting failures, Manager restarts or API errors can leave missing or stale status. A later success can replace an earlier error before you observe it. The reports do not carry a rule revision that proves an earlier success applies to the latest rules. Treat status as current reported state, not a durable failure history or proof of current enforcement.

Correlate both CRs with logs, then verify a permitted and a prohibited operation in a controlled workload. Absence of audit events does not prove absence of enforcement: logging depends on the enforcer and policy settings. See [Audit Logs](../getting_started/usage_instructions.md#audit-logs).

## Policy matching and enforcement {#policy-matching-and-enforcement}

Check the following stages in order; stop at the earliest discrepancy that explains the symptom:

1. **Matching:** namespace, target kind/name/selector, actual labels (including the `sandbox.varmor.org/enable="true"` opt-in label), container scope and explicit `unconfined` settings. Cluster policies are checked before namespaced policies; do not assume multiple matching policies are merged or selected by creation time.
2. **Generation:** selected mode/enforcer, supported rules, policy conditions and generated ArmorProfile content. A supported kernel version alone does not establish that the required LSM is enabled.
3. **Injection:** webhook availability and matching, final workload PodTemplate and actual Pod annotations/security context. For NetworkProxy, also inspect initContainer, sidecar and volume references.
4. **Lifecycle:** compare the Pod's owner, UID and creation time with the template update. Correcting a template or webhook does not modify existing containers automatically.
5. **Node loading:** correlate the actual Pod's profile reference with the Agent on its node and ArmorProfile conditions.
6. **Runtime behavior:** check that the tested operation is covered and whether the rule is intended to allow, audit or deny it. With multiple enforcers, identify the layer responsible for the result.

Seccomp file updates do not replace the filter already installed in a running container. After repairing its profile, affected application containers need recreation to use the updated filter; follow the workload's rollout procedure. Retrying ArmorProfile processing does not recreate application Pods. See [Usage Instructions](../getting_started/usage_instructions.md).

## Workload startup and crashes {#workload-startup-and-crashes}

Inspect `kubectl describe pod`, container `state`/`lastState`, events and previous logs before changing the policy. Rule out scheduling, image pulls, PVCs, resources, node health and CNI problems when there is no evidence tying the failure to vArmor.

| Signal | Investigation |
| --- | --- |
| AppArmor/Seccomp profile not found | Correct profile reference, corresponding node Agent, profile files and loading result; check for stale references after policy deletion |
| `Permission denied`, `EACCES`, `EPERM` | Correlate profile, Pod UID, operation and time with audit/kernel logs; capabilities, other security controls and application errors can produce similar symptoms |
| `SIGSYS` or `Bad system call` | Inspect Seccomp action and syscall evidence; the signal alone does not identify which policy installed the filter |
| Node NotReady, reboot, kernel BUG/Oops | Investigate node/kernel health and preserve kernel logs before attributing the failure to an application rule |
| NetworkProxy init/sidecar failure | Follow the [specialized guide](enforcers/networkproxy/troubleshooting.md) for redirection, certificates, resources and proxy readiness |

Do not disable all policies or switch to AlwaysAllow as a generic repair. If a controlled isolation test is necessary, scope the workload, duration and rollback, and account for the loss of protection.

## Profile loading failures {#profile-loading-failures}

### AppArmor save, parse and load failures {#apparmor-failures}

Distinguish the failed stage using the complete error, not only `exit status 1`:

| Error stage | Check |
| --- | --- |
| `SaveAppArmorProfile()` | Creation/write errors, filesystem space/inodes, read-only mounts and permissions; also `/proc/partitions` reads and template parsing/rendering |
| Parser syntax/include/ABI errors | Generated content, referenced includes/ABI files, parser and kernel compatibility |
| `LoadAppArmorProfile()` / `UpdateAppArmorProfile()` | Full parser output, kernel interface access, actual Agent confinement/capabilities and profile conflicts |

Warnings such as `interface file missing` or `unable to find a suitable fs` indicate interface discovery/access problems. They do not by themselves prove that the host failed to mount securityfs, that a kernel patch is missing, or that a webhook changed the Agent. Separate cache warnings from the final loading error.

Compare the installed Chart's rendered manifest, the live DaemonSet template and the corresponding Agent Pod. Match container names and rollout revisions before judging differences. Inspect the Agent's own security settings and mounts, not just those of the application:

- `/etc/apparmor.d` stores profiles and includes; the default host source is `/var/run/varmor/apparmor.d`.
- `/sys/module/apparmor` supports the enablement check; `/sys/kernel/security` exposes kernel security interfaces.
- A successful file write does not prove kernel interface access. Root identity, declared capabilities and actual process confinement are separate checks.
- Verify the installed Chart's intended `Unconfined` setting for the Agent, including structured AppArmor fields and any legacy annotation whose suffix must match the container name. This exemption concerns the Agent's management operations, not application protection.

If configuration differs, trace where it first changed: rendering, DaemonSet update, Pod creation or runtime execution. A missing field and the presence of an older controller/webhook are not proof of attribution. Use successful request/response evidence and the actual patch when available; an omitted PATCH field does not imply deletion. Restore only the settings implicated by the evidence. Do not prescribe privileged mode, global AppArmor disablement or removal of all webhooks as a generic fix.

### Disk full and empty AppArmor/Seccomp files {#disk-full}

Profile creation can succeed while a subsequent write fails with `no space left on device`. The file can remain empty or partially written; an existing file may already have been truncated. File existence is therefore insufficient evidence of a successful save. Check both free space and inodes on the filesystem actually backing the Agent's mount.

The default Agent paths are `/etc/apparmor.d` for AppArmor and `/var/lib/kubelet/seccomp` for Seccomp; verify actual volume mappings and configured paths before inspecting the host. Preserve the error, file size and relevant content before recovery. Do not manually empty or remove unrelated profile files.

When the save function returns an error, the Agent attempts to report `Failed`; persistence in either CR is subject to [Status limits](#status-limits). A zero-byte file alone does not prove an error was reported: process interruption or other failure paths can produce similar evidence.

Freeing space does not refill the file. Once storage and permissions are corrected, use [manual reconciliation](#retry-after-correcting-the-cause) to regenerate it, verify the resulting file and loading result, and follow the Seccomp container-recreation requirement where applicable.

### BPF application failure {#bpf-application-failure}

Use the complete `SaveAndApplyBpfProfile()` error to distinguish unsupported node capabilities, rule-capacity errors and BPF map-operation failures. Check the selected BPF variant and the node's actual rule count, including disk-device expansion; see [BPF limits](enforcers/bpf.md#limits-and-performance).

Correct the reported cause, then verify both permitted and prohibited operations in the affected containers. A successful retry report alone does not establish that kernel rules have recovered. Before retrying, check the [BPF version-specific limitation](#known-bpf-retry-issue) at the end of this page.

## Component and API connectivity {#component-and-api-connectivity}

Manager problems affect generation, reconciliation and admission; Agent problems affect node loading; classifier problems primarily affect BehaviorModeling. Check restarts, OOMKilled, image errors, resource limits, mounts, RBAC, CRD compatibility, certificates and endpoints according to the observed error. Running/Ready does not establish that every profile or modeling task is progressing.

For API timeouts during rollout, compare the error timestamps with the Pod UID, node and rollout changes. Enabling `hostNetwork` replaces Pods; an existing Pod does not switch network namespaces in place. Investigate the applicable node/Pod routing, Service routing and network components, but do not attribute a startup timeout to CNI without evidence.

A later `curl -k https://<kubernetes-service-ip>:443/` returning an anonymous-user `403` establishes that this later request reached an API server. It does not prove earlier connectivity, Agent credentials, CA verification, or successful access to the ArmorProfile API. First establish whether new timeout logs are still appearing.

If the Agent reports that Seccomp is unsupported, check the API version retrieval and capability-detection results in its startup logs, together with the actual node prerequisites. If connectivity has recovered but the capability result still conflicts with the environment, check the [startup version-detection issue](#known-seccomp-startup-issue) at the end of this page.

## Retry after correcting the cause {#retry-after-correcting-the-cause}

Use this procedure for a recoverable Agent-side profile-processing failure after resolving its cause, such as disk exhaustion or a repaired directory. It does not fix invalid policies, unsupported node capabilities or injection errors. Before using it for BPF, check the [version-specific retry limitation](#known-bpf-retry-issue); affected builds can report success without restoring rules.

### Why waiting may not recover the profile {#automatic-retry-limits}

The Agent's bounded workqueue retries depend on the processing function returning an error. If processing fails but reporting `Failed` succeeds, the work item can finish without a retry. Unchanged informer resync events are filtered out when both profile spec and reconciliation counter are unchanged.

The Manager's status cycle defaults to two hours. It continues refreshing status, but forces profile reconciliation only when no nodes have reported failure and the success count differs from the desired count. It is not a periodic retry of every failed profile: one reported failure can also prevent that mechanism from prompting other missing nodes for the same profile. Neither loop guarantees recovery after an acknowledged failure.

### Request another processing attempt {#manual-reconciliation}

1. Identify the ArmorProfile from the policy's `status.profileName` and confirm its namespace and ownership as described [above](#collect-evidence). Save the current status and relevant logs.
2. Read its counter and resource version:

   ```bash
   kubectl -n "$AP_NS" get armorprofile "$AP_NAME" \
     -o jsonpath='{.metadata.annotations.profile-reconcile-counter}{"\t"}{.metadata.resourceVersion}{"\n"}'
   ```

3. Increment the counter by one. An absent counter is treated as zero; set it to `1`. For an existing value of `7`, use `8` as below. Replace the example resource version with the value just read. Stop and investigate a malformed counter instead of treating it as zero.

   ```bash
   kubectl -n "$AP_NS" annotate armorprofile "$AP_NAME" \
     profile-reconcile-counter=8 --overwrite \
     --resource-version='<resource-version-from-the-read>'
   ```

   If the resource version conflicts, read the object again and recalculate the next value. This avoids overwriting a concurrent counter update. Modify the **ArmorProfile**, not the VarmorPolicy/VarmorClusterPolicy, and do not edit the generated profile spec as a recovery shortcut.

4. Watch new Agent logs, ArmorProfile node conditions and Policy Status. This update can enqueue the profile on **all Agents watching it**, not only the failed node; choose an appropriate operational window.
5. Verify the actual result: profile file content and loading for AppArmor, file content plus the required application-container recreation for Seccomp, and permitted/prohibited operations for the selected enforcer. Repeating the same counter value or applying an unchanged object does not request a new processing attempt.

Agent process restart or Pod recreation also gives a new informer initial Add events for existing ArmorProfiles. It can recover some failures after their causes have been corrected, but has a broader impact than requesting profile reconciliation. Restarting the Manager alone does not repair profile files on nodes. Preserve evidence before either action.

## Report a problem {#report-a-problem}

Include the vArmor image/tag and digest or revision, Chart version, Kubernetes/runtime/kernel versions, affected node and Pod identities, policy/enforcer/mode, sanitized policy and ArmorProfile spec/status, relevant events, and Agent/Manager logs for the same time window. Describe the change preceding the failure, the attempted recovery, and a controlled allowed/denied operation pair where applicable. State which observations are missing rather than inferring them from a healthy status.

Remove tokens, credentials, private keys and unrelated workload data. The [diagnosis reference guides](https://github.com/bytedance/vArmor/tree/main/skills/varmor-diagnosis/references/troubleshooting) provide deeper investigation paths; they follow main and may differ from the installed release. NetworkProxy-specific evidence and recovery are covered in its [troubleshooting guide](enforcers/networkproxy/troubleshooting.md).

## Known issues and version notes {#known-issues-and-version-notes}

The following issues depend on the installed version. Version information was checked on **2026-10-28**. Affected releases listed here are confirmed examples, not an exhaustive range; for custom builds, check whether the linked fix is included.

### Incorrect Seccomp capability detection after a startup API failure {#known-seccomp-startup-issue}

| Item | Details |
| --- | --- |
| Symptom | API version retrieval fails during Agent startup; the Agent later reports Seccomp as unsupported despite the environment meeting its prerequisites |
| Confirmed affected release | v0.10.6; the earliest affected release has not been established |
| Fix availability | Merged into main; a fixed release is pending |
| Tracking | [PR #424](https://github.com/bytedance/vArmor/pull/424) |

In affected builds, a failed initial API version request does not prevent capability initialization. Later API recovery or a periodic version refresh does not recalculate the Agent's Seccomp support flag. Incrementing the ArmorProfile reconciliation counter alone does not correct that flag.

**Recovery:** restore API connectivity and use a build containing the fix when available. If an upgrade is not yet possible, a controlled restart of the affected Agent after connectivity is restored gives it another opportunity to initialize correctly. Confirm successful version retrieval and capability detection in the new process, then verify profile processing and the workload. A restart does not resolve actual capability or connectivity deficiencies.

The fix waits for a valid API version before normal Agent initialization, retries with cancellation and keeps the Agent unready while waiting.

### BPF retry reports success without restoring rules {#known-bpf-retry-issue}

| Item | Details |
| --- | --- |
| Symptom | A BPF profile update fails for existing containers; reconciling identical content later reports success without restoring the requested rules |
| Confirmed affected release | v0.10.6; also confirmed in main at `15b2460`. The earliest affected release has not been established |
| Fix availability | Fix pending; no fixed release identified |
| Tracking | [Issue #426](https://github.com/bytedance/vArmor/issues/426) |

The changed profile enters the cache before kernel application completes. After a failure, identical content can hit the cache and skip application. Incrementing `profile-reconcile-counter` may therefore clear the failed node condition without restoring enforcement. A failed update can also remove previous rules on the failing container, while other containers retain old rules or have received the new ones.

Rule-capacity errors and BPF map-operation failures can trigger this path. For example, an unrolled-variant node supports 50 mount rules while control-plane validation permits up to 64; disk-device expansion can also exceed node capacity.

**Recovery:** preserve the original error and correct the underlying capacity/resource problem. Use a build containing the fix when available. Until then, restarting the affected Agent provides a recovery opportunity by rebuilding its in-memory state, but can interrupt node enforcement and does not guarantee recovery from persistent failures. Assess that impact before restarting, then verify loading and actual permitted/prohibited operations. Neither a successful annotation update nor Ready status proves that protection has recovered.
