# Agent AppArmor Profile load failure diagnosis guide

## Entry signals

Use this guide when AP node conditions or agent logs identify Profile saving, parsing, loading, or replacement failures after an AppArmor policy create/update.
An agent Pod being Running/Ready does not rule out these failures. Passing startup self-checks does not prove later kernel-management-interface access.
Start with the failed node and AP and reuse existing evidence; do not require a scan of every node. For queries, see
[node inspection](../../playbooks/node.md); for operational boundaries, see the [shared conventions](../../playbooks/README.md).

## 1. Identify the failing stage

Correlate AP/Profile name, failed node, agent Pod/container identity, and log time. Retain original loader output and exit status.
Choose branches from the logs; do not interpret every `exit status 1` as insufficient permission:

| Example signal | Verify first |
|---|---|
| `SaveAppArmorProfile()` failure | Distinguish content checks, file creation/writes, `/proc/partitions` reads, and template parsing/rendering from the underlying error. For file errors, inspect path, directory mount, read-only status, space, and permissions. |
| Parser syntax/include/ABI/unsupported-rule error | Actual generated content, related files, and parser/kernel capabilities; distinguish missing files from syntax errors. |
| `LoadAppArmorProfile()` / `UpdateAppArmorProfile()` failure | Full parser output to distinguish interface access, permission, compatibility, and Profile conflicts. |
| `interface file missing`, `unable to find a suitable fs`, `--subdomainfs` | AppArmor enablement, agent interface mount view, and access constraints. |
| `Permission denied` / `Operation not permitted` | Actual runtime identity, administrative capabilities, security constraints, mounts, and related kernel denials. |

`Cache read/write disabled: interface file missing. (Kernel needs AppArmor 2.4 compatibility patch.)`
and `Warning: unable to find a suitable fs in /proc/mounts, is it mounted?` are clues to interface discovery/access failure.
They do not alone prove an unmounted host interface, a missing kernel patch, or modification by a particular webhook.
Separate cache warnings from final load failure. Do not recommend kernel upgrades or `--subdomainfs` merely from the warning text.

After creating a file, `SaveAppArmorProfile()` reads `/proc/partitions` to prepare disk-device template data,
then parses and renders the Profile template. Any step can fail; file existence does not prove this save completed,
nor that the host directory or kernel interface is ready.

## 2. Compare deployment intent with the actual Pod

For interface/permission failures, inspect **the agent itself**, not only protected application Pods: security settings and mounts.
Compare relevant fields in the installed version's rendered manifest, actual DaemonSet template, and corresponding agent Pod as needed.
First verify owner, creation time, image, and template revision to exclude normal differences between old Pods and a new template during rollout.

Focus on container/Pod `securityContext`, compatibility annotations, capabilities, runtime user, and hostPath/volumeMount pairs
for kernel interfaces, including read-only status. Root identity, administrative capabilities, interface visibility, and AppArmor confinement are
separate requirements. Neither `runAsUser: 0` nor a declared capability guarantees successful loading.

Current Chart defaults help distinguish file-save, self-check, and kernel-load failures:

| Path inside agent | Default host source | Purpose |
|---|---|---|
| `/etc/apparmor.d` | `/var/run/varmor/apparmor.d` | Stores Profiles, ABI, and includes; the agent's `AppArmorProfileDir` points here. |
| `/sys/module/apparmor` | Same host path | `isAppArmorEnabled()` reads `parameters/enabled` here. |
| `/sys/kernel/security` | Same host path | Exposes AppArmor and other kernel security interfaces; saving a file does not prove interface access. |

The first two default volume/mount pairs are controlled by Chart `appArmorLsmEnforcer.enabled`;
`/sys/kernel/security` is mounted separately in the template. Paths may be overridden; verify pairs in actual rendered manifests.
Without the mount, writes may land in the container filesystem. Successful writes alone do not establish host-directory preparation.

The current vArmor Chart exempts the agent from AppArmor confinement, using different expressions by target Kubernetes version:

| Chart rendering branch | Expected expression |
|---|---|
| Kubernetes < 1.30 | Pod annotation `container.apparmor.security.beta.kubernetes.io/agent: unconfined`; the current template hardcodes the `agent` suffix. |
| Kubernetes >= 1.30 | Agent container `securityContext.appArmorProfile.type: Unconfined`. |

Use the installed Chart version and settings. This version boundary describes API-expression migration, not an inevitable failure on newer clusters.
The structured field was introduced in Kubernetes 1.30 and became stable in 1.31. A Chart expression change does not mean old annotations stopped working.
For example, the [1.32 Pod creation implementation](https://github.com/kubernetes/kubernetes/blob/v1.32.0/pkg/registry/core/pod/strategy.go)
still converts annotations and fields for compatibility. Verify later versions against corresponding documentation/source; do not conflate deprecation, feature-gate removal,
and removal of annotation compatibility.
Annotation suffixes must match actual container names. The current Chart's legacy annotation branch does not automatically follow `agent.name`;
inspect rendered output when customizing it, and do not mistake a name mismatch for admission deleting settings.
Container-level fields take precedence over Pod-level fields. When a container field is absent, also inspect
Pod-level settings and that version's legacy-annotation handling. If both forms exist, verify consistency.

The agent's `Unconfined` setting prevents its own AppArmor confinement; it is not evidence that application containers bypass protection.
Removing explicit settings may fall back to inheritance or runtime defaults. One missing field alone does not establish actual confinement.
For custom deployments with other security settings, verify administrative capability and actual restrictions; do not automatically require privileged mode.

## 3. Verify actual execution requirements by evidence gap

Start with API configuration, AP conditions, and bounded logs. If insufficient and authorization covers it, perform targeted read-only checks from
[node inspection 2.1](../../playbooks/node.md#21-configuration-and-runtime-constraints-for-apparmor-load-failures).
Choose only branches needed to close a gap; not every check is required:

| Requirement to distinguish | Interpretation boundary |
|---|---|
| Kernel/LSM and parser capability | Sufficient kernel version does not prove LSM enablement; unreadable interfaces do not prove it is disabled. |
| Actual mounts and interface access | Declared configuration does not prove visibility; distinguish missing, read-only, and access-denied interfaces. |
| Actual agent/parser AppArmor confinement | Inspect the correct process; absent fields or failed attribute reads do not mean `unconfined`. |
| Actual administrative capability and related kernel denials | Declared `MAC_ADMIN` does not prove it was retained or the operation allowed; no audit record alone does not exclude a restriction. |

If a process is confined by a default/custom profile, assess its impact using interface visibility, denial records, and the failed operation.
If it is actually `unconfined`, continue with mounts, capabilities, rule content, and compatibility rather than insisting on configuration loss.

## 4. Trace origin only after proving a configuration discrepancy

After confirming agent security settings differ from deployment intent, investigate where the first difference appears:

| First discrepancy | Objects and requests to inspect |
|---|---|
| Missing in rendered output | Installation settings, Chart version, Kubernetes version used for rendering, and deployment-tool processing. |
| Rendered output correct, live DaemonSet template differs | DaemonSet CREATE/UPDATE/PATCH initiators, admission components matching DaemonSets, and later configuration management. |
| Corresponding template correct, actual Pod differs | Pod creation processing, later UPDATE/PATCH initiators, and admission components matching Pods. |
| Pod declaration correct, process state differs | Node kubelet, runtime version/logs, and actual process identity. |

Compare DaemonSet `.spec.template.spec.containers[].securityContext.appArmorProfile` by container name
with Pod `.spec.containers[].securityContext.appArmorProfile`. Check Pod-level fields and legacy annotations at
their correct template/object levels too. If the template already lost the field, subsequent Pods may simply inherit it; do not assume another deletion during Pod admission.
If the same revision's template retains the field but the Pod lacks it, deletion on the DaemonSet alone does not explain that difference.

Distinguish deployment rendering, request initiation, API server compatibility conversion, and admission mutation. Follow create/update records
to the earliest discrepancy. Current webhook matching shows potential participation, not proof of a historical change.
Direct UPDATE/PATCH and webhooks are not mutually exclusive: a controller, Operator, or operational tool may construct a request
that a matching webhook then changes. Identify DaemonSet versus Pod audit resources using objectRef/requestURI,
not informal descriptions. Webhook resources, operations, and selectors must match that request.
An audit ServiceAccount identifies the caller, not necessarily a specific program; correlate userAgent, source, and component logs.
Multiple processes may share one identity.

Older components' Kubernetes API types may not recognize fields such as `appArmorProfile`. Decoding into old types and
regenerating DaemonSet/Pod updates, or replacing an entire template, container list, or security context in an admission patch,
can lose new fields unintentionally. A common webhook pipeline is deserialize -> transform -> serialize -> compute patch.
It mutates via the patch in AdmissionResponse; returning a reserialized object alone does not overwrite the resource.
Verify the raw input and output used for diff computation and the patch's actual deletion/replacement scope.
Even when the original manifest uses only legacy annotations, compatible API server versions may populate structured fields during creation,
exposing fields an old updater does not recognize. Legacy annotations are string maps and often survive more easily; their
presence does not establish a complete update, and normal compatibility conversion is not evidence of deletion.

**Unknown fields are not necessarily deleted.** Components generating precise patches for required fields can preserve everything else.
Verify supported scope, API-library version, patch implementation, or actual audit records. An old component, existing webhooks, and
a missing field do not alone establish attribution. Distinguish validating admission rejecting creation from mutating admission changing settings.
Only new fields disappearing while known fields remain is consistent with old-type processing, but is not direct evidence against a particular component.

Registering a webhook does not retroactively modify existing Pods. Later matching requests or replacement Pod creation may still be affected.
Updating an existing Pod does not automatically recreate it. Whether DaemonSet template changes replace Pods depends on the actual update strategy
(usually RollingUpdate; OnDelete does not replace existing Pods automatically). Correlate revision, UID, and time to establish propagation.

### Distinguish omitted request fields from applied changes

When existing audit records are available, narrow them by object identity and failure time and obtain relevant evidence through
[node inspection](../../playbooks/node.md#21-configuration-and-runtime-constraints-for-apparmor-load-failures).
`requestObject` records client-submitted content before version conversion, defaulting, admission, and merging;
it is neither the final persisted object nor the object before the update.

| Observation | Supported interpretation and remaining checks |
|---|---|
| CREATE contains only a legacy annotation, response gains a structured field | May be normal compatibility conversion, not proof that a third party lost a field. |
| Previous object has a field, full UPDATE request omits it | Supports updater output omission; still verify response/final object before claiming deletion. |
| PATCH does not mention a field | Do not interpret it as a full object. Use patch type, actual deletion/replacement, and applicable semantics. |
| Request includes a field but response/final object differs | Investigate server conversion, admission, and later requests; do not directly blame the initiator. |
| Matching webhook and plausible loss mechanism, but no patch for that request | Keep an evidence-based hypothesis, state missing direct evidence, and do not report confirmed deletion origin. |
| Same-request webhook patch deletes the field or replaces its parent | Supports mutation attribution; still verify later admission and the final successful response to establish actual effect. |
| Request rejected or conflicted | Does not prove live configuration changed; investigate the existing object and other successful requests. |

Use `responseStatus`, available `responseObject`, and before/after snapshots to confirm outcomes. Distinguish same-name recreation by UID,
and correlate versions using time and resourceVersion. The current Pod alone cannot represent its state when a historical request completed.
Ordinary upstream Pod updates generally cannot change these security fields. For an apparent successful deletion, recheck resource/subresource,
cluster version/implementation, and whether the actual change was to a workload template followed by Pod recreation. Do not skip update validation in the causal account.
Successfully written settings do not prove an existing process's AppArmor confinement changed; correlate container lifecycle and actual process state.
State unconfirmed points when audit level or history is insufficient. Do not fill attribution gaps by guessing.

## 5. Conclusions and recommendations

Report the proven failure stage, configuration differences, actual runtime constraints, and mutation origin separately, and identify missing evidence.
Do not turn request-field omission into proven live deletion, or suspected configuration loss into confirmed deletion by an old component.
Establish configuration change, actual agent confinement, and its causal relationship to this load failure separately. Scope impact by node/enforcer: failed updates
do not imply existing kernel Profiles disappeared or every other enforcer failed.

Match recommendations to the cause: restore intended deployment/mount/capability settings, repair admission rules or field-loss implementations, and upgrade
incompatible components if needed. Follow the appropriate rule-syntax or parser/kernel compatibility branch. Scope security exceptions to the agent,
explain impact, rollback, and verification, and do not prescribe disabling all webhooks, globally disabling AppArmor, or enabling privileged mode as generic fixes.

Corrected settings may require agent Pod replacement to change process startup constraints. Provide recommendations only; do not recreate Pods or retry loading for the user.
Verify the new Pod's final configuration, the correct process's confinement, relevant AP node-load results, and logs.
Existing repair evidence can strengthen causality; do not actively create/change policies just to validate an assumption.

## References

- [Kubernetes AppArmor configuration and runtime state](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [Kubernetes 1.31 AppArmor stability announcement](https://kubernetes.io/blog/2024/08/13/kubernetes-v1-31-release/)
- [Minimal webhook mutation and version compatibility](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
- [Admission mutation auditing](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#monitoring-admission-webhooks)
- [Audit request/response field definitions](https://github.com/kubernetes/apiserver/blob/master/pkg/apis/audit/types.go)
- [Pod update and replacement restrictions](https://kubernetes.io/docs/concepts/workloads/pods/#pod-update-and-replacement)
- [DaemonSet template update strategies](https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/#daemonset-update-strategy)

For repository maintenance, compare `manifests/varmor/templates/daemonsets/agent.yaml`,
`internal/agent/agent.go`, and `pkg/lsm/apparmor/apparmor.go`. Distributed diagnostics must use deployed versions and evidence.
