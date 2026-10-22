# Runtime Audit Event Queries (Audit)

Follow the [shared conventions](README.md) for execution and authorization. Correlate application errors with vArmor runtime actions,
selecting sources for the actual enforcer. For log locations, versions, and field limitations, see the
[violation log reference](../references/modules/violation-log.md).

## 1. Scope the investigation from application symptoms

First obtain the target container state/lastState, exit code, signal, restarts, and timestamps; read bounded application logs if needed.
Reuse these facts when already available instead of querying again.

```bash
kubectl --context <context> -n <namespace> get pod <pod-name> -o jsonpath='{range .status.containerStatuses[*]}CONTAINER={.name}{"\n"}STATE={.state}{"\n"}LAST_STATE={.lastState}{"\n"}RESTARTS={.restartCount}{"\n"}{end}'
kubectl --context <context> -n <namespace> logs <pod-name> -c <container-name> --since-time=<RFC3339-start> --tail=200 --timestamps
# Add --previous when investigating restarts; a missing previous instance does not imply a permission or connection failure.
```

Choose a window around the error. When kubectl logs cannot filter by end time, check records through the window end locally.
Keywords can narrow candidates, but inspect necessary context. Error lines may contain credentials; redact before displaying.
`EPERM/EACCES` may originate from vArmor, DAC, SELinux, the runtime, or the application itself; `SIGSYS/Bad system call`
may also originate from another Seccomp sandbox. Correlate exitCode=137 with OOMKilled/events; do not assume OOM.

## 2. Locate event sources

Use the Pod nodeName to find the node agent, confirming candidates through the DaemonSet owner, container, and Pod lifecycle.
Logs from unhealthy or old agents remain useful evidence; Running+Ready is not a prerequisite for queries. Confirm the running container before exec.

- **Component runtime errors**: Read bounded stdout logs from the target node agent for audit collection, identity correlation, profile loading,
  or log-writing errors. An absence of events does not establish that no violations occurred.
- **Unified violation files**: Prefer a restricted local copy with a known source; otherwise confirm the agent log path from actual mounts.
  Start with a bounded tail of the relevant active file. Check rotated backups in the same directory only for earlier windows. Under high traffic or for older failures,
  an empty tail match cannot rule out events. Choose a bounded local copy based on the window and file size; do not export logs from all nodes by default.
- **NetworkProxy**: Determine whether the source is agent ALS, a sidecar sink, or a deployment log channel based on the version and runtime. Existing
  sidecar access logs can assist correlation, but do not assume they include every rule action.
- **Kernel audit/log aggregation**: When an appropriate channel already exists, collect evidence by time, node, and Profile. Do not create
  debug Pods or enumerate all CRDs for this purpose. Use APM only for behavior-modeling issues.

```bash
kubectl --context <context> -n <varmor-namespace> logs <agent-pod> -c <agent-container> --since-time=<RFC3339-start> --tail=300
# Run only when the path and access authorization are confirmed and the file is relevant; bound exec duration through the execution tool.
# Bound the number of remote lines. For sensitive logs, redirect stdout to a restricted local file and display only necessary parsed summaries.
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- tail -n 500 <confirmed-violations-file>
```

Record missing files, unreadable files, rotation overwrites, and transfer failures separately. If directory discovery is needed, list only shallow
metadata in the confirmed log directory; do not recursively scan host `/var/log`. Retain event time, identity, operation, and action in necessary raw excerpts. Do not default
to the optimization skill's all-node collection, manifest, or preprocessing pipeline.

## 3. Filter and correlate locally

Prefer structured parsing of JSON lines: filter the failure interval by `eventTimestamp`, then cross-match profileName, actual enforcer,
and runtime identity. Use policy identity as an additional check when present. Prefer Pod UID/containerID to Pod name alone.
When fields are missing, retain correlatable candidates and unknowns. Record malformed data as a parse failure rather than zero matches.
Keywords are useful for an initial search, but `AUDIT/DENIED/ALLOWED` are actions. Do not combine them with the target identity using OR
and treat the results as target events. Reuse existing local parsing tools or let the model parse small excerpts; no fixed script is required.

Distinguish three types of conclusions:

1. **Observed action**: A Profile/enforcer denied or allowed an operation; state only facts directly supported by the event.
2. **Association with the target**: Establish ownership using Pod UID/containerID, or mappings across node, time, process/namespace, and object.
   Incomplete identities for short-lived processes may be supplemented, but retain ambiguities such as shared Profiles or recreated objects.
3. **Explanation of application failure**: Actual blocking, time, runtime identity, and the denied operation align with the application error, and alternative explanations have
   been investigated as appropriate. State confidence. Do not require a fixed set of six fields for every event or discard established facts because some fields are missing.

`AUDIT/ALLOWED/AUDIT|ALLOWED` does not prove blocking; an allowed event also cannot rule out a denial by another enforcer.
Interpret Seccomp or proxy actions using the actual action and version semantics, rather than requiring the literal string DENIED.

## 4. When no matching events are found

Check audit settings and enforcer semantics, agent collection, actual files and versions, the failure window, rotation/container recreation,
missing identities, and filter scope. Interpret EnhanceProtect allowViolations/auditViolations combinations per enforcer;
absence of logs cannot rule out an unlogged block. Then consider runtime-default Seccomp, SELinux, DAC, network isolation, or
application errors. Do not trigger new application activity solely to manufacture evidence.

## Optional summary points

Include the application error and time, actual log sources and read scope, matching events with enforcer/action/Profile/identity/operation,
supported conclusions and confidence, missing evidence, and the smallest next probe. Rule attribution requires the actual rules in the current policy;
do not identify a built-in rule solely from the operation name.
