# Runtime violation logs and evidence boundaries

## Sources and versions

Official agent AppArmor/BPF/Seccomp events usually go to host `/var/log/varmor/violations.log`,
visible through the existing agent's hostPath. Confirm the container path through paired volumes/volumeMounts. The official implementation uses
lumberjack rotation (10 MB per file, 3 backups), commonly named `violations-<timestamp>.log`.
Compressed files or older naming may also exist; actual version and log configuration take precedence. Agent stdout primarily reports component errors;
do not assume it contains complete violation events. APM is for BehaviorModeling, not ordinary audit storage.

NetworkProxy's unified agent-log ALS path is available from v0.10.3; runc deployments usually use node logs.
micro-VM deployments on v0.10.4+ may use a sink inside the proxy sidecar to write container logs. Verify sources for
older versions and custom deployments. Read-only diagnosis can analyze existing excerpts, but rotation, Pod recreation, or version differences may lose events. Absence of
events does not rule out an enforcer. Diagnosis does not require optimization's all-node collection or removal-eligibility gates.

## Correlation fields

Common envelope fields include `eventTimestamp` (event time, epoch seconds), `time` (collection time),
`nodeName`, `profileName`, `enforcer`, `action`, `podUID/podName/podNamespace`,
`containerID/containerName`, `pid/mntNsID`, and enforcer-specific `event`.
v0.10.3+ may include `policyKind/policyName/policyNamespace`; older versions may have only profileName.
Do not invent missing fields. Explain correlation strength from available identity, node, Profile, time, and operation details.

| action | Interpretation |
|---|---|
| DENIED | Denied and logged |
| AUDIT | Allowed and logged in observation (AppArmor/BPF) |
| AUDIT\|ALLOWED | Seccomp observation combined value |
| ALLOWED | Allowed |

Interpret AppArmor operation as file, capability, mount, ptrace, network, etc.; do not always treat `name`
as a file path. Interpret BPF operations with their event fields. Seccomp may report syscall
without arguments. NetworkProxy dstAddress is the original destination; SNI/authority/path visibility depends on layer
and TLS configuration. See enforcer/built-in-rule references for full semantics.

## Strength of conclusions

Linking a proven denial to application failure still requires correlation in time, runtime identity, and the specific operation. Short-lived processes may
lack Pod/container fields; strengthen the link using containerID, node, process/namespace details, and object mappings at that time.
Prefer UID over reused Pod names. A Profile protecting multiple Pods cannot identify one Pod by Profile match alone.

No matching record means only that the inspected excerpt contained no match. State query time, file/rotation scope, identity filters, invalid lines, and uncovered areas;
do not conclude "no denials". Aggregation/path normalization helps searches, but verify necessary original events when determining application causes.
