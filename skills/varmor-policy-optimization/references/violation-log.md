# Violation Log: violations.log

## 1. Location and rotation

- AppArmor, BPF, and Seccomp node logs reside on the host at
  **`/var/log/varmor/violations.log`**. The official agent mounts host `/var/log` through hostPath at
  the same container path, so reads through the agent access the same underlying file; there is no container-layer write followed by host synchronization.
- Copy the host file directly if an authorized read-only node transfer channel already exists; otherwise use
  `kubectl cp/exec` through the agent hostPath view. Do not create privileged debug Pods or broaden node permissions.
- Rotation uses 10MB per file with 3 backups (lumberjack). Default backup names are
  `violations-<timestamp>.log`; collection also supports `.log.gz` and legacy `violations.log.*`.
- New tasks use the [incremental collector](incremental-collection.md) to read appended bytes periodically during observation, preserving data before rotation
  and generating preprocessed results automatically at expiry. Legacy snapshot fallback exports active files and backups once before analysis. Neither path sends
  complete logs into model context.

### Conditional NetworkProxy checks

**Run this section only if the current policy enforcer includes NetworkProxy; otherwise skip it:**

1. NetworkProxy is available from `v0.10.0`; the ALS path writing to the unified agent `violations.log` is available from `v0.10.3`.
   Do not automatically optimize NetworkProxy from this log when the version is older than `v0.10.3` or unknown.
2. `v0.10.3+` with runc: events go to the host log above; use ordinary agent collection.
3. Micro-VM: from `v0.10.4+`, the built-in sink in the `varmor-network-proxy` sidecar writes container-layer logs; older versions
   lack this collection path. The current workflow lacks complete evidence across Pod/container lifecycles, so only read-only analysis is allowed;
   do not delete NetworkProxy rules.

## 2. Envelope (outer fields)

Each log entry may include:

```text
level            Log level
time             Collection time
eventTimestamp   Event time (epoch seconds; authoritative for window filtering)
nodeName         Node name
podUID / podName / podNamespace   Pod identity
containerID / containerName / image   Container identity
pid / mntNsID    Process / mount namespace
enforcer         AppArmor | BPF | Seccomp | NetworkProxy
action           Final action (see below)
profileName      Profile that produced the event
policyKind / policyName / policyNamespace   Owning policy identity
event            Enforcer-specific event object
```

### Policy identity

Typical `v0.10.1/v0.10.2` envelopes contain only `profileName`; `v0.10.3+` adds
`policyKind/policyName/policyNamespace`. Always filter by an exact match to the current policy `status.profileName`,
then validate policy identity when present. `collect_violations.py --explain` counts
`profileMismatch`, `policyIdentityMismatch`, and `missingIdentity` separately to avoid mistaking zero matches for no violations.

## 3. action vocabulary

| action | Meaning |
|---|---|
| `DENIED` | Blocked and logged |
| `AUDIT` | Allowed and logged during observation (AppArmor/BPF) |
| `AUDIT\|ALLOWED` | Combined Seccomp observation value |
| `ALLOWED` | Allowed (for example, DefenseInDepth allowViolations) |

## 4. event: enforcer-specific structures

### AppArmor (broad structure; operation identifies the domain)

Key fields: `operation`, `profile`, `name`/`name2` (paths), `deniedMask`/`requestedMask`,
`fsuid`/`ouid`, `comm`, `capability` (`name` when `operation=capable`), plus mount
 (`srcName`/`fsType`/`flags`), ptrace (`peer`/`peerProfile`), network
(`netFamily`/`netSockType`/`netProtocol`/`netForeignAddr`/`netForeignPort`), dbus, signal, etc.

Interpretation:

- `name` is a path in file events and a capability only when `operation=capable`; do not infer one from the other.
- Directory aggregation preserves combinations of `accesses`/`requestedMasks`/`deniedMasks`.

### BPF (typed; six logical event classes)

`operation` identifies the event type: `Capability`, `File`, `Bprm`, `Network`, `Ptrace`, or `Mount`.

- Capability: `capability`; File: `path` + `permissions`; Bprm: `path` (execution).
- Network: `type=socket` (`socket.domain/type/protocol`) or `type=connect`
   (`address.ip/port`);Ptrace: `external` + `permission`;Mount: `path`/`type`/`flags`.

### Seccomp

Only `syscall` is retained, alongside audit fields such as auditID/epoch/subj/pid/comm/exe. Events contain no syscall arguments.
Raw Seccomp logs do not enter model context; deterministic scripts process them.

### NetworkProxy (from Envoy ALS)

Fields: `layer` (L4/L7), `dstAddress`, `sni`, `authority`, `method`, `path`, plus
`filterChain`/`responseCode`/`reason`/`durationMs`, which aggregation removes.

- `dstAddress` is the actual destination `IP:port` recovered through Original Destination, not a fixed proxy listening address.
- L4 represents TCP connections; L7 represents HTTP requests. HTTPS path/method are invisible without TLS MITM.
- `sni` and `authority` are independent (the latter is HTTP Host); differences can identify domain fronting.

## 5. Preprocessing conventions

- Remove fluctuating fields that do not affect rule decisions, such as timestamps/PIDs/audit sequence numbers/durations; retain enforcer, operation, path, permissions,
  network destination, syscall, and capability.
- Count invalid logs: any invalid logs make the analysis ineligible for automatic deletion; never silently skip them.
- Normalize dynamic paths deterministically (`:pid`/`:pod-uid`/`:sa-rev`/`:snapshot`/`:range`). These placeholders are aggregation markers,
  **not AppArmor/BPF wildcards; never write them back into policy rules**.

## 6. Data handling

- Store raw logs and derived artifacts in a dedicated run directory. Explicitly restrict directories to `0700` and files to `0600` after each batch is written, rather than relying
  on `umask` persisting across shells.
- Logs may contain sensitive metadata such as application paths, processes, images, network IPs/ports, and HTTP authority/path;
  cite only the minimum fields needed to support conclusions and redact application identifiers.
- Do not additionally read Secret contents or specific Annotation values; reports must not expose physical HostPath paths or full resource JSON.
- After review and rollback needs are complete, clean up raw logs according to user/organization policy; do not proactively delete them without confirmation.
