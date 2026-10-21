# Enforcer capabilities and failure interpretation

See `troubleshooting/enforcer-conflicts.md` for cross-enforcer matching, VP/VCP overlap, rule conflicts, and shared conclusion categories. EnhanceProtect built-in rule implementation scope is covered separately in `modules/built-in-rules-apparmor.md`, `modules/built-in-rules-bpf.md`, and `modules/built-in-rules-seccomp.md`; default mode Profiles are in `modules/policy-mode-profiles.md`. This reference focuses on capability boundaries and enforcement signals. Establish the enforcer actually used by the Pod before interpreting events.

## 1. Capability boundaries

| Enforcer | Main control layer | Typical targets | Key prerequisites | Common runtime signals |
|---|---|---|---|---|
| AppArmor | Linux LSM | Files, execution, capabilities, some network/mount/ptrace operations | AppArmor LSM, valid Profile syntax, and load capability | `EACCES`, `Permission denied`, AppArmor audit/DENIED |
| BPF | BPF LSM/related kernel hooks | Fine-grained file, process, capability, network, mount rules | Kernel BPF/BTF/BPF LSM, architecture, and resources | `EPERM`, BPF audit, load/attach/map errors |
| Seccomp | syscall filter | Syscalls and arguments | Kubernetes/runtime Seccomp support and Profile-file visibility | `SIGSYS`, `Bad system call`, `EPERM` |
| NetworkProxy | Envoy sidecar in the Pod | L4 TCP, SNI/domains, L7 HTTP/HTTPS, TLS MITM | Webhook injection, Secret/certificates, traffic redirection, sidecar Ready | Connection refusal, TLS errors, unmatched HTTP rules, proxy audit |

Enforcers can be combined, but ordering and interactions matter. BPF kernel network rules may act before NetworkProxy, which handles only traffic redirected to the sidecar. NetworkProxy does not replace CNI NetworkPolicy.

## 2. Profile preparation chain

- AppArmor: the agent loads the Profile into the node kernel. Newer Kubernetes versions may reference it through SecurityContext `appArmorProfile`; older versions may use compatibility annotations.
- BPF: the agent loads Profile/programs and attaches hooks. Pods usually expose a vArmor BPF Profile-reference annotation.
- Seccomp: the agent places JSON Profiles where kubelet/runtime can read them, and Pods reference them through `seccompProfile`. Running containers do not reload automatically after file updates.
- NetworkProxy: the webhook injects Profile references, initContainer, Envoy sidecar, configuration/certificate volumes, and required CA environment. The initContainer redirects traffic; the sidecar enforces policy.

Always compare policy intent, actual Pod references, actual node Profiles, and runtime disposition.

## 3. Modes and auditing

For EnhanceProtect built-in rules, `allowViolations` and `auditViolations` are independent switches:

- `false/false`: usually block without logs;
- `false/true`: block and log `DENIED` (AppArmor/BPF);
- `true/true`: allow and log `AUDIT`;
- `true/false`: allow without logs.

Seccomp has special limitations: observation usually requires both fields true, and events typically appear as `AUDIT|ALLOWED`. Do not apply AppArmor/BPF `DENIED` semantics directly.

AppArmor DefenseInDepth allowlist violations are blocked and logged as `DENIED`; allowing those violations logs `ALLOWED`. Seccomp observation events use `AUDIT|ALLOWED`; blocking through `ERRNO` does not imply a vArmor `DENIED` record. NetworkProxy custom rules are governed by qualifiers and `defaultAction`, not `allowViolations`.

Audit events usually contain `enforcer`, `action`, `profileName`, time, and `event`. Prefer Pod UID, node, Profile, namespace/name, and time window for correlation. Short-lived processes may lack complete container identity; NetworkProxy usually has Pod-level identity only.

## 4. AppArmor

Check: AppArmor LSM enabled on the node; Profile presence and syntax; agent load errors; reference format for the Kubernetes version; explicit Pod `Unconfined`; and consistent Profile names across policy status/AP.

Common causes: invalid Profile/custom rules, disabled node LSM, unavailable securityfs/related mounts, incompatible loader, Profile conflicts, or Pod references to an old Profile.

## 5. Seccomp

Check final container `seccompProfile` type and localhostProfile, file placement within kubelet's actual read scope, runtime support, SIGSYS exits, and whether the workload was recreated after policy changes.

`EPERM` is not exclusive to Seccomp; correlate syscall, audit event, and Profile. `SIGSYS/Bad system call` is more suggestive, but still rule out other syscall sandboxes.

## 6. BPF

Check kernel version/architecture, BPF LSM, BTF, BPF filesystem, map/program resources, agent load/attach results, per-node container count, and rule scale.

Repeated node NotReady, kernel BUG/Oops/Call Trace, and timing aligned with BPF Profile loading should prioritize node kernel/driver risk over application CrashLoop diagnosis alone. BPF support and known kernel issues vary by version; historical fixed thresholds are clues, not cross-version conclusions.

## 7. NetworkProxy

Investigate by layer:

1. **Injection**: proxy annotations, initContainer, sidecar, and volumes;
2. **Startup**: init completion, sidecar readiness, configuration Secret/certificates;
3. **Forwarding**: redirection to the proxy and ProxyUID/port conflicts;
4. **Rules**: L4 IP/CIDR/ports, SNI/host, L7 path/method, and `defaultAction`;
5. **HTTPS**: without TLS MITM, destination IP/port and TLS SNI may be visible; encrypted HTTP Host/:authority, path, and method are not;
6. **Bypass**: whether NET_ADMIN, ProxyUID, proxyAdminPort, Pod-CIDR admin-port access, or other network isolation permits bypass.

Do not assume deny has cross-layer priority over allow. Determine final action from qualifiers, precedence, matching layers, and `defaultAction` supported by the actual version. NetworkProxy events originate in the sidecar and usually cannot identify a specific application container alone.

## 8. Recommendations only

Establish the actual enforcer and final Pod configuration before choosing rule changes, node-capability repair, or application compatibility work. Explain security impact and verification conditions for observation mode, AlwaysAllow, workload recreation, enforcer changes, or kernel upgrades; do not execute.
