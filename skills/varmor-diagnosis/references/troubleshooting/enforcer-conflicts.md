# Enforcer matching and rule conflicts

## Diagnostic objective

Do not stop at policy Ready. Establish what was declared, matched, generated, loaded on the node, used by the Pod, and ultimately responsible for disposition. Prioritize the earliest provable break; later abnormalities may be consequences.

## Six-layer matching chain

1. **Policy declaration**: Confirm mode, enforcer, rules, target, and container scope; inspect target Workload/Pod bypass settings such as `unconfined` separately.
2. **Target matching**: Confirm actual matches from VP/VCP namespace, kind, name/selector, and labels, plus policy precedence.
3. **Compilation**: Confirm rules/enforcer capabilities become a valid AP. Unsupported kernels, mode-specific fields, or invalid rules can fail here.
4. **Admission injection**: Confirm webhook matching and required annotations, SecurityContext, sidecar, or references in final Pod/PodTemplate.
5. **Node loading**: Confirm the target node agent loaded the Profile and meets LSM, BPF, runtime, certificate, and resource prerequisites.
6. **Runtime enforcement**: Correlate actual behavior with Profile, enforcer, Pod UID, node, time, and action to identify allow, audit, or deny.

Health at a later layer cannot substitute for an unproven earlier layer. AP existence does not prove Pod injection; Pod injection does not prove node loading.

## VP/VCP overlap and final ownership

VP and VCP may both match a workload. Do not infer priority solely from creation time or object name. Verify:

- Overlap in targets, namespace scope, and selectors. The current injector checks VCPs before VPs; within the same policy kind, multiple matches have no guaranteed stable selection order;
- The policy selected by the injector and its corresponding AP/profileName; do not assume rules from matching policies are merged;
- Final Profile, enforcer, mode, and container scope in PodTemplate and actual Pod;
- Whether policy generation, AP version, and Pod creation time belong to the same activation chain.

When declaration shows multiple candidate policies but AP/Pod shows one final result, diagnose from final AP ownership and actual Pod configuration. Contradictory observation points warrant "rule conflict" or "insufficient evidence", not an immediate ineffective-policy conclusion.

## Combining enforcers

Multiple enforcers may affect one application action at different control layers:

- AppArmor and BPF may both constrain files, execution, capabilities, mounts, or networking;
- Seccomp constrains syscalls; application file/network errors may be symptoms of a denied underlying syscall;
- NetworkProxy handles only redirected sidecar traffic and may combine with CNI NetworkPolicy, DNS, kernel network rules, and application validation.

`EACCES`, `EPERM`, and `Permission denied` cannot identify an enforcer alone. `SIGSYS`/`Bad system call` suggests Seccomp more strongly but still needs Profile, Pod, node, and time evidence. Find the earliest, most specific denial explaining the symptom, then assess other layers. Multiple Profiles alone do not attribute every failure to vArmor.

## Allow, Audit, and Deny semantics

For AppArmor/BPF EnhanceProtect built-in rules and the implicit baseline, `allowViolations` and `auditViolations` independently control disposition and logging:

- Disallow without audit: may block without a corresponding audit record;
- Disallow with audit: block and log a denial;
- Allow with audit: allow and log an allowed/audit event;
- Allow without audit: allow without a corresponding audit event.

Seccomp observation/events cannot simply reuse AppArmor/BPF `DENIED` interpretation; use syscall, signal, action, and Profile semantics. NetworkProxy custom rules depend primarily on qualifiers, precedence, and `defaultAction`, not `allowViolations`.

## NetworkProxy rule layers

Use this order to avoid mistaking an unmatched rule for a proxy failure:

1. **Injection**: Pod proxy annotations, initContainer, sidecar, configuration/certificate volumes, and required environment.
2. **Startup**: init completion, sidecar readiness, and valid Secret, certificates, configuration, and ports.
3. **Forwarding**: Actual redirection of target traffic; bypass/misrouting from ports, ProxyUID, admin port, or loopback.
4. **Protocol and matching**: Distinguish L4 IP/CIDR/ports before SNI/domains and L7 HTTP host/path/method. Rules at different layers do not replace each other.
5. **Precedence and default action**: Verify qualifiers, rule precedence, allow/deny relationships, and `defaultAction`; do not infer behavior from textual rule order alone.
6. **HTTPS visibility**: Without TLS MITM, connection metadata and TLS SNI may be visible, but encrypted HTTP Host/:authority, path, and method are not.
7. **Bypass and external layers**: Inspect permitted bypass identities, admin ports, Pod CIDR, and additional CNI NetworkPolicy, DNS, service-mesh, or application-proxy effects.

Sidecar Ready establishes only proxy readiness, not that all traffic traverses it. In the current implementation, L4 and HTTP allow rules are alternative authorizations where both apply: a broad L4 allow can permit a request that misses an HTTP allow rule. Matching deny rules still take precedence. Check the deployed version before generalizing this behavior.

## Shared conclusion categories

Choose the category closest to the evidence:

- Unmatched
- Unsupported capability
- Not compiled
- Not injected
- Template injected but Pod not updated
- Not loaded
- Loaded but not triggered
- Triggered and allowed
- Triggered and denied
- Rule conflict
- Application issue
- Insufficient evidence
