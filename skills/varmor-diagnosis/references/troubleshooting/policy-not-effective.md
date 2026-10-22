# Ineffective policy diagnosis guide

## Entry signals

- VP/VCP `ready=false`, abnormal phase, or error conditions;
- AP absent, Pending, or `currentNumberLoaded < desiredNumberLoaded`;
- Policy/AP healthy but no vArmor injection in the Pod;
- Pod injected but not actually constrained, or audit events differ from expectations.

## Five-stage localization

1. **Matching**: target kind/name/selector, namespace, VCP priority, matching labels, container scope, and unconfined;
2. **Compilation**: mode, enforcer, mode-specific fields, rules, and NetworkProxy configuration;
3. **Injection**: Webhook rules, Service/endpoints/certificates, and final Pod SecurityContext/annotations;
4. **Loading**: AP node conditions, target node agent, Profile type, and node capability;
5. **Enforcement**: Profile/enforcer/action/Pod UID/time in events correlated with actual application behavior.

Between injection and loading, assess workload lifecycle: compare PodTemplate, actual Pod creation time, and ownerReferences to establish whether the Pod came from the newly injected template. This distinguishes old Pods surviving a policy update from actual webhook/agent failures.

## Typical scenarios

### Ready=False

Read condition reason/message first, then correlate manager and validating webhook. Do not change rules first.

### Ready=True but no AP or targets

Verify actual selector matches and whether Ready was mistaken for "application targets exist". A VCP may override a VP.

### AP not loaded on some nodes

Correlate each failed nodeName with agent, kernel/LSM/BTF, runtime, and Profile loading evidence.
For AppArmor failures, use the [specialized guide](agent-apparmor-load-failure.md) to identify the stage. Agent Ready
does not rule out load failures caused by its own security constraints, mounts, or admission configuration differences.

### AP complete but Pod uninjected

Check webhook configuration and matching labels, Pod/workload API versions, target kind, PodTemplate creation time, and explicit unconfined settings.

### Pod injected but behavior unconstrained

Verify the actual Pod Profile, node load status, enforcer-specific fields, and whether the Pod is an old instance. Seccomp updates particularly require workload recreation.

### NetworkProxy ineffective

Check proxy annotations, initContainer, sidecar readiness, Secret/certificates, redirection, ProxyUID/ports, rule layers, and HTTPS MITM in order. Do not interpret unmatched L7 path/method rules directly as an L4 networking failure.

## Compare enforcers with final configuration

Compare policy enforcers, AP content, actual Pod references, node loading, and runtime events individually. For VP/VCP overlap, use final AP ownership and actual Pod settings. With multiple enforcers, identify the earliest denial layer that explains the symptom. See `enforcer-conflicts.md` for cross-layer conflicts and NetworkProxy rule layers.

## Conclusion requirements

Choose explicitly among unmatched / not compiled / not injected / template injected but Pod not updated / not loaded / loaded but not triggered / triggered and allowed / triggered and denied / application issue / insufficient evidence. If only a broken stage is proven, do not claim the root cause is established.
