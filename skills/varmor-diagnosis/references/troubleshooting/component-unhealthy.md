# Unhealthy vArmor component diagnosis guide

## Entry signals

Manager/agent/classifier Pods not Ready, repeated restarts, OOMKilled, ImagePullBackOff, functional failure despite readiness, or associated AP/webhook/modeling failures.

## Assess each component

- **Manager**: Leader, reconciliation, CRD/RBAC, webhooks, certificates, API server;
- **Agent**: Node coverage, AP processing, Profile loading, kernel/LSM/BTF/runtime;
- **Classifier**: Shared Deployment/Service for random-path classification during BehaviorModeling; node agents perform collection, preprocessing, and reporting;
- **NetworkProxy Pods/sidecars**: Injection, Secret, certificates, resources, ports, and readiness.

## Investigation layers

Manager failures primarily affect compilation, reconciliation, and webhooks; agent failures affect node Profile loading; NetworkProxy sidecar failures affect post-injection forwarding/enforcement; classifier failures primarily affect BehaviorModeling. Component Running/Ready cannot replace VP/VCP, AP, actual Pod configuration, and runtime-event evidence.

If the agent runs normally but AppArmor loading fails, especially with kernel-interface discovery/access errors, use
[AppArmor load failure](agent-apparmor-load-failure.md) to inspect the agent's own configuration and actual runtime conditions.

## Evidence order

Inspect Pod status, lastState, events, and resources before component logs. Correlate manager failures with Leader/webhooks, agent failures with node/AP conditions, and classifier failures with APM/reporting.

## Common causes

RBAC/configuration/CRD version mismatches, image/resources, node taints/resources/mounts, missing kernel capabilities, certificates/endpoints, API server throttling, or insufficient modeling storage. Running with stalled AP/modeling/proxy progress indicates a functional-health failure.

## Remediation direction

Restore control-plane availability and node coverage before policy content. Explain impact, scope, and rollback for any recommended restart, scaling, recreation, mode switch, or policy change.
