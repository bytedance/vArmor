# varmor-manager control plane

## Responsibilities

`varmor-manager` reconciles VP/VCP, validates policies, and generates APs; serves mutating/validating webhooks; receives and aggregates behavior data for BehaviorModeling; propagates NetworkProxy configuration/Secrets; and uses leader election to select the active processor.

## Deployment runtime design

The manager usually runs as a Deployment. Replicas, leader election, Service, WebhookConfiguration, RBAC, certificate/configuration mounts, readiness/liveness, and resource limits jointly determine actual control-plane availability:

- Multiple replicas improve availability, but usually only the Leader reconciles at a given time. A Running non-Leader is not evidence that it processes policies.
- Services and endpoints carry admission calls. Deployment Ready, Service existence, and webhook reachability are distinct observations.
- Readiness may reflect only the process or basic dependencies, not VP/VCP status, AP generation, or injection. Liveness failures can destabilize election and interrupt reconciliation.
- RBAC determines whether the manager can watch/update VP, VCP, AP, and webhook objects. Certificate/configuration mounts determine whether webhook and NetworkProxy functions can start.
- Resource limits affect modeling, APM aggregation, and large-scale reconciliation. After OOM, also check for stalled policy status or transient webhook outages.

Connect Deployment, Leader Lease, Service/endpoints, WebhookConfiguration, and policy/AP status. Do not substitute one manager Pod's Running or Ready state for the complete control-plane evidence chain.

## Health signals

- Manager Pod Ready, restarts, lastState, and resources;
- A unique Leader and continuous lease renewal;
- VP/VCP conditions, phase, and profileName changing with events;
- AP creation/updates and status reporting node results;
- Webhook Service/endpoints, certificates, and actual failurePolicy;
- During modeling, manager receipt of node data and successful APM persistence.

"Pod Running" or "a Leader exists" establishes process/election health only, not working reconciliation or webhook workflows.

## Typical failures

### CrashLoopBackOff / startup failure

Distinguish CRD schema/version, RBAC, configuration/enforcer capability, image/resources, and Kubernetes API compatibility first. Separate startup failure from rejection of a specific policy.

### No Leader or frequent transitions

Common causes include missing/unwritable leases, RBAC, API server instability, or manager failures. Reconciliation then lacks a stable processor; whether matching requests are blocked depends on the actual webhook `failurePolicy`.

### Running but policies are not delivered

For persistently unchanged VP/VCP or missing/stale APs, distinguish API server throttling/unreachability, queue backlog, policy validation failure, target-chain issues, and controller logic errors. A healthy manager does not justify skipping webhooks, policy status, or APs.

### OOM or insufficient resources

Cross-node modeling aggregation, APM generation, and local storage can significantly change resource requirements. Assess limits, data volume, and storage type together.

### Webhook without endpoints

If the manager Service has no Ready endpoint, the API server cannot reliably call it. Actual impact depends on failurePolicy, matching rules, and request type; `Ignore` can allow requests without injection.

## Diagnostic evidence

Prefer the chain `policy event/status -> manager reconciliation evidence -> AP status -> webhook/Pod injection`. Leader, RBAC, API server, and certificates are foundational dependencies. Do not interpret every manager warning as an application failure.

## Recommendations only

Follow "restore observability and control-plane stability -> verify one policy chain -> verify node enforcement". For RBAC, certificate, webhook, resource-limit changes, or manager restart, provide impact, prerequisites, rollback, and verification points only; do not execute.
