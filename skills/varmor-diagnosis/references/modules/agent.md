# varmor-agent node data plane

## Responsibilities

`varmor-agent` runs as a DaemonSet across nodes, watches APs, prepares/loads Profiles locally, reports results to the manager's status service, and participates in violation auditing and behavior collection. The manager updates AP status from those reports. The agent is a primary evidence source for actual node enforcement capability.

## DaemonSet runtime design

The agent DaemonSet configuration directly determines node coverage and kernel visibility. Correlate nodeSelector/affinity, tolerations, hostPath/security mounts, ServiceAccount/RBAC, resource limits, update strategy, and target node status:

- DaemonSet desired/current/ready counts show scheduling coverage only; correlate each node with AP node conditions and Profile load results.
- Untolerated system-node taints, insufficient resources, or unsatisfied affinity can leave one node unprotected while the cluster appears healthy.
- Missing hostPath, permissions, or kernel-interface mounts may leave an agent Pod Ready but unable to load Profiles: functional failure despite readiness.
- During agent updates, distinguish Profiles still enforced for old Pods from initialization gaps on new nodes. Completed DaemonSet rollout alone does not prove all APs recovered.

## Health assessment

Correlate node coverage, Ready/restarts/lastState, AP load counts and node conditions, and logs according to the symptom. Inspect kernel, LSM, BTF, and runtime capabilities when compatibility or loading errors warrant it; a full health check is not required every time.

Running does not mean functional health. Treat "Pod Ready but AP not Ready on that node" as a functional-health discrepancy.

## Typical failures

### Node not covered

Common causes include taint/toleration, nodeSelector, affinity, insufficient resources, or an unconverged DaemonSet update. The impact is node-local, although that node's target Pod may be the only visible failure.

### Startup failure or repeated restarts

Use evidence to distinguish RBAC/watch permissions, image/configuration, hostPath/security mounts, kernel/LSM self-checks, and resource shortages. Do not attribute a CrashLoop directly to Profile rules.

### Profile load failure

- AppArmor: syntax, LSM, securityfs, constraints on the agent itself, loader, or Profile conflicts;
- Seccomp: file writing/path, kubelet/runtime visibility, and Profile content;
- BPF: kernel/architecture/BTF/BPF LSM, map/program resources, and load/attach;
- NetworkProxy: the manager propagates proxy Secrets/configuration; node-side checks focus on mounts, runtime, and AP status.

For inaccessible AppArmor interfaces, loader permission errors, or agent security settings inconsistent with the template, use
[AppArmor load failure](../troubleshooting/agent-apparmor-load-failure.md) to distinguish deployment, admission, later updates, runtime, and
kernel-interface failures. The agent's own `Unconfined` setting is runtime configuration; assess it separately from application containers explicitly bypassing protection.

### Node-level failures

If a node becomes NotReady, reboots, or has a kernel panic affecting multiple Pods, investigate the node before application container crashes. If BPF Profile loading correlates with kernel errors, establish scope and evidence before recommending node isolation, kernel upgrades, or another enforcer.

## Diagnostic evidence

Key correlation fields are node name, AP name, Profile name, policy name, agent Pod, container ID, time window, and AP node conditions. A Profile on the node proves resource presence only, not that a Pod uses it; verify Pod SecurityContext/annotations and runtime events.

## Recommendations only

Check coverage, permissions, resources, configuration, and node compatibility before Profile content. For agent restarts, workload recreation, enforcer changes, weaker rules, or kernel upgrades, explain impact, rollback, and verification points; do not execute them.
