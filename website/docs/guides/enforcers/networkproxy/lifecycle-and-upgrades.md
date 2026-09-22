---
sidebar_position: 5
---

# Lifecycle and upgrades

Rule changes can take effect in an existing proxy. Changes to container images, resources or TLS mounts require updated workload specifications and replacement Pods. Use the table below to plan an update.

## Change matrix

| Change | Action |
| --- | --- |
| HTTP/L4 rules | Update the policy, wait for the proxy to load it, then verify new requests |
| Source Secret value for a header | Update the Secret, then make a valid policy spec update; see [credential rotation](tls-and-credentials.md#rotate-and-verify) |
| Add/remove MITM domains in a Pod already configured for MITM | Wait for proxy configuration and certificate updates, then verify HTTPS requests |
| Enable MITM for the first time | Recreate affected Pods with the TLS mounts and application CA configuration |
| Replace a CA or its trust bundle | Reload or restart applications that cache the CA bundle, then verify TLS connections |
| Change proxy image or resource settings | Update the workload template and roll out replacement Pods |
| Change proxy UID or listening ports | Create a replacement policy: these fields cannot be changed on an existing policy |

Dynamic configuration updates take time to reach each Pod. During an update, new requests may briefly fail while the proxy loads the required configuration. Existing connections are not necessarily closed when rules change. If you need to end existing sessions, include connection draining or Pod replacement in your rollout plan.

## Upgrade vArmor and its proxy together

Use the Manager, Agent and proxy images supplied for the same release. Follow the release notes for upgrade requirements.

When an upgrade changes audit-log compatibility, use this order to keep audit collection working:

1. Upgrade the node Agents.
2. For micro-VM workloads, update the proxy image in the workload templates and roll out replacement Pods, since audit collection runs inside those Pods.
3. Upgrade the Manager, then check affected policy status, proxy readiness and audit logs.

Changing an installation's default proxy image does not update containers already running. Include affected workload templates and Pods in the upgrade. For changes to proxy startup configuration, recreate the affected Pods after their configuration has been updated.

After upgrading, verify an allowed request, a denied request and their expected audit events. HTTP methods are case-sensitive; use `GET` for a standard GET request.

## Remove a policy deliberately

`updateExistingWorkloads` controls updates to controller-managed workloads when policies are created or deleted. Review [Usage Instructions](../../../getting_started/usage_instructions.md) and the [API](../../../getting_started/interface_specification.md) before removing protection.

Inspect the resulting workload template and replacement Pods to confirm that proxy containers and mounts have been removed. Recreate standalone Pods as needed, then verify connectivity. For the isolated Quick Start, delete the dedicated namespace as shown in the tutorial.
