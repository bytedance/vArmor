---
sidebar_position: 6
---

# Observability

Verify configuration and behavior separately. Use the policy's status and conditions to diagnose configuration errors, then check the actual Pod, proxy and requests.

## Check policy enforcement {#evidence-to-collect}

| Check | What to inspect | Purpose |
| --- | --- | --- |
| Policy | Generation, phase, ready and error conditions | Confirm processing and locate configuration errors |
| Pod | Injected containers, mounts, readiness and restarts | Confirm the proxy is running |
| Proxy logs | Configuration load or rejection messages | Confirm the rule update was accepted |
| Requests and backend logs | Status codes, responses and backend access records | Verify allowed and denied traffic |
| Audit logs | Action, Pod, policy, request path and method | Identify traffic that triggered a rule |

After updating a policy, check proxy logs and request results. A proxy that rejects new configuration can continue using its previous configuration; resolve the loading error before proceeding.

## Audit decision matrix

For configured egress rules, HTTP requests and TCP/TLS connections are audited as follows:

| Default | Matching rules | Outcome | Selected audit event |
| --- | --- | --- | --- |
| allow | None | Allow | None |
| allow | deny, no matching audit rule | Deny | None |
| allow | deny + audit | Deny | DENIED |
| allow | audit | Allow | AUDIT |
| deny | None | Deny | DENIED |
| deny | allow | Allow | None |
| deny | allow + audit | Allow | AUDIT |
| deny | deny and allow + audit | Deny | DENIED |

An audit-only rule does not allow under default deny. Separate matching deny and audit rules also select a `DENIED` event. A request matching multiple audit conditions produces one event at the same logging location.

NetworkProxy reports `DENIED` or `AUDIT`, not `ALLOWED`. Audit events distinguish proxy denials from upstream responses; **an upstream HTTP 403 remains AUDIT** when selected for auditing. L4 denial may appear as a closed connection or TLS failure without an HTTP response.

In `DefenseInDepth`, leaving the network rules empty blocks traffic without the audit events described above. Configure explicit egress rules when you need auditing.

## Where logs appear

For ordinary container runtimes such as runc, read `/var/log/varmor/violations.log` on the workload's node. For a configured micro-VM runtime, read the same path inside the `varmor-network-proxy` sidecar. See [runtime detection](../../../getting_started/installation.md#micro-vm-kata-detection-for-networkproxy-auditing).

Events carry Pod/policy identity. Proxy events do not identify which application process or container originated a request in a shared Pod network namespace. HTTP records include request-level fields where visible; TCP and TLS passthrough records are connection-level. Correlate L4 evidence by Pod, destination and time window; a connection record can correspond to multiple requests.

Filter logs by the affected namespace and Pod. Redact credentials and sensitive URLs or headers before sharing logs or proxy configuration.

## Useful checks

```bash
kubectl get varmorpolicy -n YOUR_NAMESPACE YOUR_POLICY -o yaml
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o wide
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy-init
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy --since=10m
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o jsonpath='{range .status.containerStatuses[*]}{.name}{" "}{.imageID}{" restarts="}{.restartCount}{"\n"}{end}'
```

Use [Metrics](../../../getting_started/metrics.md) for component monitoring and [Troubleshooting](troubleshooting.md) for interpreting errors. Audit logging is selective; absence of an event must be compared with the matrix and the actual running configuration.
