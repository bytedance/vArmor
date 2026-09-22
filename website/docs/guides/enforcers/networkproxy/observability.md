---
sidebar_position: 6
---

# Observability

Verify configuration and behavior separately. Use the policy's status and conditions to diagnose reconciliation, then check the actual Pod, proxy and requests.

## Evidence to collect

| Layer | Useful evidence | What it does not prove |
| --- | --- | --- |
| Controller | Policy generation, phase, ready and error conditions | Every proxy accepted that generation |
| Pod | Injected containers, mounts, actual image IDs, readiness and restarts | Intended rules are active |
| Proxy | Reload/rejection logs and non-sensitive configuration version/hash checks | Application trust or backend availability |
| Traffic | Client result plus an owned backend's receipt/non-receipt | Audit delivery |
| Audit | Expected action, Pod/policy identity, path/method where visible | Exactly-once delivery under faults |

A generated Secret can be current while Envoy retains an older valid configuration after a rejected update. A TCP readiness probe is not an acknowledgment of the policy version.

## Audit decision matrix

For ordinary configured egress rules, the following matrix applies to the relevant HTTP-request or TCP/TLS-connection logging location:

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

An audit-only rule does not allow under default deny. Separate matching deny and audit rules also select a `DENIED` event. Overlapping audit conditions do not intentionally produce multiple events at the same logging location. This is not an exactly-once guarantee for transport/storage.

NetworkProxy reports `DENIED` or `AUDIT`, not `ALLOWED`. It identifies proxy denials from Envoy RBAC reason fields; **an upstream HTTP 403 remains AUDIT** when selected for auditing. L4 denial may appear as a closed connection or TLS failure without an HTTP response.

The special `DefenseInDepth` fallback with no configured rules denies without the ordinary audit matrix. Do not use that fallback to test the default-deny audit row.

## Where logs appear

With node-central auditing (normally runc), Envoy sends ALS records to the node's vArmor Agent, which writes `/var/log/varmor/violations.log` on that node. For a configured micro-VM deployment, the embedded sink writes this path inside the sidecar filesystem instead. See [runtime detection](../../../getting_started/installation.md#micro-vm-kata-detection-for-networkproxy-auditing).

Events carry Pod/policy identity. Proxy events do not identify which application process or container originated a request in a shared Pod network namespace. HTTP records include request-level fields where visible; TCP and TLS passthrough records are connection-level. Correlate L4 evidence by Pod, destination and time window, not by an HTTP request ID absent from those records.

Limit log collection to the test namespace/Pod and redact sensitive URLs and headers. Never publish a full generated Secret or LDS dump to diagnose credential injection.

## Useful checks

```bash
kubectl get varmorpolicy -n YOUR_NAMESPACE YOUR_POLICY -o yaml
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o wide
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy-init
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy --since=10m
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o jsonpath='{range .status.containerStatuses[*]}{.name}{" "}{.imageID}{" restarts="}{.restartCount}{"\n"}{end}'
```

Use [Metrics](../../../getting_started/metrics.md) for component monitoring and [Troubleshooting](troubleshooting.md) for interpreting errors. Audit logging is selective; absence of an event must be compared with the matrix and the actual running configuration.
