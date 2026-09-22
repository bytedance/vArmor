---
sidebar_position: 7
---

# Troubleshooting

Use the symptom table to locate the problem. Check policy status, Pod events and proxy logs, then send an allowed and a denied request to verify the result.

## Symptom checklist

| Symptom | Check | Recovery |
| --- | --- | --- |
| No sidecar | Workload opt-in label, policy target kind/name/labels, namespace and cluster-policy precedence | Correct selection; inspect the controller and create a new test Pod |
| Init container repeatedly fails | Permission or iptables errors in init logs | Fix permissions or network configuration, then recreate the Pod; do not ignore iptables errors |
| Connection failure or proxy OOM | Pod events, proxy logs, backend availability and resource usage | Restore backend connectivity or adjust resources according to the reported error |
| HTTPS path restriction has no effect | TLS passthrough versus MITM, broad L4 allow | Configure interception/trust and remove unintended alternative authorization |
| MITM 404 | HTTP Host outside the applicable MITM destination scope, or an IPv6 spelling mismatch | Check MITM configuration and client requests against the [destination scope rules](policy-semantics.md#domain-fronting-boundary) |
| TLS verification fails | Application CA and upstream CA/identity separately; old cached trust | Correct the appropriate trust path, wait for certificate files to update, reload the relevant process |
| Allowed requests get 503 after an update | Proxy configuration loading, certificate updates and backend connectivity | Resolve proxy or upstream errors, wait for proxy readiness, then retry the request |
| Policy Ready but old behavior persists | Rejected proxy configuration, delayed configuration updates or startup settings | Correct the policy configuration, confirm the update, then verify requests |
| Header remains old after Secret change | Policy generation and processing status | Trigger a valid spec update as described in [TLS and Credentials](tls-and-credentials.md#rotate-and-verify) |
| Policy Error after credential update | Missing Secret/key, empty/unsafe value, generated configuration size | Fix the referenced Secret or configuration and update the policy; last valid namespace configuration remains active |
| No audit | Matrix expectation, node versus sidecar log location, Agent/proxy version compatibility | Check [Observability](observability.md) and [upgrade guidance](lifecycle-and-upgrades.md#upgrade-varmor-and-its-proxy-together) |

## Confirm process identity, not only the Pod specification

The sidecar starts as root and its entrypoint drops the Envoy process to the policy's UID. `kubectl exec ... id` describes a new helper process and may not describe the running Envoy. Inspect the UID fields in `/proc/<envoy-pid>/status`. Locate the Envoy process before reading its status file.

## Recovery boundaries

- Envoy can retain the previous configuration after rejecting an update; check proxy logs to confirm that the new rules loaded.
- A failed read of an existing MITM Secret can currently lead to new CA generation. If the CA changed unexpectedly, investigate Manager/API errors, verify the new bundle and reload applications that cached the old CA.
- If initialization fails after creating some redirection rules, correct the permission or network-backend error and recreate the Pod to start with a clean network namespace.
- A cluster policy's configuration publication to a new namespace can fail when referenced Secrets are absent. Fix those dependencies and trigger a valid policy spec update.
- Generated Secret data warns above 700 KiB and is rejected above 900 KiB. Large combinations of hosts, ports, paths and methods expand the configuration. Reduce the rule/domain/mutation set rather than bypassing size checks.

## When reporting a problem

Include the vArmor revision, runtime and Kubernetes version, proxy image ID, sanitized policy, target/workload kind, policy status, container state and a reproducible allow/deny pair. State whether MITM was present at initial injection and which change preceded the failure. Include backend receipt evidence and matching audit records where available; omit credentials, private keys and complete generated configuration dumps.
