---
sidebar_position: 7
---

# Troubleshooting

Start with an owned test destination and one expected allow/deny pair. Keep the initial failure as evidence; repeated retries until one succeeds do not demonstrate that a configuration is correct.

## Symptom checklist

| Symptom | Check | Recovery |
| --- | --- | --- |
| No sidecar | Workload opt-in label, policy target kind/name/labels, namespace and cluster-policy precedence | Correct selection; inspect the controller and create a new test Pod |
| `CreateContainerConfigError` with non-root inheritance | Injected container fields in the stored template | Follow the [old-template repair](lifecycle-and-upgrades.md#recover-an-old-non-root-template) procedure |
| Init container repeatedly fails | Permission errors, netfilter backend, partially created chains | Fix the persistent cause, then recreate the Pod/network namespace; do not ignore iptables errors |
| EOF, refused connections or repeated proxy OOM | Actual Envoy process UID versus `proxyUID`, image ID and entrypoint | Use the matching custom image and a fresh Pod; do not treat more memory as proof of a fix |
| HTTPS path restriction has no effect | TLS passthrough versus MITM, broad L4 allow | Configure interception/trust and remove unintended alternative authorization |
| MITM 404 | HTTP authority outside the chain's virtual hosts, including IPv6 text mismatch | Align MITM identity, HTTP host and client authority; do not add a catch-all blindly |
| TLS verification fails | Application CA and upstream CA/identity separately; old cached trust | Correct the appropriate trust path, wait for projection, reload the relevant process |
| Allowed requests get 503 after an update | CDS/LDS/validation SDS convergence and upstream connectivity | Inspect proxy errors and verify the upstream before repeating a bounded readiness check |
| Policy Ready but old behavior persists | Rejected proxy configuration, stale projected files or static bootstrap | Repair input, reconcile, then verify reload and actual requests |
| Header remains old after Secret change | Policy generation and successful reconcile | Trigger a valid spec update as described in [TLS and Credentials](tls-and-credentials.md#rotate-and-verify) |
| Policy Error after credential update | Missing Secret/key, empty/unsafe value, generated configuration size | Fix the dependency/input and reconcile; last valid namespace configuration remains active |
| No audit | Matrix expectation, node versus sidecar log location, compatible ALS consumer | Check [Observability](observability.md) and consumer-before-producer upgrade order |

## Confirm process identity, not only the Pod specification

The sidecar starts as root and its entrypoint drops the Envoy process to the policy's UID. `kubectl exec ... id` describes a new helper process and may not describe the running Envoy. Inspect the UID fields in `/proc/<envoy-pid>/status` using an authorized diagnostic method. In micro-VM mode a supervisor may be PID 1, so do not assume `/proc/1` always belongs to Envoy.

An incompatible cached image can use a different entrypoint/UID despite the expected tag and environment variable. Compare the runtime image ID and entrypoint behavior with the deployed release. After fixing the image, verify both allowed and denied requests and check that restarts stop.

## Recovery boundaries

- Envoy can retain the previous configuration after rejecting an update; policy Ready is not a versioned application acknowledgment.
- A failed read of an existing MITM Secret can currently lead to new CA generation. If the CA changed unexpectedly, investigate Manager/API errors, verify the new bundle and reload applications that cached the old CA. Do not promise automatic old-CA preservation on transient read failure.
- Init scripts are not guaranteed to be safely repeatable after partial application in the same network namespace. Recreate the Pod after correcting permissions/backend problems.
- A cluster policy's configuration publication to a new namespace can fail when referenced Secrets are absent. Fix those dependencies and trigger a valid policy spec update; do not rely on an undocumented force-sync annotation or guaranteed automatic retry.
- Generated Secret data warns above 700 KiB and is rejected above 900 KiB. Large combinations of hosts, ports, paths and methods expand the configuration. Reduce the rule/domain/mutation set rather than bypassing size checks.

These are operational boundaries of the documented implementation. A future recovery design is not an existing guarantee.

## When reporting a problem

Include the vArmor revision, runtime and Kubernetes version, proxy image ID, sanitized policy, target/workload kind, policy status, container state and a reproducible allow/deny pair. State whether MITM was present at initial injection and which change preceded the failure. Include backend receipt evidence and matching audit records where available; omit credentials, private keys and complete generated configuration dumps.
