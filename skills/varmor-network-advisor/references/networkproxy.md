# NetworkProxy constraints for vArmor v0.10 and later

The links below describe the v0.10 capability baseline. For v0.10 and later, use the official index to find stable documentation matching the actual deployment, and verify the installed CRD, Agent, and proxy. Do not treat v0.10 as an upper version limit or assume complete interface compatibility merely because a release is newer. The scripts currently generate `crd.varmor.org/v1beta1` policies; doctor checks that this API is still served and has the required fields. Run server dry-run before deployment as well.

- [Official llms.txt](https://www.varmor.org/llms.txt) → [v0.10 index](https://www.varmor.org/docs/v0.10/llms.txt)
- [Policy semantics](https://www.varmor.org/docs/v0.10/guides/enforcers/networkproxy/policy-semantics.md)
- [Audit matrix and log locations](https://www.varmor.org/docs/v0.10/guides/enforcers/networkproxy/observability.md)
- [TLS and credentials](https://www.varmor.org/docs/v0.10/guides/enforcers/networkproxy/tls-and-credentials.md)
- [Lifecycle](https://www.varmor.org/docs/v0.10/guides/enforcers/networkproxy/lifecycle-and-upgrades.md)
- [Policy modes (Chinese)](https://www.varmor.org/zh-cn/docs/v0.10/guides/policies_and_rules/policy_modes)

## Two independent control dimensions

System access control settings, including mode and allowViolations/auditViolations, do not control NetworkProxy. Network rules live in `enhanceProtect.networkProxyRawRules.egress` for EnhanceProtect or `defenseInDepth.networkProxy.egress` for DefenseInDepth. New policies default to EnhanceProtect; imported policies retain EnhanceProtect or DefenseInDepth. Combining system denylists with network allowlists does not require changing the entire policy.mode.

| defaultAction | Matching qualifiers | Behavior | Normalized event |
|---|---|---|---|
| allow | none | Allow | none |
| allow | deny | Block | none |
| allow | deny,audit | Block | DENIED |
| allow | audit or allow,audit | Allow | AUDIT |
| deny | none | Block | DENIED |
| deny | allow | Allow | none |
| deny | allow,audit | Allow | AUDIT |
| deny | deny and allow,audit | Block | DENIED |

L4 `rules` need an actual IP/CIDR/ports match condition. A rule containing only qualifiers may pass CRD validation but is skipped by the translator. To observe all TCP, use `ports: [{port: 1, endPort: 65535}]` without restricting the IP family. To observe all HTTP, use `match.hosts: ["*"]`.

An audit-only rule grants no permission under default deny. A matching deny takes priority. Different fields within a rule use AND; lists of values within a field use OR; allow rules use OR. L4 allow and HTTP allow are alternative authorizations. A broad L4 allow cannot serve as a prerequisite for L7 authorization.

## Log schema

`enforcer=NetworkProxy`; `action=AUDIT|DENIED` (no ALLOWED); `profileName`, `podNamespace`, `podName`, `podUID`, `nodeName`, and `eventTimestamp` (Unix seconds). Newer deployments also include policyKind/policyName/policyNamespace. Older deployments may omit them; do not require fields they do not provide. Verify the actual CRD, Agent, and Envoy images instead of assuming every fix exists based on version labels alone.

The event object contains `layer=L4|L7`, `dstAddress` (IPv4:port or [IPv6]:port), and `sni`. L7 adds `authority`, `method`, `path`, `responseCode`, `reason`, and `filterChain` (such as http_chain / mitm_tls_dns_chain). Do not fill missing SNI from authority; a mismatch can indicate domain fronting or misconfiguration. Events have Pod granularity and cannot distinguish application containers or processes within the same Pod.

For ordinary runtimes, read the node's violations.log; micro-VMs may use sidecar files. Envoy stdout mainly helps diagnose configuration loading. HTTP requests and L4 connections do not correspond one-to-one. TCP events for long-lived connections may appear only after closure. A connection still open at the observation deadline may therefore be absent from the candidate; do not infer that it is unnecessary. Review required long-lived dependencies and recommend final user-managed Pod recreation under enforcement to test startup and fresh connections, as described in [verification.md](verification.md). monitor incrementally tracks current and retained rotated files, but completeness still depends on shared log throughput, retention, and collection speed. See [observation-and-collection.md](observation-and-collection.md) for gap detection and deadlines.

## Actual authorization granularity

- Visible HTTP / MITM: Host or authority, actual destination port, normalized path, and case-sensitive method.
- TLS passthrough: SNI and actual destination port; paths/methods are ignored. Adding a path to an HTTP host rule does not guarantee path restrictions for passthrough TLS on the same host/port. HTTPS path guarantees require MITM.
- HTTP rules match host, port, method and path, not URL scheme. MITM also leaves matching plaintext HTTP permissions; it does not make a rule HTTPS-only. Approved HTTP deny rules override grants and can deny an entire non-MITM SNI/port, even when their HTTP methods or paths are narrower. Describe this candidate effect without claiming it is loaded or verified. Never invent a dummy denied method/path to disguise a protocol-only restriction.
- Non-HTTP/TLS: IP/port; do not infer domain names.
- Paths exclude the query. Do not decode a path again after Envoy has normalized it.
- Prefix `/api` also allows `/apix`. Use `/api/` for a subtree and add exact `/api` separately if needed.
- `mitm.domains` selects decryption scope only; it is not an allowlist. MITM certificate wildcard scope differs from HTTP wildcard rules. This CLI uses literal DNS names/IP addresses.
- NetworkProxy redirects TCP. Do not claim coverage for UDP DNS, QUIC, loopback, or other traffic outside that redirection. System enforcers can help remove application NET_ADMIN and prevent use of ProxyUID to resist bypass; preserve/configure them according to user goals.

Initial proxy injection or initial MITM requires new Pods/mounts. For each new startup observation, ask users to create or recreate target Pods after the collector is ready to capture startup behavior. The assistant manages policies, collection, and analysis only; it does not perform business workload lifecycle operations. New and imported policies explicitly set updateExistingWorkloads=false; the original value is retained only in original-policy.json. Existing network rules update through the projected configuration Secret and watched LDS/CDS files. Within the same observation/review/validation workflow, reuse its injected Pods for enforcement, rule refinement and restoration of observation: these rule-only changes do not need a rollout. Wait for propagation/loading, then test fresh connections; Policy.ready alone does not establish sidecar configuration acknowledgment. Changes to startup-injected volumes/environment, redirection settings, or explicit startup coverage may still require user-managed recreation. Keep normal certificate verification for MITM; do not use curl -k. Check whether the application uses the injected CA paths, certificate pinning, and client certificate requirements.

The default webhook objectSelector requires sandbox.varmor.org/enable="true", and the object must also match the policy target. Read the installed webhook configuration to detect customization. Deployment/StatefulSet/DaemonSet targets match the object's own metadata.labels; Pod targets match Pod metadata.labels. For custom controllers, use a Pod target and stable selector; users configure selection and enable labels in the controller's Pod template and create new Pods. This does not establish compatibility for every runtime; verify actual injection and audit.
