---
sidebar_position: 4
---

# Security and compatibility

NetworkProxy does not require an LSM for its own enforcement. Before deploying a policy, confirm that the cluster permits proxy injection and meets the permission, networking and image requirements below.

## Permissions and identity

vArmor configures the injected containers' security contexts automatically; no manual settings are needed. Cluster admission must allow the injected containers to start as root and the init container to use `NET_ADMIN`. Namespaces enforcing Restricted Pod Security need an appropriate exception.

The application UID must differ from `proxyUID`, because traffic from the proxy UID is exempt from redirection. Choose the UID before creating the policy: `proxyUID`, `proxyPort` (default 15001) and `proxyAdminPort` (default 15000) are immutable, and the ports must not conflict with each other or the workload.

Do not give business containers `NET_ADMIN` or the ability to switch to the exempt proxy UID. Apply appropriate capability and process restrictions using container security contexts and, where applicable, AppArmor/BPF. NetworkProxy is not a boundary against a process that can rewrite its own redirection rules.

## Traffic scope

- Redirection is in the Pod network namespace, not a private namespace for each container. Do not infer per-container network enforcement from `spec.target.containers`.
- TCP is redirected; UDP, including ordinary UDP DNS and QUIC/HTTP/3, is not inspected by this enforcer.
- Loopback destinations and proxy-UID traffic are deliberately exempt. NetworkProxy is not an all-egress firewall.
- Use a separate Pod network namespace. Do not deploy this guide's injection with `hostNetwork: true`; its redirection design is not a node-wide network policy mechanism.
- Protect proxy admin access. Local non-proxy traffic to the configured admin port is dropped by the init rules; do not assume that alone isolates every sidecar admin endpoint from other Pods.
- Service Mesh or other proxies may also change routing and iptables. When combining them, check routing conflicts and verify allowed and denied traffic before deployment.

## Images, runtimes and resources

Use the matching vArmor **custom** Envoy and proxyinit images, not an upstream Envoy image with a similar version label.

See [Installation](../../../getting_started/installation.md) for runtime detection, iptables backend selection and resource settings. For Kata or other micro-VM runtimes, configure runtime detection and check the platform's admission and volume requirements.

Adjust proxy CPU and memory requests/limits to the workload. Monitor resource usage and request latency as traffic increases.

## IPv6

Even when IPv6 addresses are equivalent, different textual spellings can prevent MITM request destinations and HTTP host rules from matching. Use a consistent spelling in the MITM configuration, HTTP rules and the client's Host/authority; prefer canonical compressed notation, with brackets in an HTTP authority. For a `/128` MITM destination, clients should use the canonical compressed IP spelling; the header-mutation domain reference must still equal the original `/128` declaration.

Inconsistent address spelling can prevent either an allow or a deny rule from matching.

## TLS and application behavior

Read [TLS and Credentials](tls-and-credentials.md) for two-sided trust, CA caching and certificate pinning. Authorization matches the available protocol fields; it does not inspect request bodies or understand whether an allowed API request contains sensitive data. The current policy API does not expose arbitrary Envoy filters such as `ext_proc`.
