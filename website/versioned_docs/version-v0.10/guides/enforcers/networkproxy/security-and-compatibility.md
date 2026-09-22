---
sidebar_position: 4
---

# Security and compatibility

Evaluate these prerequisites before deploying a policy. NetworkProxy avoids an LSM dependency for its own enforcement, but still depends on Kubernetes admission, injected containers, working netfilter redirection and compatible proxy images.

## Permissions and identity

The init container starts with `runAsUser: 0`, `runAsNonRoot: false` and `NET_ADMIN` to set up redirection. The sidecar also starts as UID 0 with `runAsNonRoot: false`; the **vArmor custom image entrypoint** then runs Envoy under `proxyUID` (default 1337). These container-level fields override inherited Pod non-root defaults for the injected containers. They do not change the business container's security context.

This injection is not compatible with a namespace that unconditionally enforces Restricted Pod Security requirements. Arrange an appropriate, reviewed admission policy for this workload; do not disable cluster-wide admission controls as a troubleshooting shortcut.

The application UID must differ from `proxyUID`, because traffic from the proxy UID is exempt from redirection. Choose the UID before creating the policy: `proxyUID`, `proxyPort` (default 15001) and `proxyAdminPort` (default 15000) are immutable, and the ports must not conflict with each other or the workload.

Do not give business containers `NET_ADMIN` or the ability to switch to the exempt proxy UID. Apply appropriate capability and process restrictions using container security contexts and, where applicable, AppArmor/BPF. NetworkProxy is not a boundary against a process that can rewrite its own redirection rules.

## Traffic scope

- Redirection is in the Pod network namespace, not a private namespace for each container. Do not infer per-container network enforcement from `spec.target.containers`.
- TCP is redirected; UDP, including ordinary UDP DNS and QUIC/HTTP/3, is not inspected by this enforcer.
- Loopback destinations and proxy-UID traffic are deliberately exempt. NetworkProxy is not an all-egress firewall.
- Use a separate Pod network namespace. Do not deploy this guide's injection with `hostNetwork: true`; its redirection design is not a node-wide network policy mechanism.
- Protect proxy admin access. Local non-proxy traffic to the configured admin port is dropped by the init rules; do not assume that alone isolates every sidecar admin endpoint from other Pods.
- Service Mesh or other proxies may also change routing and iptables. This guide does not establish general coexistence support; validate the combined path and both allow/deny outcomes before deployment.

## Images, runtimes and resources

Use the matching vArmor **custom** Envoy and proxyinit images, not an upstream Envoy image with a similar version label. The custom entrypoint must honor `VARMOR_ENVOY_UID`. With `IfNotPresent`, replacing an existing tag in a registry does not replace node-cached image content. Publish a new tag when image behavior changes, update the actual workload template and verify running image IDs.

For runtime detection, iptables backend selection and resource settings, use [Installation](../../../getting_started/installation.md). The micro-VM audit path is implemented, but the recent IPv4/runc smoke and regression results do not establish validation of every Kata/serverless deployment. Runtime-specific admission, volume and connectivity requirements must be checked separately.

Resource requests/limits are adjustable; the defaults are not a tested throughput guarantee. Raising memory limits is not a remedy for mismatched Envoy process UID and redirection exceptions.

## IPv6

IPv6 matching/generation has dedicated tests, but the referenced Kubernetes regression runs used IPv4 Pod networking. They do not establish full IPv6 cluster compatibility.

MITM IP selection parses addresses, while HTTP virtual-host/host matching also depends on text. Equivalent compressed and expanded IPv6 spellings need not match. Use a consistent spelling in the MITM configuration, HTTP rules and the client's Host/authority; prefer canonical compressed notation, with brackets in an HTTP authority. A `/128` MITM declaration generates a canonical IP virtual host; its header-mutation reference must still equal the original `/128` declaration.

Do not infer that every equivalent-text mismatch is harmless: a mismatched deny rule can matter as well as a mismatched allow rule.

## TLS and application behavior

Read [TLS and Credentials](tls-and-credentials.md) for two-sided trust, CA caching and certificate pinning. Authorization matches the available protocol fields; it does not inspect request bodies or understand whether an allowed API request contains sensitive data. The current policy API does not expose arbitrary Envoy filters such as `ext_proc`.
