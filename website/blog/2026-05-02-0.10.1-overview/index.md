---
slug: varmor-0.10.1-new-features-overview
title: "vArmor v0.10.1: See Inside HTTPS — AI Agent Traffic Inspection, Key Injection, and CVE-2026-31431 Mitigation"
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes, AIAgent, LLM, NetworkProxy, TLSMITM]
date: 2026-05-02T00:00
---

In vArmor v0.10.0, we introduced the **NetworkProxy enforcer** — a sidecar-based transparent proxy that brings L4/L7 network access control to Kubernetes workloads. While v0.10.0 could already enforce allow/deny policies on plaintext HTTP and TLS SNI, **HTTPS encrypted traffic remained a black box**: the proxy could see the destination domain via SNI, but could not inspect request paths, headers, or response bodies.

vArmor v0.10.1 completes the **Phase 2** of the NetworkProxy enforcer by adding **TLS Man-in-the-Middle (MITM)** capabilities, unlocking deep HTTPS inspection, automatic header injection, and anti-Domain-Fronting protection. This release also introduces **IPv6 dual-stack support**, **configurable sidecar resource quotas**, a **ConfigMap-to-Secret migration** for improved security, and demonstrates **rapid CVE response** capabilities through the CVE-2026-31431 mitigation case study.

<!--truncate-->

## Why TLS MITM?

In v0.10.0, the NetworkProxy enforcer could match HTTPS traffic by TLS SNI (Server Name Indication) — enough to control *which domains* an AI Agent can connect to, but not *what it sends*. Consider these real-world requirements:

- **API Key governance**: Inject LLM API Keys at the proxy layer so that Agent containers never see the actual keys, preventing key leakage via Prompt Injection or container compromise.
- **Deep L7 inspection**: Enforce path-level and method-level rules on HTTPS traffic (e.g., only allow `POST /v1/chat/completions` to `api.openai.com`).
- **Anti-Domain-Fronting**: Detect and block attacks where the TLS SNI and HTTP `Host` header differ — a technique used to tunnel traffic through trusted CDN domains.
- **Request auditing**: Inspect and log HTTP requests (headers and bodies) in encrypted traffic — particularly valuable for auditing AI Agent and LLM communications for compliance and anomaly detection.

TLS MITM is the key that unlocks all of these capabilities.

## TLS MITM: How It Works

### Per-Policy CA Management

vArmor v0.10.1 implements **fully automatic, per-policy CA certificate management**:

1. When a `VarmorPolicy` or `VarmorClusterPolicy` enables MITM, the vArmor Manager automatically generates a dedicated **ECDSA P-256 CA key pair** for that policy.
2. The CA certificate and key, along with all Envoy xDS configurations, are stored in a **unified Kubernetes Secret** (one per policy), replacing the previous ConfigMap-based approach.
3. The CA certificate is injected into the target Pod as a **trusted root** via environment variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`), alongside the **Mozilla CA bundle** (embedded via Go `go:embed`).
4. For each intercepted TLS connection, the Envoy sidecar generates a **leaf certificate** on-the-fly with multi-SAN support, signed by the policy-specific CA.

### Secret-Based Configuration

All proxy configurations have been migrated from ConfigMap to Secret:

| Secret Data Key | Content |
|---|---|
| `lds.yaml` | Envoy Listener Discovery Service config |
| `cds.yaml` | Envoy Cluster Discovery Service config |
| `ca.crt` | Per-policy CA certificate |
| `ca.key` | Per-policy CA private key |
| `ca-bundle.crt` | Mozilla trusted CA bundle |

Three projected volumes with **key-level isolation** ensure that the Envoy sidecar can access xDS configs and CA materials, while the application container only sees the CA bundle for trust establishment — never the CA private key.

### Anti-Domain-Fronting

When MITM is enabled, the Envoy sidecar terminates the client TLS connection and has access to the plaintext HTTP request. vArmor automatically enforces **SNI-Host consistency**: if the TLS SNI does not match the HTTP `Host` header, the request is rejected with a `404` response. This effectively blocks Domain Fronting attacks, where an adversary hides the true destination behind a trusted domain's SNI.

### Header Injection via SecretRef

MITM also enables **automatic HTTP header injection**, configured through Kubernetes Secret references in the policy CRD. This is the foundation for **API Key governance** — the proxy can inject authentication headers (e.g., `Authorization: Bearer <key>`) into outbound requests, so the Agent container never needs direct access to API credentials.

```yaml
networkProxyConfig:
  mitm:
    domains:
    - "*.openai.com"
    headerMutations:
    - domain: "*.openai.com"
      headers:
      - name: Authorization
        secretRef:
          name: openai-credentials
          key: api-key
enhanceProtect:
  networkProxyRawRules:
    egress:
      defaultAction: deny
      httpRules:
      - qualifiers: ["allow", "audit"]
        match:
          hosts:
          - "*.openai.com"
```

## IPv6 Dual-Stack Support

vArmor v0.10.1 adds full **IPv6 dual-stack support** for the NetworkProxy enforcer:

- **Automatic detection**: The controller detects whether the cluster runs single-stack (IPv4 or IPv6) or dual-stack, and configures listeners and iptables rules accordingly.
- **Dedicated listeners**: Separate Envoy listeners are created for IPv4 and IPv6 traffic, ensuring correct transparent proxy behavior on dual-stack clusters.
- **iptables integration**: The init container always sets up both `iptables` and `ip6tables` redirect rules by default, ensuring correct behavior regardless of cluster network configuration.

This ensures that vArmor's network protection works seamlessly in modern Kubernetes clusters that have adopted IPv6.

## Configurable Sidecar Resource Quotas

TLS MITM operations (certificate generation, encryption/decryption) are more resource-intensive than simple passthrough proxying. To address this, v0.10.1 introduces **configurable sidecar resource quotas**:

- **MITM-aware defaults**: When MITM is enabled, the default sidecar resource limits are automatically elevated from `100m CPU / 128Mi memory` to `1000m CPU / 512Mi memory`.
- **Per-policy override**: Users can fine-tune resource requests and limits in the policy CRD with field-level merge semantics.

```yaml
spec:
  policy:
    enforcer: NetworkProxy
    enhanceProtect:
      networkProxySidecarResources:
        requests:
          cpu: "500m"
          memory: "256Mi"
        limits:
          cpu: "2000m"
          memory: "1Gi"
```

## Rapid CVE Response: CVE-2026-31431 as a Case Study

**CVE-2026-31431** is a critical vulnerability where a malicious container can exploit the `AF_ALG` socket family combined with `splice()` to corrupt the kernel page cache of read-only files. In Kubernetes environments, this enables **full container escape** — an unprivileged pod can corrupt shared container image layer pages (e.g., a binary in the kube-proxy image), and when a privileged DaemonSet next executes that binary, the attacker's payload runs with host-level root privileges. This makes the vulnerability particularly dangerous for AI Agent workloads running on shared Kubernetes clusters.

vArmor's architecture is designed for **rapid security response**. When CVE-2026-31431 was disclosed, vArmor users could immediately craft and deploy mitigation policies using the **custom rule interface** and **audit mode** of the AppArmor and BPF enforcers — without waiting for any software update:

```yaml
  policy:
    enforcer: AppArmorBPF
    mode: EnhanceProtect
    enhanceProtect:
      # Disable creating socket with AF_ALG domain (AF_ALG: Interface to kernel crypto API)
      # For AppArmor enforcer
      appArmorRawRules:
      - rules: |
          audit deny network alg,
      # For BPF enforcer
      bpfRawRules:
        network:
          sockets:
          - qualifiers: ["audit", "deny"]
            domains: ["alg"]
```

This example demonstrates several core strengths of vArmor:

- **Observability**: The `audit` qualifier logs every blocked `AF_ALG` socket attempt, giving security teams immediate visibility into potential exploit activity across the cluster. It also helps identify whether any legitimate workloads actually depend on `AF_ALG` — allowing teams to assess the blast radius before switching from audit to hard deny.
- **Dynamic policy management**: Policies can be created, updated, and rolled out to workloads in real-time — no Pod restarts, no node reboots, no maintenance windows required.
- **Custom rule flexibility**: The `appArmorRawRules` and `bpfRawRules` interfaces allow security teams to express arbitrary kernel-level restrictions, turning any CVE analysis into an enforceable policy within minutes.

To further simplify this workflow, vArmor v0.10.1 also ships the **`copy-fail-mitigation` built-in rule**, so users can enable the same protection with a single rule name — no manual policy authoring required:

| Enforcer | Mechanism |
|---|---|
| **AppArmor** | Denies `network alg` to block `AF_ALG` socket creation |
| **BPF** | Blocks socket creation with `AF_ALG` family at the syscall level |

> **Note on Seccomp**: Although Seccomp can technically block `AF_ALG` socket creation, it is intentionally not included as a built-in enforcer for this rule. Seccomp profiles are applied at container creation time and cannot be dynamically updated or relaxed while the container is running, unlike AppArmor and BPF enforcers which support runtime policy updates. A manual Seccomp configuration example via `syscallRawRules` is provided in the documentation for users who still prefer it.
## Other Improvements

- **Envoy upgrade**: Sidecar Envoy upgraded to v1.38-latest with upstream performance improvements and bug fixes.
- **Code reorganization**: NetworkProxy translator and renderer refactored with dedicated MITM translation logic and MITM-aware filter chain construction.
- **11 new example YAMLs**: Covering MITM-enabled policies, header injection, IPv6, and resource quota customization.


## Known Limitations

**IP-based MITM + plaintext HTTP**

When a target IP address (not a domain name) is configured as a TLS MITM object, **plaintext HTTP traffic** destined to that IP will not match the `http_chain`, and its L7 access control rules will not take effect. This is an inherent behavior of Envoy's filter chain matching algorithm — `prefix_ranges` matching takes precedence and eliminates less specific chains. If your workloads need both TLS MITM and plaintext HTTP L7 access control for the same target, configure rules using domain names rather than IP addresses.

**CA bundle overrides container-native CA list**

The `SSL_CERT_FILE` and similar environment variables cause the runtime to **ignore** the container image's original CA list (e.g., `/etc/ssl/certs/ca-certificates.crt`). Custom CAs added to the container image will be lost. If the user has already set these environment variables, vArmor's injection is skipped (idempotent check), and users need to manually append the vArmor CA to their custom bundle.

**Java (JKS) incompatibility**

Java applications use JKS/PKCS12 keystores and do not read PEM-format CA bundles from environment variables. Java workloads require manual `keytool -import` to add the MITM CA to the default truststore.

**Certificate Pinning incompatibility**

Domains that enforce Certificate Pinning (e.g., banking SDKs, payment SDKs) **cannot be MITM-intercepted** — clients hardcode certificate fingerprints, and any MITM certificate will fail validation. These domains can only be controlled at the SNI level via TLS passthrough. Users should ensure that such domains' CDNs do not allow Host ≠ SNI routing.

**SecretRef rotation**

In-place updates to the data of a referenced API Key Secret do not automatically propagate to Envoy. The recommended rotation workflow is: create a new Secret, update the policy's `secretRef.name` to point to the new Secret, which triggers a reconcile and hot-updates the sidecar configuration — **no Pod restart required**.

## What's Next

With Phase 2 complete, the NetworkProxy enforcer now provides a comprehensive security solution spanning from L4 to L7, covering both plaintext and encrypted traffic. Looking ahead, we plan to explore:

- **User-provided CA (`CASecretRef`)**: Allow users to supply their own CA certificate and private key for MITM leaf certificate signing, supporting enterprise PKI integration and compliance requirements. This will also resolve the "CA bundle override" limitation by merging the user-provided CA, Mozilla bundle, and MITM CA into a three-way bundle.
- **Global sidecar resource quota management**: Cluster-level default resource configuration via `varmor-config` ConfigMap, allowing administrators to set unified sidecar resource quotas without per-policy configuration, with a three-tier merge chain (per-policy > global config > built-in defaults).
- **Automatic SecretRef watch**: Watch referenced API Key Secrets and automatically trigger re-reconcile when their data changes, eliminating the current "create new Secret + update policy" rotation workflow.
- **Intelligent policy generation**: Leveraging LLM technology to automatically recommend minimum-privilege network access policies based on observed Agent behavior patterns.
- **Deeper protocol support**: While gRPC (HTTP/2) and WebSocket already pass through the current MITM pipeline (as they are built on HTTP/1.1 upgrade or HTTP/2 CONNECT), future releases will add protocol-aware L7 inspection — e.g., gRPC service/method-level RBAC rules and WebSocket frame-level auditing.

## Conclusion

vArmor v0.10.1 marks the completion of the NetworkProxy enforcer's TLS MITM capabilities, transforming it from a domain-level gatekeeper into a full **deep packet inspection engine** for encrypted traffic. Combined with automatic per-policy CA management, anti-Domain-Fronting protection, header injection for API Key governance, IPv6 dual-stack support, and rapid CVE response through observable, dynamically managed policies, this release significantly strengthens vArmor's ability to secure AI Agent workloads in production Kubernetes environments.

Whether you're operating an AI application platform, deploying autonomous AI Agents, or managing LLM workloads in multi-tenant Kubernetes clusters, vArmor v0.10.1 gives you the tools to enforce fine-grained, protocol-aware security policies — ensuring that your Agents can only do what they're authorized to do.

Upgrade to vArmor v0.10.1 today, and share your feedback on [GitHub](https://github.com/bytedance/vArmor)! For full details, see the [Release Notes](https://github.com/bytedance/vArmor/releases).
