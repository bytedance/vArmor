---
slug: varmor-0.10.4-new-features-overview
title: "vArmor v0.10.4: NetworkProxy Audit Persistence, Micro-VM (Kata) Compatibility, and Production-Grade Operations"
authors: [DannyWei]
tags: [NewFeatures, ReleaseNotes, AIAgent, NetworkProxy]
date: 2026-08-04T00:00
---

In vArmor v0.10.0, we introduced the [NetworkProxy enforcer](/blog/varmor-0.10.0-new-features-overview/), bringing L4/L7 network access control to Kubernetes workloads through a sidecar proxy architecture. In [v0.10.1](/blog/varmor-0.10.1-new-features-overview/), we completed the Phase 2 TLS Man-in-the-Middle (MITM) capability, upgrading it into a deep packet inspection engine that covers encrypted traffic.

vArmor v0.10.4 is a **production-focused** release. We concentrated on three things: making NetworkProxy's **audit capability truly land** — audit logs that are persistent and can be correlated to workload identity; keeping vArmor working reliably in **non-standard runtimes such as micro-VMs (Kata / Serverless sandboxes)**; and lowering the operational cost of large-scale deployments through **cluster-level sidecar resource quota management** and **iptables backend auto-adaptation**. In addition, policy-advisor's conflict detection is now more precise.

<!--truncate-->

## Why Focus on "Audit Persistence" and "Runtime Compatibility"?

Over its first two releases, the NetworkProxy enforcer solved the "can we control it" problem — from domain-level gatekeeping to deep inspection of encrypted traffic. But once users deployed it into real production clusters, especially multi-tenant environments running AI Agents, new engineering problems surfaced:

- **Where did the audit logs go?** The enforcer supports the `audit` qualifier, but the audited egress traffic records need a stable, collectable landing location, and they must be attributable to the specific Pod and workload that produced them.
- **What about micro-VM scenarios?** More and more AI Agent workloads run on Kata Containers or cloud-vendor Serverless offerings (e.g., Volcengine VCI, Alibaba Cloud ECI). The network namespaces and mount boundaries of these micro-VM runtimes differ from runc, and the original audit collection path and iptables injection method would fail — or even cause traffic to be silently dropped.
- **How do we manage resources uniformly at scale?** MITM sidecars consume more resources than pass-through proxies, and configuring resource quotas on a per-policy basis is simply impractical at cluster scale.

v0.10.4 is built around these three problems.

## Persistent Egress Audit Logs for NetworkProxy

The NetworkProxy enforcer reports violation audit events for egress traffic through its Envoy sidecar. v0.10.4 completes the persistence of this audit pipeline:

- **Unified landing path**: All audited egress traffic records are ultimately written to the container-visible `/var/log/varmor/violations.log`, in a normalized, structured record format that log collection systems can consume uniformly.
- **Node-level collection (runc)**: Under the runc runtime, the Envoy sidecar streams audit records over a node-level hostPath Unix Domain Socket via gRPC ALS (Access Log Service) to the `varmor-agent` DaemonSet on the node, and the agent is responsible for writing the log file. This decouples audit-data writing from collection, and consumes neither the resources nor the privileges of the application container.
- **Pod-level identity correlation**: Since these events are produced by the proxy at Pod granularity, every record carries Pod-level identity information (`nodeName`, `podName`, `podNamespace`, `podUID`), so security teams can precisely correlate each network access to a specific workload, instead of dealing with isolated logs stripped of context.

This evolves NetworkProxy's audit mode from "can record" to "can be collected by a production-grade log system and can be traced back to its source."

## Micro-VM (Kata / Serverless) Audit and Traffic-Redirection Compatibility

This is the core improvement in v0.10.4 for real AI Agent deployment environments. The boundaries of micro-VM runtimes (Kata, Serverless sandboxes) are fundamentally different from runc, and vArmor performs adaptive handling on two critical paths.

### Audit Collection: In-Sidecar ALS Sink

Under a micro-VM runtime, the sidecar runs inside the micro-VM, and the aforementioned node-level hostPath Socket **cannot cross the VM boundary** (some Serverless vendors even reject such hostPath mounts outright at admission). To address this, for workloads identified as micro-VMs, vArmor:

- **Omits the hostPath volume and mount**, avoiding a rejected mount that would prevent the Pod from being scheduled;
- **Starts an in-sidecar audit Sink**, binding the Socket inside the container's own rootfs and writing directly to the container-local `/var/log/varmor/violations.log`.

Whether runc or micro-VM, the final audit records are **byte-for-byte identical**, so upper-layer collection and analysis logic need not distinguish between runtimes.

### Micro-VM Detection: `microVMDetection`

vArmor determines which workloads run under a micro-VM runtime via the `microVMDetection` configuration. The decision logic is: the workload's `runtimeClassName` matches the list, **or** any annotation rule matches, **or** any label rule matches (for annotation/label rules, an empty value means match by key existence only, while a non-empty value requires an exact match). The built-in defaults already cover upstream Kata and the Serverless runtimes of major cloud vendors:

| Dimension | Built-in Default |
|------|-----------|
| `runtimeClassNames` | `kata`, `kata-qemu`, `kata-clh` |
| annotation | `vke.volcengine.com/burst-to-vci=enforce` (Volcengine VKE burst-to-VCI) |
| label | `alibabacloud.com/eci=true` (Alibaba Cloud ECI) |

To extend the detection rules for a custom micro-VM runtime, edit the `varmor-config` ConfigMap, or set the value of `dynamicConfig.microVMDetection` at install time — **it hot-reloads with no restart required**.

### Traffic Redirection: iptables Backend Auto-Adaptation

The NetworkProxy enforcer injects iptables rules via an init container to transparently redirect egress traffic. Different runtimes and different infrastructures (such as certain PaaS meshes) do not use a consistent iptables backend (`legacy` vs. `nft`), and hardcoding one backend can cause traffic to be silently dropped — for example, when a Kata Pod's network namespace was already programmed by a PaaS mesh init using the `legacy` backend.

Starting with the `proxyinit:v0.2` image, vArmor **automatically detects the iptables backend already in use in the target network namespace and drives the matching backend**:

- On a brand-new network namespace, it defaults to `nft` (consistent with existing behavior);
- If it detects rules already present in both backends, it aborts explicitly with `CONFLICT` rather than blindly guessing and causing a hidden failure.

This capability is fully automatic and requires no configuration switch — just ensure the Chart pulls `proxyinit:v0.2` or a newer version.

## Cluster-Level Sidecar Resource Quota Management

In the [future roadmap of v0.10.1](/blog/varmor-0.10.1-new-features-overview/), we proposed providing cluster-level management of default sidecar resources. v0.10.4 delivers on that promise.

vArmor adds a runtime hot-reloadable dynamic configuration, carried in the `varmor-config` ConfigMap in vArmor's namespace. The Manager watches this ConfigMap via an informer and hot-reloads on change **without a restart**; if the ConfigMap is missing or malformed, it falls back to the built-in defaults that are identical to the values shipped with the Chart.

Administrators now only need to **configure once** to set default resource requests/limits for every NetworkProxy sidecar injected across the cluster, instead of setting `.spec.policy.networkProxy.resources` on each policy individually. The injector uses a **three-tier, field-level merge chain** to resolve the final resources, with each leaf field (`requests.cpu`/`requests.memory`/`limits.cpu`/`limits.memory`) falling back independently:

> Policy-level override > Cluster-level global config (`varmor-config`) > Built-in default

Considering that MITM sidecars carry a heavier load (bidirectional TLS handshakes), the configuration is split into two mutually independent tiers — an MITM sidecar reads only the `mitm` tier, a non-MITM sidecar reads only the `nonMitm` tier, and the two tiers do not inherit from each other. The built-in defaults are as follows:

| Tier | CPU requests | Memory requests | CPU limits | Memory limits |
|------|-------------|---------------|-----------|-------------|
| `nonMitm` | 50m | 64Mi | 500m | 256Mi |
| `mitm` | 100m | 128Mi | 1000m | 512Mi |

```bash
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.cpu="50m" \
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.memory="64Mi" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.cpu="1000m" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.memory="512Mi"
```

Notes on usage: resource quantities must be quoted as strings (e.g., `"500m"`, `"256Mi"`); an unquoted bare number is parsed as an integer (`memory: 100` means 100 bytes, not 100Mi); tier key names must be spelled exactly as `nonMitm` and `mitm`, and misspellings are silently ignored and fall back to the built-in defaults; invalid entries (unknown resource names, unparseable quantities, non-positive values, or a limit lower than the request within the same tier) are ignored and logged when the Manager loads them.

## policy-advisor: More Precise Shell-Usage Conflict Detection

policy-advisor supports filtering out built-in rules that conflict with observed behavior data, making the generated policy templates more precise. v0.10.4 enhances the matching capability of rules such as `disable-shell`: when matching, the advisor now judges based on **both the basename of the executable and its file extension**.

As a result, even if a shell appears in the behavior data only in the form of a script path (e.g., `/var/lib/cilium/bpf/init.sh`, without an independent `sh`/`bash`/`dash` binary execution record), it can still be correctly identified as a conflict via its `.sh` extension, filtering out the corresponding conflicting rule and avoiding the generation of a policy that would break the business.

## Upgrade Notes

- The NetworkProxy init container image must be `proxyinit:v0.2` or newer to enable the iptables backend auto-adaptation capability.
- Both micro-VM detection and sidecar resource defaults are carried by the `dynamicConfig` of the `varmor-config` ConfigMap, supporting initialization at install time as well as hot updates after installation, with no restart required for changes.

## Summary

If v0.10.0 and v0.10.1 answered "can vArmor control an AI Agent's network behavior," then v0.10.4 answers "can vArmor do it stably, observably, and with low operational cost in a real production cluster." Through persistent audit logs with Pod-level identity correlation, adaptive compatibility for micro-VM (Kata / Serverless) runtimes on both the audit-collection and traffic-redirection paths, unified cluster-level management of sidecar resource quotas, and more precise conflict detection in policy-advisor, this release brings the NetworkProxy enforcer much closer to large-scale, multi-runtime, multi-tenant real-world deployment environments.

Welcome to upgrade and try out vArmor v0.10.4, and share your feedback with us via [GitHub](https://github.com/bytedance/vArmor)! For full details, please refer to the [Release Notes](https://github.com/bytedance/vArmor/releases/tag/v0.10.4).
