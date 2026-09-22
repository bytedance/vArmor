---
sidebar_position: 5
sidebar_label: NetworkProxy
---

# NetworkProxy

NetworkProxy controls redirected outbound TCP traffic through a vArmor-managed Envoy sidecar. Use it to restrict HTTP requests, filter TLS destinations using SNI, inspect HTTPS with TLS interception (MITM), or inject upstream authentication headers.

This guide describes the **v0.10.5** behavior and matching vArmor proxy images. For older installations, read [Lifecycle and Upgrades](lifecycle-and-upgrades.md) before applying these examples. A version label alone does not identify cached image contents.

## What it can inspect

| Traffic | Available policy information | Audit granularity |
| --- | --- | --- |
| Plain HTTP/1.1 and HTTP/2 cleartext (h2c) | Destination IP/port, HTTP Host, path and method | HTTP request |
| TLS passthrough | Destination IP/port and visible TLS SNI | Connection; no decrypted HTTP path/method |
| HTTPS intercepted by MITM | Destination IP/port and decrypted HTTP Host, path and method | HTTP request |
| Other TCP traffic | Destination IP/port | Connection |

NetworkProxy does not inspect UDP/QUIC or act as a DNS policy engine. It does not provide request-body classification, prompt-injection detection or application-process attribution. Protect other paths with appropriate network and container controls; see [Security and Compatibility](security-and-compatibility.md).

## How it works

1. A matching policy generates an Envoy configuration Secret in the workload namespace.
2. vArmor injects `varmor-network-proxy-init` and `varmor-network-proxy` into an opted-in workload. The init container installs TCP redirection rules in the Pod network namespace.
3. Envoy chooses a protocol/filter chain and evaluates its rules. MITM chains terminate TLS before evaluating HTTP requests and then establish upstream TLS.
4. Envoy reads dynamic configuration from projected files. Selected audit events go to the node Agent, or to the in-sidecar sink for configured micro-VM deployments.

The sidecar does not create per-container network namespaces. A successful policy status or an open readiness port is not proof that a particular request uses the intended rules.

## Start here

- [Quick Start](quick-start.mdx): run an isolated HTTP allow/deny example.
- [Policy Semantics](policy-semantics.md): understand L4/L7 combinations, defaults and chain selection.
- [TLS and Credentials](tls-and-credentials.md): configure trust, MITM and header injection.
- [Security and Compatibility](security-and-compatibility.md): check permissions, UID, runtime and protocol boundaries.
- [Lifecycle and Upgrades](lifecycle-and-upgrades.md): update rules, credentials, images and existing templates.
- [Observability](observability.md) and [Troubleshooting](troubleshooting.md): establish what actually ran and diagnose failures.

Use [Installation](../../../getting_started/installation.md) for Helm configuration and [Interface Specification](../../../getting_started/interface_specification.md#networkproxyconfig) for field definitions.
