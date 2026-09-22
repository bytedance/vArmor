---
sidebar_position: 5
sidebar_label: NetworkProxy
---

# NetworkProxy

NetworkProxy controls redirected outbound TCP traffic through a vArmor-managed Envoy sidecar. Use it to restrict HTTP requests, filter TLS destinations using SNI, inspect HTTPS with TLS interception (MITM), or inject upstream authentication headers.

This guide describes the **v0.10.5** behavior and matching vArmor proxy images. For older installations, read [Lifecycle and Upgrades](lifecycle-and-upgrades.md) before applying these examples.

**HTTP header injection:** for HTTPS requests intercepted by MITM, NetworkProxy can add or replace request headers by domain, such as `Authorization`. Values can be configured directly or referenced from a Kubernetes Secret, so the application does not need to supply the credential itself. See [TLS and Credentials](tls-and-credentials.md#inject-a-credential-header).

## What it can inspect

| Traffic | Available policy information | Audit granularity |
| --- | --- | --- |
| Plain HTTP/1.1 and HTTP/2 cleartext (h2c) | Destination IP/port, HTTP Host, path and method | HTTP request |
| TLS passthrough | Destination IP/port and visible TLS SNI | Connection; no decrypted HTTP path/method |
| HTTPS intercepted by MITM | Destination IP/port and decrypted HTTP Host, path and method | HTTP request |
| Other TCP traffic | Destination IP/port | Connection |

NetworkProxy does not inspect UDP/QUIC or act as a DNS policy engine. It does not provide request-body classification, prompt-injection detection or application-process attribution. Protect other paths with appropriate network and container controls; see [Security and Compatibility](security-and-compatibility.md).

## How it works

![NetworkProxy in runc and Kata: the same in-Pod traffic path, with different audit log locations](/img/networkproxy/runtime-comparison-en.svg)

Both runtimes redirect application TCP traffic to Envoy inside the Pod, where policy determines whether it is forwarded. With runc, the node Agent records audit events. With Kata, the application and proxy run in the same virtual machine and audit logs are written inside the sidecar, without an audit connection across the VM boundary. The audit paths shown record only traffic selected for auditing by the policy.

Both modes use `/var/log/varmor/violations.log`, on the node or in the sidecar filesystem respectively. Configure [runtime detection](../../../getting_started/installation.md#micro-vm-kata-detection-for-networkproxy-auditing) for Kata; see [Observability](observability.md) for log access.


1. A matching policy generates an Envoy configuration Secret in the workload namespace.
2. vArmor injects `varmor-network-proxy-init` and `varmor-network-proxy` into an opted-in workload. The init container installs TCP redirection rules in the Pod network namespace.
3. Envoy applies rules according to the traffic protocol. For HTTPS within the MITM scope, it decrypts and checks the HTTP request, then connects to the upstream over TLS.
4. Envoy loads configuration updates from mounted files. Selected audit events are recorded on the node, or inside the sidecar for configured micro-VM runtimes.

NetworkProxy applies rules to traffic in the shared Pod network namespace. After creating a policy, verify its effect with allowed and denied requests.

## Start here

- [Quick Start](quick-start.mdx): run an isolated HTTP allow/deny example.
- [Policy Semantics](policy-semantics.md): understand L4/L7 combinations, defaults and MITM scope.
- [TLS and Credentials](tls-and-credentials.md): configure trust, MITM and header injection.
- [Security and Compatibility](security-and-compatibility.md): check permissions, UID, runtime and protocol boundaries.
- [Lifecycle and Upgrades](lifecycle-and-upgrades.md): update rules, credentials and proxy workloads.
- [Observability](observability.md) and [Troubleshooting](troubleshooting.md): establish what actually ran and diagnose failures.

Use [Installation](../../../getting_started/installation.md) for Helm configuration and [Interface Specification](../../../getting_started/interface_specification.md#networkproxyconfig) for field definitions.
