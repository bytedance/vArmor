---
sidebar_position: 3
---

# TLS and credentials

First complete the [HTTP Quick Start](quick-start.mdx). MITM additionally requires the application to trust vArmor's CA and Envoy to trust the upstream server. Confirm both before interpreting a TLS failure as policy denial.

## The two trust relationships

| TLS connection | Trust requirement |
| --- | --- |
| Application → Envoy | The application trusts the policy's MITM CA and accepts the generated server identity |
| Envoy → upstream | The upstream certificate chains to Envoy's trusted bundle and matches the routed HTTP authority |

vArmor generates a CA per policy configuration namespace and publishes certificate material with the Envoy configuration. Application containers receive a CA bundle combining public roots and the MITM CA, without the CA private key. The injector supplies `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `CURL_CA_BUNDLE` when the application has not already defined the corresponding variable.

These variables are integration aids, not universal SDK support. Existing trust variables, custom trust stores, certificate pinning and libraries that cache CAs may require application-specific configuration. Updating a mounted certificate file does not reload an application's in-memory trust store. Do not use `curl -k` to validate MITM.

Publicly trusted upstreams are the normal starting point. A private upstream CA is a separate trust requirement; the two CA directions are not interchangeable. The policy API does not expose a general upstream-CA reference. Configure supported settings through the policy API; directly editing generated configuration can be overwritten by vArmor.

## Configure interception and authorization together

The following is a **policy fragment**, not a complete Kubernetes resource. Replace the example hostname with your owned HTTPS service, whose certificate Envoy can validate:

```yaml
policy:
  enforcer: NetworkProxy
  mode: EnhanceProtect
  enhanceProtect:
    networkProxyRawRules:
      egress:
        defaultAction: deny
        httpRules:
        - qualifiers: [allow, audit]
          match:
            hosts: [api.example.com]
            ports: [{port: 443}]
            paths: [{prefix: /v1/}]
            methods: [POST]
  networkProxyConfig:
    mitm:
      domains: [api.example.com]
```

Create the policy before the test workload so injection includes the TLS mounts. For an existing non-MITM Pod, follow [Lifecycle and Upgrades](lifecycle-and-upgrades.md); a Secret update cannot add missing Pod mounts.

Use exact DNS names, wildcard DNS names, IP literals or single-host CIDRs (`/32` for IPv4, `/128` for IPv6) as supported by the API. List the parent name separately from `*.example.com`. MITM domain entries must have no surrounding whitespace or duplicate identities. IPv6 text consistency has additional [constraints](security-and-compatibility.md#ipv6).

## Inject a credential header

Create a Secret in the **target workload's namespace**. For a `VarmorClusterPolicy`, each selected namespace needs its own referenced Secret. This example contains only a disposable demonstration value:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: upstream-credential
  namespace: varmor-networkproxy-demo
type: Opaque
stringData:
  authorization: "Bearer demonstration-only"
```

Add this fragment under `spec.policy.networkProxyConfig.mitm`, alongside `domains`:

```yaml
headerMutations:
- domain: api.example.com
  headers:
  - name: Authorization
    secretRef:
      name: upstream-credential
      key: authorization
```

The mutation's `domain` must literally equal a `domains` entry, including case; wildcard expansion and IP/CIDR equivalence do not satisfy the reference. Specify exactly one of `value` or `secretRef`. The header value is used as supplied, including any `Bearer ` prefix, and replaces an existing header of the same name. Avoid trailing newlines in credential files; empty or unsafe values fail configuration generation.

**A Secret reference does not keep the credential out of Envoy configuration.** vArmor reads the Secret when processing the policy and includes the resolved value in the Envoy listener configuration (`lds.yaml`). This configuration is stored in a vArmor-generated Secret and mounted as a file in the sidecar. Anyone with permission to read that Secret or mounted file can access the credential.

## Rotate and verify

1. Update the source Secret through your credential-management process.
2. Trigger a real, valid policy **spec** update. Changing the source Secret alone does not update the proxy configuration. A harmless rule-description change can provide a spec update without changing the authorization criteria; inspect the resulting generation/status.
3. Check for policy processing errors, then wait for the configuration files to update and the proxy to load them. Verify a new request at an owned backend using a non-sensitive indicator; do not print the credential.
4. Confirm allowed and denied requests still behave as intended. Revoke the previous credential only after verification and any required overlap period.

Missing Secrets/keys, empty values or unsafe values can yield `phase: Error`, `ready: false`. On a failed update, the affected namespace keeps its last valid configuration: a requested tightening and credential rotation have **not** taken effect. Fix the dependency and trigger another valid spec update. A cluster policy does not provide atomic publication or rollback across namespaces.

Plan credential rotation around existing connections and application trust reloads. See [Lifecycle and Upgrades](lifecycle-and-upgrades.md).
