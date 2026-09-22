---
sidebar_position: 2
---

# Policy semantics

Configure rules under `spec.policy.enhanceProtect.networkProxyRawRules.egress` in `EnhanceProtect`, or `spec.policy.defenseInDepth.networkProxy.egress` in `DefenseInDepth`. `AlwaysAllow` and `RuntimeDefault` do not supply an application HTTP allowlist; NetworkProxy does not support `BehaviorModeling`.

## Defaults, qualifiers and combinations

- `defaultAction: allow`: requests/connections are allowed unless a deny rule matches.
- `defaultAction: deny`: an allow rule must match, and no deny rule may match.
- `deny` takes precedence over `allow`, regardless of YAML order.
- `audit` selects logging; it does not grant permission under default deny. `allowViolations` does not override these NetworkProxy decisions.
- Use `allow`, `deny`, `audit`, `allow,audit` or `deny,audit` as appropriate. Do not combine `allow` and `deny` in one rule.

Within one rule, different specified criteria are combined with **AND**. Values within a criterion list are **OR**. Rules within an allow or deny group are **OR**; unrelated parts of different rules are not combined into a new rule.

**L4 and HTTP allow rules are alternative authorizations where both apply.** An L4 allow for an entire destination subnet/port can permit requests that do not match an HTTP allow rule. Do not add a broad L4 allow as a presumed prerequisite for a narrow HTTP allowlist. Matching deny rules still take precedence.

For example, default deny plus only an HTTP allow for `GET /public/` limits visible HTTP to that rule. Adding an L4 allow for the server's IP and port also authorizes its other requests unless explicitly denied.

## What a rule matches

| Field | Plain HTTP or MITM | TLS passthrough |
| --- | --- | --- |
| `rules[].ip` / `cidr` / `ports` | Original destination address and port | Original destination address and port |
| `httpRules[].match.hosts` | HTTP Host / `:authority` | TLS SNI |
| `httpRules[].match.ports` | Actual destination port; see HTTP Host port requirements below | Actual destination port |
| `paths` | Normalized URL path | Ignored |
| `methods` | Exact, case-sensitive method token | Ignored |

A passthrough HTTP rule with no `hosts` produces no SNI permission. A rule with a host and restrictive path/method still authorizes or denies TLS by its host/port criteria alone. Configure MITM before depending on HTTPS path/method restrictions.

Host and SNI matching ignore case. Exact hosts and wildcard suffix hosts are supported; `*.example.com` excludes the bare `example.com` and unrelated suffixes such as `example.com.attacker.test`. HTTP/SNI rule wildcard matching and TLS certificate wildcard validity are different checks: an MITM wildcard certificate covers one DNS label, not an arbitrary number. Use explicit names when the intended boundary is narrow.

`methods: [GET]` does not match `get` or `GeT`. Custom methods are supported and must also use the exact case sent by the client.

Paths are case-sensitive. `prefix: /api` also matches `/apix`; use `/api/` for a subtree and an additional exact `/api` rule if needed. URL path matching excludes the query string. HTTP processing normalizes paths, merges repeated slashes and unescapes escaped slash/backslash separators before authorization and forwarding. Verify the normalized path at your backend if it has its own path interpretation.

Ports are destination ports, not a value a caller may spoof in Host. For explicit non-default ports, the HTTP Host must also contain the matching port. Prefer a normal client URL containing the destination port; changing only `Host: ...:443` cannot make a connection to another port satisfy a port-443 rule.

## Traffic handling and MITM scope {#chain-selection-and-mitm-scope}

`mitm.domains` selects traffic for decryption; it is **not an allowlist**. HTTP/L4 authorization still determines whether an intercepted request is forwarded.

The destination IP, TLS SNI and protocol determine whether traffic is intercepted. Configuring an IP for MITM does not change HTTP rule enforcement for plaintext requests to that IP.

| Situation | Expected processing |
| --- | --- |
| Plain HTTP to a configured MITM IP | HTTP rules still apply |
| TLS with a configured DNS SNI, including at a configured MITM IP | Decrypt HTTPS for that DNS name and apply HTTP rules |
| TLS to a configured MITM IP without SNI | Decrypt HTTPS for that IP and apply HTTP rules |
| TLS outside applicable MITM scope | TLS passthrough rules; encrypted HTTP remains invisible |
| Non-HTTP, non-TLS TCP | TCP rules |

## Domain-fronting boundary

MITM checks the decrypted request destination: Host in HTTP/1.1 or `:authority` in HTTP/2. Connections intercepted by DNS name can request only configured DNS destinations; connections intercepted by IP can request only configured IP destinations. Requests outside the corresponding scope normally receive a 404 and are not forwarded upstream. Requests within scope must still satisfy HTTP/L4 rules.

This does **not** require downstream SNI and HTTP Host to be identical. If A and B are both configured DNS MITM destinations, SNI=A with Host=B may proceed under B's rules. For interception by IP, the destination IP and HTTP Host are not required to be identical either.

For upstream MITM TLS, Envoy derives SNI and certificate identity validation from the routed HTTP authority. The upstream connection still uses the original destination address; this does not resolve Host to a new IP or establish a DNS-to-IP binding. TLS passthrough cannot perform these decrypted Host checks.

See [Observability](observability.md) for the separate audit decision and [TLS and Credentials](tls-and-credentials.md) for MITM identity/trust constraints.
