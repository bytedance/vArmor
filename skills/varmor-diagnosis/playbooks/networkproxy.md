# NetworkProxy-Specific Checks (NetworkProxy)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Investigate NetworkProxy by layer: injection -> startup -> forwarding -> rules -> HTTPS -> bypass. In sidecar/Envoy deployments, injected proxy components provide the applicable L4/L7, SNI, or TLS MITM capabilities; confirm capabilities and injection layout against the actual version and Pod configuration.

## When to use
- Policy includes the NetworkProxy enforcer
- Pod creation fails due to initContainer/sidecar/Secret/certificate issues
- Egress connection failures, TLS errors, or abnormal HTTP requests
- L7 rules (path/method) do not take effect
- HTTPS rules do not take effect

## Prerequisites
- Known target namespace and Pod name
- Known policy type (VP/VCP), policy name, and VP namespace

---

## 1. Injection layer

Confirm that the Pod has complete NetworkProxy injection evidence.

```bash
# 1. Annotation keys only; do not output values
# proxy can discover candidates but also matches Istio/Linkerd annotations; a match alone does not establish ownership.
# Assess candidate keys against policy profileName, component images, and configuration references; selectively read nonsensitive values if needed
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}'

# 2. initContainer (traffic redirection): list name + image for all initContainers
# vArmor NetworkProxy initContainer images use the deployment registry and names match deployment configuration
kubectl -n <namespace> get pod <pod-name> -o jsonpath='INIT_CONTAINERS={range .spec.initContainers[*]}{.name}{"("}{.image}{") "}{end}{"\n"}'

# 3. sidecar (Envoy proxy): list name + image for all containers
kubectl -n <namespace> get pod <pod-name> -o jsonpath='CONTAINERS={range .spec.containers[*]}{.name}{"("}{.image}{") "}{end}{"\n"}'

# 4. Proxy configuration volumes (Secrets/certificates): list name + secretName + configMapName for all volumes
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.volumes[*]}{.name}{"\t"}{.secret.secretName}{"\t"}{.configMap.name}{"\n"}{end}'

# 5. Container environment variable names only; never print sensitive CA/certificate/token values
# proxy/ca/cert/port can discover candidates; read necessary switch/port values selectively and do not expose sensitive values
# List all env names directly, or inspect only the confirmed proxy sidecar container's env
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}{.name}{":\n"}{range .env[*]}{"  "}{.name}{"\n"}{end}{end}'
```

**Injection-layer symptoms:**
- Missing initContainer -> Webhook did not inject NetworkProxy components
- Missing sidecar -> incomplete Webhook injection
- Missing Secret volume -> proxy configuration/certificate not mounted; Pod startup may fail
- All absent -> no NetworkProxy injection; return to [webhook.md](webhook.md)

---

## 2. Startup layer

Confirm that initContainer and sidecar start correctly.

```bash
# Pod and per-container status
kubectl -n <namespace> get pod <pod-name> -o jsonpath='PHASE={.status.phase}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}READY={.ready}{"\t"}RESTARTS={.restartCount}{"\t"}STATE={.state}{"\n"}{end}{range .status.initContainerStatuses[*]}INIT={.name}{"\t"}READY={.ready}{"\t"}STATE={.state}{"\n"}{end}'

# initContainer failure details (choose duration based on failure time)
kubectl -n <namespace> logs <pod-name> -c <proxy-init-name> --since=<duration> --tail=50

# Sidecar status and logs
kubectl -n <namespace> logs <pod-name> -c <proxy-sidecar-name> --since=<duration> --tail=100

# Pod events
kubectl -n <namespace> describe pod <pod-name> | grep -A30 "Events:"
```

**Common startup-layer issues:**
- **initContainer CrashLoop**: Usually iptables redirection failure; check NET_ADMIN and node iptables/nftables compatibility
- **Sidecar not Ready**: Envoy configuration load failure, certificate error, or port conflict
- **Secret not found**: Manager has not propagated the proxy configuration Secret, or the Secret name mismatches
- **Insufficient resources**: Sidecar OOMKilled; inspect resources configuration

---

## 3. Forwarding layer

First use init logs, relevant configuration, and existing connection/access logs to determine whether traffic passes through the sidecar.
If evidence is insufficient, briefly inspect listening state in the confirmed sidecar; assess risk using both container identity and the actual command.

```bash
# Targeted read-only inspection; select the container explicitly for exec and bound duration through the execution tool.
kubectl -n <namespace> exec <pod-name> -c <proxy-sidecar-name> -- ss -tln
# Use netstat if ss is unavailable; do not install tools. Interpret results against confirmed ports.
```

First confirm ProxyUID, proxyAdminPort, and bypass settings from the actual policy/Pod/proxy configuration; relevant nonsensitive values may be read.
Before checking redirection rules, confirm network namespace/view and permissions; query specific chains read-only rather than dumping all rules.
Active tests from application containers generate real requests. Use user-authorized targets, request methods, and ports with bounded connection and total time;
do not assume arbitrary application URLs have no side effects:

```bash
# Use only when necessary and current authorization covers the specific request.
kubectl -n <namespace> exec <pod-name> -c <app-container> -- curl --connect-timeout 5 --max-time 10 http://<confirmed-test-target>:<port>/<confirmed-path>
```

**Forwarding-layer symptoms:**
- Connection timeout/refusal: Possible redirection, proxy-rule, destination-service, or network cause; correlate logs with confirmed rules
- Proxy loop: Incorrect ProxyUID redirects the sidecar's own traffic
- Admin-port bypass failure: Incorrect proxyAdminPort prevents bypass

---

## 4. Rule layer

Confirm correct distribution and matching of L4/L7 rules.

Prefer actual policy rules, proxy configuration-loading logs, and relevant access events. Use admin endpoints only with confirmed address, port,
access authorization, and need; select relevant statistics or configuration sections with bounded connection/total time and output size.
Do not export entire config_dump or all stats by default. Assess admin-interface requests by the specific action; mutation endpoints are prohibited.
If tools cannot target output, assess the full response size and save locally for redacted analysis when needed.

```bash
kubectl -n <namespace> logs <pod-name> -c <proxy-sidecar-name> --since=<duration> --tail=200
```

**Key rule-layer concepts:**
- Establish matching layers and disposition from qualifiers, precedence, and configuration supported by the deployed version; conceptual L4/SNI/L7 order alone cannot determine the final action
- L4 rules: IP/CIDR + port
- SNI/host rules: TLS SNI or HTTP Host header
- HTTP rules match host, path, method, and destination port. Arbitrary header matching is not exposed by the current CRD; MITM header mutation is a separate feature. Encrypted HTTP fields require TLS MITM
- In the current implementation, matching deny rules take precedence, and L4/HTTP allow rules are alternative authorizations where both apply. A broad L4 allow can permit requests that miss a narrow HTTP allow. Confirm deployed-version semantics and `defaultAction`
- When no rule matches, `defaultAction` determines the action
- See `../references/troubleshooting/enforcer-conflicts.md` for detailed rule layers and conflict handling

**Common rule issues:**
- L7 path/method rules do not affect HTTPS without TLS MITM (only SNI matching is available)
- Rule text order is not execution priority; validate final actions through qualifiers, precedence, matching layers, and `defaultAction`
- Confirm `defaultAction` values and unmatched behavior from the actual policy and version; the field name alone does not determine every flow's final action
- Do not misinterpret an L7 rule mismatch as an L4 network failure

---

## 5. HTTPS/TLS MITM layer

Confirm MITM settings from actual policy/proxy configuration, then inspect application-container CA references and mounts. Prefer relevant env/volume
configuration in PodSpec; only if runtime differences matter, inspect one known CA path or nonsensitive variable directly.
Do not read all environment variables before filtering, or expose certificate private keys or credentials. Active HTTPS tests follow the forwarding layer's request authorization,
target, and timeout conventions; do not skip certificate verification by default.

**HTTPS interpretation:**
- Certificate validation error (x509: certificate signed by unknown authority) -> inspect CA injection, application trust store, and actual certificate chain
- Connection reset/EOF -> MITM configuration issue or sidecar not handling CONNECT
- TLS handshake failure -> certificate/protocol-version/cipher mismatch
- **Without TLS MITM, HTTPS L7 path/method rules do not take effect**; only SNI matching is available

---

## 6. Bypass layer

Determine whether traffic bypasses the proxy.

```bash
# Inspect bypass-related annotation keys only; do not output values
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}' | grep -iE 'bypass|exclude|ignore'

# Common bypass paths:
# 1. NET_ADMIN: Other containers with NET_ADMIN may modify iptables to bypass the proxy
# 2. ProxyUID: Traffic from the sidecar's own UID bypasses redirection
# 3. proxyAdminPort: Admin-port traffic bypasses the proxy
# 4. Pod CIDR/cluster-internal traffic: Usually bypassed, depending on configuration
# 5. localhost/127.0.0.1: Usually bypassed
```

---

## 7. Policy NetworkProxy configuration validation

Return to the policy object to verify configuration:

Reuse the VP/VCP obtained earlier and locate NetworkProxy configuration using the actual CRD, policy mode, and version.
Include the policy namespace for VP and omit it for VCP. Do not generalize example field paths to all versions.
Inspect relevant rules, qualifiers/precedence, defaultAction, listening ports, ProxyUID, TLS MITM, and bypass configuration;
read nonsensitive values if necessary. For Secrets, inspect only references, mounts, and certificate metadata; do not expose credentials or private keys.

---

## Optional summary points
A NetworkProxy summary may include:
1. Which of the six layers is affected (injection/startup/forwarding/rules/HTTPS/bypass)
2. Container status (init/sidecar/app)
3. Certificate/Secret mounts
4. Whether traffic redirection works
5. Rule types (L4/SNI/L7) and defaultAction
6. Whether TLS MITM is enabled
7. Sidecar log errors and access records
8. Next direction
