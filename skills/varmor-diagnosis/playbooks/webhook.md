# Webhook Injection Validation (Webhook)

Follow the [shared conventions](README.md) for execution and authorization. The checkpoints and example commands below are optional;
reuse known facts and select fields and branches for the current issue. Do not run every step or fill every output item.

## Objective
Validate Admission Webhook configuration, availability, and matching rules. Distinguish requests that do not match, Webhooks not called, failures allowed through, and successful injection later overwritten.

## When to use
- Policy/AP healthy but the target Pod has no signs of vArmor injection
- Webhook errors occur during Workload creation
- Some Pods are injected and others are not
- New Pods do not receive new configuration after a policy update

## Prerequisites
- Known vArmor installation namespace (<varmor-namespace>; confirm from actual deployment objects)
- Known target namespace and Workload name

---

## 1. Webhook configuration existence

```bash
# List all vArmor-related Webhook configurations
kubectl get mutatingwebhookconfigurations | grep -i varmor
kubectl get validatingwebhookconfigurations | grep -i varmor

# Inspect the full Webhook configuration (replace <webhook-name>)
kubectl get mutatingwebhookconfiguration <mutating-webhook-name> -o yaml
kubectl get validatingwebhookconfiguration <validating-webhook-name> -o yaml
```

**Key fields:**
| Field | Meaning |
|---|---|
| `webhooks[*].rules` | Matching API group/version/resource/operation |
| `webhooks[*].namespaceSelector` | Namespace label selector |
| `webhooks[*].objectSelector` | Object label selector |
| `webhooks[*].failurePolicy` | Fail/Ignore: block or allow when the call fails |
| `webhooks[*].clientConfig.service` | Webhook Service reference (namespace/name/path/port) |
| `webhooks[*].clientConfig.caBundle` | CA certificate; must be nonempty and valid for TLS |

### 1.1 Validate matching rules

```bash
# List every webhook entry in all MutatingWebhookConfiguration objects; do not assume the target is webhooks[0]
kubectl get mutatingwebhookconfigurations -o go-template='{{range .items}}{{$config := .metadata.name}}{{range .webhooks}}{{$config}}{{"\t"}}{{.name}}{{"\t"}}{{.clientConfig.service.namespace}}{{"/"}}{{.clientConfig.service.name}}{{":"}}{{.clientConfig.service.port}}{{"\n"}}{{end}}{{end}}' | grep -i varmor
# Select configurations and specific webhook entries whose clientConfig.service.namespace points to <varmor-namespace>
# Stale Webhooks from an old installation often reference a deleted namespace or a different installation instance
MUTATING_WEBHOOK=<select-the-webhook-whose-service-points-to-varmor-namespace>
MUTATING_WEBHOOK_ENTRY=<selected-webhook-entry-name>
echo "Selected MutatingWebhook: $MUTATING_WEBHOOK / $MUTATING_WEBHOOK_ENTRY"
# Select the exact entry and output all its rules; stop on no match or duplicates rather than silently choosing the first item
kubectl get mutatingwebhookconfiguration "$MUTATING_WEBHOOK" -o json | WEBHOOK_ENTRY="$MUTATING_WEBHOOK_ENTRY" python3 -c "
import json, os, sys
obj = json.load(sys.stdin)
name = os.environ['WEBHOOK_ENTRY']
matched = [w for w in obj.get('webhooks', []) if w.get('name') == name]
if len(matched) != 1:
    print(f'WEBHOOK_ENTRY_ERROR: expected one entry named {name}, found {len(matched)}')
    sys.exit(1)
w = matched[0]
print('FAILURE_POLICY=' + str(w.get('failurePolicy', '')))
print('NS_SELECTOR=' + json.dumps(w.get('namespaceSelector', {}), separators=(',', ':')))
print('OBJ_SELECTOR=' + json.dumps(w.get('objectSelector', {}), separators=(',', ':')))
for i, rule in enumerate(w.get('rules', [])):
    print(f'RULE[{i}] apiGroups={rule.get(\"apiGroups\", [])} apiVersions={rule.get(\"apiVersions\", [])} resources={rule.get(\"resources\", [])} operations={rule.get(\"operations\", [])}')
"
```

**Matching-rule checklist:**
1. Do API groups/versions/resources cover the target Workload type (such as `apps/v1/deployments` or `v1/pods`)?
2. Do operations include CREATE (and UPDATE if update-time injection is supported)?
3. Does namespaceSelector require labels, and does the target namespace have them?
4. Does objectSelector require labels, and does the target Pod/Workload satisfy the matching fields in the actual WebhookConfiguration, deployment configuration, and version? Do not assume a fixed annotation or label value as a universal default.
5. Is failurePolicy Fail or Ignore? Ignore silently allows requests without injection when calls fail.

---

## 2. Webhook Service and endpoints

```bash
# Inspect the Webhook Service
kubectl -n <varmor-namespace> get svc | grep -E 'webhook|manager'

# Inspect Service details
kubectl -n <varmor-namespace> get svc <webhook-service-name> -o jsonpath='TYPE={.spec.type}{"\t"}SELECTOR={.spec.selector}{"\n"}{range .spec.ports[*]}PORT_NAME={.name}{"\t"}PORT={.port}{"\t"}TARGET_PORT={.targetPort}{"\n"}{end}'

# Check for Endpoints
kubectl -n <varmor-namespace> get endpoints <webhook-service-name> -o jsonpath='{range .subsets[*]}ADDRESSES={.addresses[*].ip}{"\t"}PORTS={.ports[*].port}{"\n"}{end}'

# If Endpoints are absent, query Pods using the Service's own selector rather than an assumed label key
# Convert the selector map to comma-separated key=value pairs for -l
SVC_SELECTOR_RAW=$(kubectl -n <varmor-namespace> get svc <webhook-service-name> -o go-template='{{range $k,$v := .spec.selector}}{{$k}}={{$v}}{{","}}{{end}}') ||
  { echo "SERVICE_QUERY_FAILED: cannot read webhook Service selector"; return 1 2>/dev/null || exit 1; }
SVC_SELECTOR_L=$(printf '%s' "$SVC_SELECTOR_RAW" | sed 's/,$//')
echo "Service selector: $SVC_SELECTOR_L"
[ -n "$SVC_SELECTOR_L" ] && kubectl -n <varmor-namespace> get pods -l "$SVC_SELECTOR_L" --show-labels || echo "Cannot resolve service selector to label query; list manager pods manually"
```

**Interpretation:**
- Service absent -> stale Webhook configuration or installation issue
- Empty Endpoints (no subsets or empty addresses) -> manager Pods unready or Service selector mismatch
- Endpoint addresses present but Pods not Ready -> failed health checks or startup in progress
- Service and endpoints healthy -> establishes configuration and endpoint existence only; actual API Server-to-Webhook connectivity still requires request errors or call evidence

---

## 3. TLS certificate validation

```bash
# Extract the CA Bundle from the selected webhook entry; inspect certificate metadata only
WEBHOOK_JSON=$(kubectl get mutatingwebhookconfiguration "$MUTATING_WEBHOOK" -o json) ||
  { echo "WEBHOOK_QUERY_FAILED: cannot read selected configuration"; return 1 2>/dev/null || exit 1; }
CA_BUNDLE=$(printf '%s' "$WEBHOOK_JSON" | WEBHOOK_ENTRY="$MUTATING_WEBHOOK_ENTRY" python3 -c "
import json, os, sys
obj = json.load(sys.stdin)
matched = [w for w in obj.get('webhooks', []) if w.get('name') == os.environ['WEBHOOK_ENTRY']]
if len(matched) != 1:
    sys.exit('WEBHOOK_ENTRY_ERROR: cannot uniquely select CA bundle')
print(matched[0].get('clientConfig', {}).get('caBundle', ''))
") || { echo "CA_BUNDLE_SELECTION_FAILED"; return 1 2>/dev/null || exit 1; }
if [ -z "$CA_BUNDLE" ]; then
  echo "CA_BUNDLE_EMPTY"
else
  CERT_META=$(printf '%s' "$CA_BUNDLE" | base64 -d | openssl x509 -noout -text 2>/dev/null) ||
    { echo "CA_BUNDLE_DECODE_FAILED"; return 1 2>/dev/null || exit 1; }
  printf '%s\n' "$CERT_META" | head -20
fi

# Inspect certificate mounts in manager
kubectl -n <varmor-namespace> get deploy <manager-deploy-name> -o jsonpath='{range .spec.template.spec.volumes[*]}{.name}{"\t"}{.secret.secretName}{"\n"}{end}' | grep -i cert
kubectl -n <varmor-namespace> get secrets | grep -iE 'webhook|cert|tls'
```

**Symptoms of certificate issues:**
- Admission error `x509: certificate signed by unknown authority`
- Admission error `x509: certificate is valid for ... not ...`
- Connection timeout or connection refused
- Empty or expired caBundle

---

## 4. Quick Webhook connectivity checks

```bash
# Prefer existing failed Admission request errors, events, and manager logs; do not create test Pods
# First check namespace matching labels
kubectl get ns <namespace> --show-labels

# Method 2: test Webhook port reachability through port-forward (L3; execute only with authorization)
# Confirm the target, port, and path from the actual WebhookConfiguration/Service; use one target, short timeouts, and an overall deadline.
# Save the port-forward PID and clean up on completion or timeout; do not use -k to skip certificate verification by default.
# This example illustrates the flow without prescribing a fixed port or path:
# kubectl -n <varmor-namespace> port-forward svc/<webhook-service-name> <local-port>:<service-port> &
# PF_PID=$!
# timeout <seconds> curl --connect-timeout <seconds> --max-time <seconds> https://127.0.0.1:<local-port>/<confirmed-path>
# PF_STATUS=$?; kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; exit "$PF_STATUS"

# Method 3: read bounded Admission logs from relevant manager instances; identify candidates using component.md.
# Webhook investigations need not identify the reconcile Leader first.
kubectl -n <varmor-namespace> logs <manager-pod> -c <manager-container> --since=<duration> --tail=200
# Filter locally by request time, target object, and admission/webhook/mutate/validate/inject.
```

---

## 5. Distinguish four missing-injection scenarios

| Scenario | Evidence | Next step |
|---|---|---|
| **Request does not match** | Webhook rules/selectors do not match the target; namespace labels or target objectSelector labels are missing | Check labels and matching rules; see target validation in [policy.md](policy.md) |
| **Webhook not called** | Service has no Endpoints, certificate error, network failure, or port mismatch | Repair Service/Endpoint/certificate; see manager checks in [component.md](component.md) |
| **Call failed but request allowed** | failurePolicy=Ignore with manager errors; no Webhook-related records in target events | Inspect manager logs and causes, then restore Webhook availability |
| **Injection overwritten** | Admission response shows injection but the final object lacks fields, or another admission/controller later rewrites the object | Inspect other Mutating Webhook patches, `reinvocationPolicy`, and subsequent controllers; Webhook call order has no universally configurable priority |

### 5.1 Check PodTemplate injection

```bash
# Replace <workload-kind> with the actual resource type: deploy, statefulset, or daemonset
# Inspect injection evidence in the target Workload PodTemplate; start with relevant fields and add other nonsensitive fields only if needed
kubectl -n <namespace> get <workload-kind> <workload-name> -o jsonpath='CONTAINERS={.spec.template.spec.containers[*].name}{"\n"}INIT_CONTAINERS={.spec.template.spec.initContainers[*].name}{"\n"}POD_SECCOMP={.spec.template.spec.securityContext.seccompProfile.type}{"/"}{.spec.template.spec.securityContext.seccompProfile.localhostProfile}{"\n"}POD_APPARMOR={.spec.template.spec.securityContext.appArmorProfile.type}{"/"}{.spec.template.spec.securityContext.appArmorProfile.localhostProfile}{"\n"}{range .spec.template.spec.containers[*]}CTR_SECCOMP[{.name}]={.securityContext.seccompProfile.type}{"/"}{.securityContext.seccompProfile.localhostProfile}{"\n"}CTR_APPARMOR[{.name}]={.securityContext.appArmorProfile.type}{"/"}{.securityContext.appArmorProfile.localhostProfile}{"\n"}{end}'

# List every annotation key (keys only, no values), without grep filtering or binary signal output.
# Establish vArmor injection using multiple signals such as initContainer/sidecar/securityContext;
# annotation keys containing apparmor/seccomp/varmor alone are insufficient.
kubectl -n <namespace> get <workload-kind> <workload-name> -o go-template='{{range $k,$v := .spec.template.metadata.annotations}}{{$k}}{{"\n"}}{{end}}'

# Look for the following injection evidence:
# AppArmor: container.apparmor.security.beta.kubernetes.io/<container> (standard Kubernetes annotation key) or spec.securityContext.appArmorProfile (Pod/Container level)
# Seccomp: spec.securityContext.seccompProfile (type=Localhost) (Pod/Container level)
# BPF: vArmor-specific annotation keys (version-dependent; list keys first, then confirm against the AP profileName)
# NetworkProxy: proxy annotation keys, initContainer (<proxy-init-name>), sidecar (<proxy-sidecar-name>), certificate volumes
# Discover candidate annotation keys first, then read only necessary nonsensitive values (such as Profile references); confirm ownership through policy, configuration, and the actual version.
```

---

## Optional summary points
A Webhook summary may include:
1. Whether Webhook configurations exist and rules/selectors cover the target
2. Service/Endpoint status and ports
3. failurePolicy setting
4. Certificate validity
5. Which of the four scenarios explains injection failure
6. Likely overwrite source if injection was overwritten
7. Next direction
