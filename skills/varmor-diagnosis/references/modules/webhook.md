# vArmor Admission Webhook

## 1. Two webhook types

- **MutatingWebhook**: Handles target Workload/Pod creates or updates and injects AppArmor/BPF/Seccomp Profile references. For NetworkProxy, it also injects initContainer, sidecar, Secret/volumes, redirection, and TLS MITM settings.
- **ValidatingWebhook**: Validates VP/VCP targets, mode-required fields, enforcer combinations, NetworkProxy parameters, immutable fields, and other semantic constraints.

The manager serves webhooks, but configuration, Service, endpoints, certificates, and object matching form a separate evidence chain.

## Admission and controllers

Webhooks process admission requests entering the API server; they do not proactively modify existing Pods. Deployment, StatefulSet, and DaemonSet injection usually appears in the PodTemplate first, then in Pods created by their controllers. Bare Pods are injected directly in PodSpec. Distinguish unmatched requests, no webhook invocation, failed calls allowed through, injected templates with unreplaced old Pods, and injected Pods without node loading.

Assess WebhookConfiguration rules, namespace/object selectors, failurePolicy, Service/endpoints, and CA bundle together with the manager Deployment's actual service capability. Configuration existence does not prove requests reach the manager, and successful calls do not prove the final Pod retains expected fields.

## 2. Matching conditions

For "policy exists but no injection", check more than the policy selector:

- API group/version/resource and operation are covered by webhook rules;
- Namespace/object selectors match;
- Workload kind agrees with `spec.target.kind`;
- Workload/Pod labels meet matching fields declared by the deployed configuration; do not assume fixed annotations or label values as universal defaults;
- VP namespace matches the request namespace; identify VCP/VP overlap. The current injector checks VCPs first and selects one matching policy; verify deployed behavior rather than assuming rule merging;
- target.name/selector, the container list, and explicit `unconfined` settings do not change the expected result.

## 3. Observation points after injection

AppArmor may appear in both compatibility annotations and Kubernetes SecurityContext. For Seccomp, inspect `type` and `localhostProfile`; BPF commonly uses a vArmor annotation. NetworkProxy should include proxy annotations, initContainer, sidecar, configuration/certificate volumes, and required container CA mounts/env.

Do not infer actual Pods from the workload template alone. Inspect final Pod spec, owner, creation time, and whether it came from the new template.

## 4. Failure modes

### Missing configuration or unmatched rules

Policy/workload requests succeed without injection or validation. Common causes include upgrade leftovers, inconsistent configuration names, uncovered API requests, or selector/label mistakes.

### Unavailable Service/endpoints

The API server cannot call the manager. Interpret impact using the actual `failurePolicy`: the current local vArmor implementation generates Mutating/Validating Webhooks with `Ignore`, but deployments or other versions may differ. `Fail` blocks matching requests; `Ignore` permits them and may silently lose injection/validation.

### TLS/CA/Service path errors

Typical errors mention connection, x509, certificate, timeout, or no endpoint. Check CA bundle, Service reference/address, port, path, and manager readiness. Do not attribute every admission rejection to policy syntax.

### Existing targets

Webhooks primarily affect admission requests. Existing Pods do not gain injection automatically when webhook configuration recovers. Check `updateExistingWorkloads` and actual workload kind to determine rollout behavior.

## 5. Recommendations only

Use final object state and webhook configuration to distinguish unmatched requests, no invocation, call failures, and injection overwritten afterward. For webhook, certificate, matching-label changes, or Pod recreation, provide risks, affected scope, and verification points only; do not execute.
