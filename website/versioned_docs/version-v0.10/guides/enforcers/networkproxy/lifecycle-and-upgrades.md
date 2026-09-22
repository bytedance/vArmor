---
sidebar_position: 5
---

# Lifecycle and upgrades

Separate three things when planning a change: policy reconciliation, projected Envoy configuration, and the Kubernetes Pod template. A change to one does not imply the others have converged.

## Change matrix

| Change | Required checks/actions |
| --- | --- |
| HTTP/L4 rules in an already injected Pod | Reconcile the policy, wait for dynamic configuration, verify new requests; no blanket zero-error transition guarantee |
| Source Secret value for a header | Perform a valid policy spec update after the Secret update; verify the newly injected value without printing it |
| Add/remove MITM identities in a Pod already equipped for MITM | Verify LDS/CDS/certificate and validation SDS convergence, trust and new requests |
| Enable MITM for a Pod without TLS volumes | Update/rebuild the workload template so new Pods receive TLS mounts and CA configuration; inspect actual injection |
| Replace a CA or its trust bundle | Verify proxy/application files, then reload or restart applications that cache trust |
| Change static bootstrap | Ensure the generated bootstrap is updated, then restart Envoy or recreate the Pod |
| Change proxy image or resource settings | Inspect/update the injected workload template and roll out replacement Pods; a default setting alone does not change existing containers |
| Change UID or proxy/admin port | Immutable policy fields: plan a replacement policy/workload migration and verify its new redirection |
| Repair a previously injected template | Explicitly repair the stored template; a normal rule update is not a template repair operation |

Successful same-Pod dynamic-update regression checks exercised new requests after checking projection and actual behavior. They do not promise immediate revocation of established connections, atomic multi-file updates, or availability while clusters/listeners are converging. A temporary 503 can indicate an upstream cluster or trust dependency not yet available.

## Upgrade vArmor and its proxy together

Use images corresponding to the release, with a new tag or immutable digest for changed image content. `IfNotPresent` is compatible with immutable tags; reusing a tag can leave different nodes running different binaries. Check the deployed Manager/Agent revision, injected image specification and runtime image ID rather than relying on Helm's app version alone.

For upgrades that introduce the `varmor_np_event` audit stream, upgrade consumers before producers:

1. Upgrade node Agents while the old Manager still produces compatible configurations.
2. Upgrade embedded sinks in micro-VM sidecars, including existing workload templates/Pods.
3. Upgrade the Manager, regenerate affected configurations through reconciliation, and verify proxy reload and audit delivery.

Do not send new stream names to old consumers. An image-default change does not replace old embedded sinks, and a Manager upgrade alone does not prove every existing configuration Secret has been regenerated.

Custom HTTP method handling also uses a static bootstrap runtime setting as well as LDS options. After upgrading, confirm the generated bootstrap has been refreshed and recreate affected proxies before relying on custom method handling. Policy method tokens are case-sensitive in v0.10.5: use `GET` if that is the intended method, rather than a lowercase spelling previously normalized by older code.

## Recover an old non-root template

The fixed injection paths explicitly set both injected containers to `runAsUser: 0` and `runAsNonRoot: false`, while leaving application security contexts intact. Previously stored templates may still lack those fields. Their existing injection annotation can prevent fresh webhook injection.

A normal HTTP rule update was observed **not** to repair such a Deployment template. Upgrading the Manager or restarting from an unchanged template is therefore insufficient.

For an affected Deployment, review this targeted strategic-merge patch, substituting your namespace and workload name. It preserves the other container fields:

```bash
kubectl patch deployment YOUR_DEPLOYMENT -n YOUR_NAMESPACE --type=strategic -p '
{"spec":{"template":{"spec":{
  "initContainers":[{"name":"varmor-network-proxy-init","securityContext":{"runAsUser":0,"runAsNonRoot":false}}],
  "containers":[{"name":"varmor-network-proxy","securityContext":{"runAsUser":0,"runAsNonRoot":false}}]
}}}}'
kubectl rollout status deployment/YOUR_DEPLOYMENT -n YOUR_NAMESPACE
```

Use it only when those injected container names already exist. Inspect the resulting template and a newly created Pod; verify application identity, actual Envoy process UID and allowed/denied requests. Confirm a later Pod recreation also succeeds. The documented cluster recovery verified Deployments; do not claim the same live test was run for every controller kind.

## Remove a policy deliberately

`updateExistingWorkloads` affects controller-managed workload updates on policy creation/deletion. Review [Usage Instructions](../../../getting_started/usage_instructions.md) and the [API](../../../getting_started/interface_specification.md) before relying on it. Inspect the resulting template and replacement Pods to confirm sidecars, mounts and routing are removed as intended.

Deleting a policy does not constitute proof that existing connections or injected standalone Pods have been reset. For the isolated Quick Start, delete its dedicated namespace. For production, plan and verify replacement Pods and connectivity before considering withdrawal complete.
