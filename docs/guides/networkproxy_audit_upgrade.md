# NetworkProxy audit selection and upgrades

## Event semantics

Enforcement and rule classification are unchanged. At each logging location,
the renderer emits one access logger selected by:

`(defaultAction == deny AND actual RBAC denial) OR matching audit shadow rule`

The deny condition is **not** enabled for an allow-default policy. In that
mode, a deny without a matching audit rule remains silent. If an independent
audit rule also matches a denied request, the selected event is DENIED.
Two enabled conditions use an Envoy `or_filter` with independent CEL
children, not two loggers or a combined CEL expression.

New configurations use `varmor_np_event:<profileName>`. The sink determines
the action for each entry, including mixed outcomes within the same ALS batch:

- L7: `response.response_code_details` starting with `rbac_access_denied`
  means DENIED.
- L4: `common_properties.connection_termination_details` with that prefix
  means DENIED.
- Other selected events are AUDIT. HTTP 403 alone does not imply denial by
  vArmor; an upstream 403 remains AUDIT.

Legacy `varmor_np_deny` and `varmor_np_audit` streams are still accepted.
Legacy deny entries stay DENIED even without a reason; legacy audit entries
are now classified by their reason. Old configurations with two loggers can
still emit duplicates until regenerated and reloaded.

One logger prevents duplicate emission when both predicates match at a single
logging location. It is not an end-to-end exactly-once delivery guarantee:
HTTP/MITM records are per request, and passthrough TLS/TCP records per connection.
Buffering, delivery failure and independent logging locations are unchanged.

## Kubernetes rollout: consumers before configuration producers

**Old sinks reject the new `varmor_np_event` class. Do not roll out the new
Manager together with old Agent or embedded sinks.**

1. Keep the old Manager running so it continues to generate legacy log names.
   Upgrade every Agent that receives NetworkProxy ALS streams.
2. Upgrade every embedded NetworkProxy sink in existing Kata/VCI workloads.
   The sink binary is bundled in the NetworkProxy sidecar image. Changing a
   default image tag only affects future injection; existing workload Pods
   must be updated/recreated with the new image. Ensure all consumers of
   each shared configuration have been upgraded, including workloads whose
   owning controller still has the old sidecar image.
3. Only then upgrade the Manager. Regenerate/reconcile the affected profiles,
   verify that the resulting LDS uses the event class, and verify Envoy has
   loaded it. Recheck violation logs for both an allowed audited request and
   a policy-denied request.

This change does not automatically orchestrate the above rollout. A
simultaneous all-component image update does not guarantee the required order.
Plan workload disruption and validation before applying it to a cluster.

For rollback, first restore legacy rendered configurations and verify all
Envoys have loaded them; only then downgrade Agents or embedded sinks. Retaining
the new consumers with legacy configurations is compatible.
