---
sidebar_position: 1
sidebar_label: Enforcers
---

# Enforcers: overview and selection

Choose an enforcer from the behavior you need to control, then check the node and workload prerequisites. An enforcer supplies the enforcement mechanism; a policy mode and its rules determine the permitted behavior.

| Goal | Start with | Main consideration |
| --- | --- | --- |
| Restrict file access and program execution | [AppArmor](apparmor.md) or [BPF](bpf.md) | The corresponding Linux LSM must be enabled on the nodes |
| Restrict system calls | [Seccomp](seccomp.md) | Changes to the profile require new containers |
| Restrict socket operations and destination IPs/ports at the kernel layer | [BPF](bpf.md) | Kernel and runtime prerequisites apply; this does not inspect HTTP paths |
| Restrict HTTP requests or TLS destinations; inspect HTTPS using MITM | [NetworkProxy](networkproxy/index.md) | Injected containers, traffic redirection and, for MITM, application trust are required |

## Choose a mode and scope

Use [Policy Modes](../policies_and_rules/policy_modes/index.md) to select a supported mode. `EnhanceProtect` adds targeted restrictions; `DefenseInDepth` uses an allowlist where supported. `BehaviorModeling` is experimental and must be enabled explicitly; it is not supported with NetworkProxy. BPF does not support `DefenseInDepth`.

A `VarmorPolicy` selects workloads in its namespace. A `VarmorClusterPolicy` has cluster scope and takes precedence over a matching namespaced policy. Start with a dedicated namespace and a narrow target. See [Writing Policies](../policies_and_rules/writing_policies.md).

## Combining enforcers

Supported combinations, such as `AppArmorSeccomp` and `AppArmorNetworkProxy`, can address different behaviors within one policy. Each component still has its own prerequisites, update behavior and audit semantics. A combination does not make an unsupported mode available, and permission at one enforcement layer does not override a denial at another.

Consult the [enforcer field reference](../../getting_started/interface_specification.md#policy) before choosing a combination. NetworkProxy acts on redirected traffic in the Pod network namespace; do not infer per-container network isolation from the container selection available to other enforcers.

## Next steps

1. Check [Installation](../../getting_started/installation.md) for environment requirements and enabled components.
2. Follow [Writing Policies](../policies_and_rules/writing_policies.md) to build and verify a policy.
3. Use [Usage Instructions](../../getting_started/usage_instructions.md) for status and operations, and [Metrics](../../getting_started/metrics.md) for component monitoring.
