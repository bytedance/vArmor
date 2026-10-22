# Policy modes and default Profiles

This guide distinguishes generated Profiles from injected Pod settings in the current implementation. Use it to explain why protection exists or is absent when a policy has no built-in/custom rules. Verify behavior against the deployed version, VP/VCP, AP, Pod references, and loaded node Profiles.

## 1. AlwaysAllow

AlwaysAllow is vArmor's control mode without additional mandatory access controls: AppArmor uses an Allow template, the BPF Profile is empty, and Seccomp defaults to `ALLOW`. It does not disable Kubernetes, the runtime, the Linux kernel, or other independent security mechanisms, which may still deny application operations.

## 2. RuntimeDefault

RuntimeDefault generates vArmor runtime baselines for AppArmor/BPF:

- AppArmor: restricts some `/proc` writes, `/proc/sysrq-trigger`, `/proc/*/mem`, `/proc/kmem`, `/proc/kcore`, and sensitive `/sys` paths; restricts mount and cross-Profile ptrace.
- BPF: restricts `/proc/sysrq-trigger`, `/proc/*/mem`, `/proc/kmem`, `/proc/kcore`, and sensitive `/sys` paths; adds mount restrictions and restricts ptrace read/trace.
- Seccomp: the injector sets `seccompProfile.type: RuntimeDefault`, selecting the container runtime's default filter. Separately, the AP generator creates an `ALLOW` Profile for compatibility with existing Pods that still reference the previous Localhost path after a mode switch. That generated file does not prove the actual Pod uses an allow-all filter; inspect its final `seccompProfile` and lifecycle.

## 3. EnhanceProtect

EnhanceProtect is Allow-by-Default with user-selected built-in and custom rules. With no explicit rules:

- `privileged=false`: AppArmor/BPF still include the RuntimeDefault baseline from section 2.
- `privileged=true`: AppArmor/BPF use an AlwaysAllow template/empty Profile without that baseline.
- Seccomp: generated Profiles default to `ALLOW`; restrictions are added only when actual Seccomp built-in or custom syscall rules exist.

The policy's `enhanceProtect.privileged` flag selects the AppArmor/BPF baseline; it does not set container `securityContext.privileged`. Do not infer Seccomp absence from this flag alone. The current generator still builds Seccomp content when that enforcer is selected, while injection skips containers that are actually privileged or explicitly Seccomp-Unconfined.

`allowViolations` and `auditViolations` change how EnhanceProtect rules/baselines block and audit; they do not determine whether AppArmor/BPF include a baseline. Seccomp observation uses `LOG` for matched rules only when both flags are true; other combinations usually use `ERRNO`.

## 4. BehaviorModeling

Before modeling completes, AppArmor/BPF/Seccomp use `Complain` semantics to collect behavior. Seccomp defaults to `LOG` and explicitly allows basic file syscalls. After completion, this mode returns to AlwaysAllow/empty Profiles; it does not automatically become Deny-by-Default.

Its output is ArmorProfileModel (APM). For allowlist protection, verify that the APM was generated and referenced by a subsequent DefenseInDepth policy.

## 5. DefenseInDepth

DefenseInDepth is Deny-by-Default and has no universal fixed baseline. It uses a behavior model or user-provided AppArmor/Seccomp Profile as an allowlist, then adds corresponding custom rules:

- AppArmor: loads an APM or custom AppArmor Profile and can append AppArmor Raw Rules.
- Seccomp: loads an APM or custom Seccomp Profile, defaults to `ERRNO` in enforcement and `LOG` with `allowViolations=true`, and can append syscall Raw Rules.
- BPF: DefenseInDepth is rejected during policy validation/admission, with an additional guard in Profile generation.

BehaviorModeling and DefenseInDepth are experimental. The current implementation includes BPF behavior collection, but BPF DefenseInDepth remains unsupported; NetworkProxy supports DefenseInDepth with its own rules and does not support BehaviorModeling. Prioritize APM/Profile source, mode completion state, and final action when diagnosing these modes. For NetworkProxy, use its dedicated rule semantics rather than an AppArmor/Seccomp baseline.
