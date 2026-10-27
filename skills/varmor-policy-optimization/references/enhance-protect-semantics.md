# EnhanceProtect Semantics: Rule Categories, Observation Mode, and Implicit Baseline

This file describes stable mode semantics only. The valid built-in rule set, enforcer compatibility matrix, and expansion of aggregate capability rules are
maintained in `scripts/data/builtin-rules-catalog.json` and are not duplicated here.

## 1. EnhanceProtect rule sources

EnhanceProtect is Allow-by-Default: rules are layered onto a base Profile. There are two rule sources.

### 1.1 Built-in rules (referenced by name)

| Field | Structure | Description |
|---|---|---|
| `hardeningRules` | `[]string` | Hardening: escape paths, capability management, mount/kernel-interface restrictions |
| `vulMitigationRules` | `[]string` | Vulnerability mitigation: block exploitation chains for specific vulnerabilities |
| `attackProtectionRules` | `[]{rules, targets}` | Attack protection; rules in a group share optional `targets` |

`attackProtectionRules.targets` applies only to **AppArmor**, restricting rules to specified executables and their child
processes through AppArmor sub-Profiles. It **does not provide equivalent per-process BPF restrictions**.

`hardeningRules` and `vulMitigationRules` have no rule-level `targets`; do not invent them during attribution.

### 1.2 Custom rules (RawRules; see raw-rules-syntax.md)

`appArmorRawRules`, `bpfRawRules`, `syscallRawRules`, `networkProxyRawRules`.

## 2. Observation mode

Two switches under `enhanceProtect` control observation of built-in rules and the AppArmor/BPF baseline:

```yaml
enhanceProtect:
  auditViolations: true
  allowViolations: true
```

For AppArmor/BPF built-in rules and their baseline:

| allowViolations | auditViolations | Behavior | action |
|---|---|---|---|
| false | false | Block without proactive logging | No event |
| false | true | Block and log | `DENIED` |
| true | true | Allow and log | `AUDIT` |
| true | false | Allow without logging | No event |

The observation configuration is `auditViolations=true` + `allowViolations=true` (log violations without blocking).
The validator fills both switches and explicitly reports this normalization as an adjustment rather than silently changing them.

### Seccomp-specific behavior

- Built-in Seccomp rules generate `SCMP_ACT_LOG` only when both switches are true; all other combinations generate `SCMP_ACT_ERRNO`, even with `allowViolations=true`. vArmor records observation events as `AUDIT|ALLOWED`, not `AUDIT`. When BehaviorModeling is active, verify its audit-event routing before relying on observation logs.
- However, **`syscallRawRules` actions are user-defined**: actions other than `SCMP_ACT_ALLOW/LOG` (such as ERRNO, KILL*, TRAP, TRACE, NOTIFY) may actually block during observation. The script reports risk notices without rewriting them.
- Seccomp events carry syscall names without arguments; for example, they cannot distinguish chmod setting executable bits from SUID/SGID bits.

NetworkProxy rules use their own qualifiers and `defaultAction`; these two switches do not put NetworkProxy into observation mode. An `audit` qualifier alone does not authorize traffic under `defaultAction=deny`.

## 3. Implicit baseline (important blind spot)

When `privileged=false` (the default), EnhanceProtect **implicitly includes the RuntimeDefault baseline for AppArmor/BPF**. This does not add a Seccomp syscall blocklist or a NetworkProxy baseline:

- The baseline is absent from policy rule fields, so **deleting rules cannot remove it**; the guard also prohibits changing it.
- If an event is attributed to the baseline but matches no atomic policy rule, list it separately as "baseline-originated (rule deletion ineffective)"
  and leave the structural decision to the user (accept the restriction or set `privileged=true`).
- With policy `privileged=true`, AppArmor/BPF use AlwaysAllow/empty base Profiles, removing that baseline. This flag does not grant container privileges or change `securityContext.privileged`.
- **Seccomp requires separate verification**: the API documentation describes a Seccomp exclusion for this flag, but the `internal/profile/profile.go` / `internal/profile/seccomp/seccomp.go` generators in `v0.10.5` and the `v0.10.6` release candidate revision recorded in the catalog still build Seccomp content when that enforcer is selected. The injector skips Seccomp for actually privileged containers or explicit Seccomp-Unconfined settings. Inspect the deployed generator, AP content, and final Pod `securityContext`; do not promise that changing this policy flag disables Seccomp.

Establish rule ownership and the effective enforcer from generation logic. For example, `disallow-create-user-ns` appears in the hardening
list but generates no AppArmor/BPF rules; Seccomp actually filters `unshare(CLONE_NEWUSER)`.
