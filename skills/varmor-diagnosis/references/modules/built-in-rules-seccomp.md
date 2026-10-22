# Seccomp built-in rule implementation

This guide maps the Seccomp implementation of the vArmor v0.9.2 EnhanceProtect reference rule set; verify additions against the deployed version. Declaring a rule does not prove enforcement: verify the Seccomp enforcer, final Pod `seccompProfile`, node Profile file, and workload recreation.

Correlate Seccomp audit syscall/action/profile, process `SIGSYS`/`Bad system call`, and node-agent file-write results. `EPERM` is not Seccomp-specific; establish syscall, time, and Profile correlation. Built-in rules use `LOG` when both `allowViolations=true` and `auditViolations=true`; other combinations usually use `ERRNO`.

## 1. Seccomp rule mapping

The reference set contains these seven rules:

| Rule ID | Generated syscall restriction |
|---|---|
| `disallow-create-user-ns` | Argument 0 of `unshare` matches `CLONE_NEWUSER`. |
| `disallow-load-all-bpf-prog` | Argument 0 of `bpf` equals `BPF_PROG_LOAD`. |
| `disallow-load-bpf-via-setsockopt` | `setsockopt` uses level `SOL_SOCKET` and optname `SO_ATTACH_FILTER` or `SO_ATTACH_REUSEPORT_CBPF`. |
| `disallow-userfaultfd-creation` | `userfaultfd`. |
| `dirty-pipe-mitigation` | `splice`. |
| `disable-chmod-x-bit` | The mode argument of `chmod`, `fchmod`, `fchmodat`, or `fchmodat2` contains any execute bit. |
| `disable-chmod-s-bit` | The mode argument of `chmod`, `fchmod`, `fchmodat`, or `fchmodat2` contains a SUID or SGID bit. |

## 2. Rules not implemented by Seccomp

Built-in rules not listed here do not generate Seccomp restrictions. Inspect AppArmor or BPF according to actual rule ownership.

Rules with `attackProtectionRules.targets` do not generate Seccomp restrictions; executable-specific restrictions are implemented only by AppArmor child profiles.
