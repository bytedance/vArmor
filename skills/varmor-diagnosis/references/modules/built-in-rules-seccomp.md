# Seccomp 内置规则实施

本指南解释 EnhanceProtect 内置规则由 Seccomp 实施的范围。基于当前 Agent 依赖的 vArmor v0.9.2 规则集整理。策略声明规则不代表已生效：还需确认 Seccomp Enforcer、最终 Pod `seccompProfile`、节点 profile 文件和目标 Workload 是否已重建。

优先关联 Seccomp audit 的 syscall、action、profile，进程的 `SIGSYS`/`Bad system call`，以及节点 agent 的 profile 写入结果。`EPERM` 不具备 Seccomp 专属性，必须与 syscall、时间和 Profile 闭合。`allowViolations=true` 且 `auditViolations=true` 时，内置规则生成 `LOG`；其他组合通常生成 `ERRNO`。

## 1. Seccomp 规则映射

当前内置规则仅有以下七项：

| 规则 ID | 生成的 syscall 限制 |
|---|---|
| `disallow-create-user-ns` | `unshare` 的第 0 个参数命中 `CLONE_NEWUSER`。 |
| `disallow-load-all-bpf-prog` | `bpf` 的第 0 个参数等于 `BPF_PROG_LOAD`。 |
| `disallow-load-bpf-via-setsockopt` | `setsockopt` 的 level 为 `SOL_SOCKET`，optname 为 `SO_ATTACH_FILTER` 或 `SO_ATTACH_REUSEPORT_CBPF`。 |
| `disallow-userfaultfd-creation` | `userfaultfd`。 |
| `dirty-pipe-mitigation` | `splice`。 |
| `disable-chmod-x-bit` | `chmod`、`fchmod`、`fchmodat`、`fchmodat2` 的 mode 参数命中任一执行位。 |
| `disable-chmod-s-bit` | `chmod`、`fchmod`、`fchmodat`、`fchmodat2` 的 mode 参数命中 SUID 或 SGID 位。 |

## 2. 不由 Seccomp 实施的规则

未列在本指南中的内置规则不会由 Seccomp 生成约束，应按实际规则归属检查 AppArmor 或 BPF。

带 `attackProtectionRules.targets` 的规则不会生成 Seccomp 限制；指定可执行文件的限制只由 AppArmor child profile 实施。
