# AppArmor 内置规则实施

本指南解释 EnhanceProtect 内置规则由 AppArmor 实施的范围。基于当前 Agent 依赖的 vArmor v0.9.2 规则集整理。策略声明规则不代表已生效：还需确认 AppArmor 已启用、Profile 已生成并加载、Pod 已引用对应 Profile。

优先关联 AppArmor audit 的 profile、operation、name/path、denied_mask、action，以及 AP 和节点 agent 的加载状态。`allowViolations/auditViolations` 会影响拒绝或审计行为，但不改变规则归属。

## 1. AppArmor 规则映射

| 规则组 | 规则 ID | 实施要点 |
|---|---|---|
| 特权逃逸与挂载 | `disallow-write-core-pattern` | 禁止写 `/proc/sys/kernel/core_pattern`。 |
| 特权逃逸与挂载 | `disallow-mount-securityfs`、`disallow-mount-procfs`、`disallow-mount-cgroupfs`、`disallow-mount`、`disallow-umount` | 限制相应文件系统或挂载操作；`procfs/cgroupfs` 还限制危险的 bind/rbind/move/remount 组合。 |
| 特权逃逸与挂载 | `disallow-write-release-agent`、`disallow-debug-disk-device`、`disallow-mount-disk-device` | 分别限制 cgroup `release_agent` 写入、动态识别的磁盘设备读写、动态识别的磁盘设备挂载。 |
| 能力与内核攻击面 | `disallow-insmod`、`disallow-load-bpf-prog`、`disallow-abuse-user-ns` | 分别限制 `CAP_SYS_MODULE`、`CAP_SYS_ADMIN`/`CAP_BPF`、`CAP_SYS_ADMIN`。 |
| 能力与内核攻击面 | `disable-cap-all`、`disable-cap-all-except-net-bind-service`、`disable-cap-privileged`、`disable-cap-*` | 生成 capability 限制；`disable-cap-*` 中 `*` 是具体 capability 名称，例如 `disable-cap-net-raw`。 |
| Proc/ptrace | `disallow-access-procfs-root`、`disallow-access-kallsyms` | 分别限制 ptrace read、读取 `/proc/kallsyms`。 |
| 信息泄露 | `mitigate-sa-leak`、`mitigate-disk-device-number-leak`、`mitigate-overlayfs-leak`、`mitigate-host-ip-leak` | 分别限制 ServiceAccount 文件、`partitions/mountinfo`、`mounts/mountinfo`、`/proc/*/net/arp` 的读取。 |
| 文件与命令 | `disable-write-etc` | 限制 `/etc` 写入。 |
| 文件与命令 | `disable-busybox`、`disable-shell`、`disable-wget`、`disable-curl`、`disable-chmod`、`disable-su-sudo` | 限制对应可执行文件；`shell` 覆盖 sh/bash/dash。镜像中软链接或 BusyBox applet 的实际路径会影响命中。 |
| 网络与运行时 | `disable-network`、`disable-inet`/`disable-ipv4`、`disable-inet6`/`disable-ipv6`、`disable-unix-domain-socket`、`disable-icmp`、`disable-tcp`、`disable-udp` | 限制 AppArmor network 族、类型或协议。 |
| 网络与运行时 | `block-access-to-container-runtime` | 限制 containerd、Docker、CRI-O socket 的读写。 |
| 漏洞缓解 | `cgroups-lxcfs-escape-mitigation`、`runc-override-mitigation` | 分别限制 cgroup 关键文件写入、`runc` 写入。 |

## 2. 不由 AppArmor 实施的规则

`disallow-create-user-ns`、`disallow-load-all-bpf-prog`、`disallow-load-bpf-via-setsockopt`、`disallow-userfaultfd-creation`、`dirty-pipe-mitigation`、`disable-chmod-x-bit`、`disable-chmod-s-bit` 不由 AppArmor 内置规则实现，应检查 Seccomp Profile。

`attackProtectionRules.targets` 仅 AppArmor 支持：会为指定可执行文件创建 child profile。应同时确认父 Profile 到 child profile 的执行切换和实际 executable 路径。
