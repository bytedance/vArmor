# BPF 内置规则实施

本指南解释 EnhanceProtect 内置规则由 BPF 实施的范围。基于当前 Agent 依赖的 vArmor v0.9.2 规则集整理。策略声明规则不代表已生效：还需确认 BPF Enforcer、BPF LSM/BTF 等节点能力、Profile load/attach 和目标节点处理结果。

优先关联 agent 的 load/attach 日志、BPF audit、AP 中的文件/进程/网络/挂载规则和节点内核能力。`allowViolations/auditViolations` 会影响拒绝或审计行为，但不改变规则归属。

## 1. BPF 规则映射

| 规则组 | 规则 ID | 实施要点 |
|---|---|---|
| 特权逃逸与挂载 | `disallow-write-core-pattern`、`disallow-write-release-agent` | 分别限制 core_pattern、release_agent 写入。 |
| 特权逃逸与挂载 | `disallow-mount-securityfs`、`disallow-mount-procfs`、`disallow-mount-cgroupfs`、`disallow-mount-disk-device`、`disallow-mount`、`disallow-umount` | 生成 BPF mount 约束；新挂载限制通常仅在 `enhanceProtect.privileged=true` 时额外需要，proc/cgroup 还限制危险重新挂载或卸载。 |
| 特权逃逸与挂载 | `disallow-debug-disk-device` | 对动态识别的磁盘设备生成读写限制。 |
| 能力与内核攻击面 | `disallow-insmod`、`disallow-load-bpf-prog`、`disallow-abuse-user-ns` | 分别限制 `CAP_SYS_MODULE`、`CAP_SYS_ADMIN`/`CAP_BPF`、`CAP_SYS_ADMIN`。 |
| 能力与内核攻击面 | `disable-cap-all`、`disable-cap-all-except-net-bind-service`、`disable-cap-privileged`、`disable-cap-*` | 生成 capability bitmap 限制。 |
| Proc/ptrace | `disallow-access-procfs-root`、`disallow-access-kallsyms` | 分别限制 ptrace read、读取 `/proc/kallsyms`。 |
| 信息泄露 | `mitigate-sa-leak`、`mitigate-disk-device-number-leak`、`mitigate-overlayfs-leak`、`mitigate-host-ip-leak` | 由 BPF 文件路径规则实施。 |
| 信息泄露 | `disallow-access-k8s-sensitive-files` | 限制读取 Kubernetes 配置、`~/.kube/config` 和 Secret volume 路径；当前策略优化任务表单不提供此规则，但诊断已有策略时仍应识别。 |
| Metadata 网络 | `block-access-to-metadata-service`、`block-access-to-aws-metadata-service`、`block-access-to-volc-metadata-service`、`block-access-to-alibaba-metadata-service`、`block-access-to-oci-metadata-service` | 生成到对应 metadata IP 的 connect 限制。 |
| 文件与命令 | `disable-write-etc` | 生成 BPF 文件读写限制。 |
| 文件与命令 | `disable-busybox`、`disable-shell`、`disable-wget`、`disable-curl`、`disable-chmod`、`disable-su-sudo` | 生成对相应路径的执行限制；`shell` 覆盖 sh/bash/dash。 |
| 网络与运行时 | `disable-network`、`disable-inet`/`disable-ipv4`、`disable-inet6`/`disable-ipv6`、`disable-unix-domain-socket`、`disable-icmp`、`disable-tcp`、`disable-udp` | 生成 socket create 或协议限制。 |
| 网络与运行时 | `block-access-to-kube-apiserver`、`ingress-nightmare-mitigation` | 依赖服务出站控制可用及 Kubernetes Service/Endpoint 解析；服务不存在或能力未启用时应查生成日志和 AP 内容。 |
| 网络与运行时 | `block-access-to-container-runtime` | 限制 containerd、Docker、CRI-O socket 的读写。 |
| 漏洞缓解 | `cgroups-lxcfs-escape-mitigation`、`runc-override-mitigation` | 分别限制 cgroup 关键文件写入、`runc` 写入。 |

## 2. 不由 BPF 实施的规则

`disallow-create-user-ns`、`disallow-load-all-bpf-prog`、`disallow-load-bpf-via-setsockopt`、`disallow-userfaultfd-creation`、`dirty-pipe-mitigation`、`disable-chmod-x-bit`、`disable-chmod-s-bit` 在当前 BPF 生成器中没有等效 hook 实现，应检查 Seccomp Profile。

带 `attackProtectionRules.targets` 的内置规则不会生成 BPF 限制；指定可执行文件的细粒度限制只由 AppArmor child profile 实施。
