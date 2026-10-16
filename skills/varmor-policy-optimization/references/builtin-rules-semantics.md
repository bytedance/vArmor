# 内置规则语义参考

用于理解和校验用户策略中已有内置规则。每条给出**用途**与**误伤风险**；不得仅凭规则名称猜测，
不得因为读到本参考就扩充策略规则，任何规则取舍都以用户提供和确认为准。

规则分三类。标注的 enforcer 为其实际生效层（部分规则虽出现在某清单，但实际由其他 enforcer
执行）。

## 版本边界

- catalog 的 `catalogProvenance` 只记录取材来源，不要求集群版本精确相等。
- 官方 `v0.10.1`～`v0.10.5` 的 AppArmor/BPF/Seccomp 内置规则实现文件完全一致，均视为已验证
  兼容；比对日期、上游路径和各版本组 SHA-256 见 catalog 的
  `builtInRuleCompatibility.verificationEvidence`。
- `v0.10.0` 仅缺少 `copy-fail-mitigation`；策略不使用该规则时，不因此阻断其他内置规则。
- 其他或无法识别的版本标记为 `unknown`，只对实际使用的内置规则提示核验，不泛化为整份策略
  不兼容。NetworkProxy 的功能和日志版本另见
  [violation-log.md](violation-log.md)。

## 一、hardeningRules（系统加固）

| 规则 | 用途 | 误伤风险 | enforcer |
|---|---|---|---|
| disallow-write-core-pattern | 禁止改 `/proc/sys/kernel/core_pattern`（常见逃逸路径） | 正常业务几乎不用，低 | AppArmor/BPF |
| disallow-mount-securityfs | 禁止挂载 securityfs | 正常业务几乎不用，低 | AppArmor/BPF |
| disallow-mount-procfs | 禁止新挂载/重挂 procfs | 依赖挂载的初始化/边车可能受影响 | AppArmor/BPF |
| disallow-write-release-agent | 禁止写 cgroup release_agent | 正常业务不用，低 | AppArmor/BPF |
| disallow-mount-cgroupfs | 禁止新挂载/重挂 cgroupfs | 依赖 cgroup 手动挂载的组件受影响 | AppArmor/BPF |
| disallow-debug-disk-device | 禁止读写动态识别的宿主磁盘设备 | 存储/磁盘类插件可能受影响 | AppArmor/BPF |
| disallow-mount-disk-device | 禁止挂载宿主磁盘设备 | 存储类组件受影响 | AppArmor/BPF |
| disallow-mount | 禁止 mount 系统调用 | 需要挂载的初始化容器会被拦；默认基线在 privileged=false 时已含类似限制 | AppArmor/BPF |
| disallow-umount | 禁止 umount | 需卸载的组件受影响 | AppArmor/BPF |
| disallow-insmod | 禁用 CAP_SYS_MODULE | 需加载内核模块的组件（某些网络/存储插件）被拦 | AppArmor/BPF |
| disallow-load-bpf-prog | 禁止加载高权限 eBPF（保留 socket/cgroup 类型） | 依赖 eBPF 的网络/可观测组件受影响 | AppArmor/BPF |
| disallow-access-procfs-root | 禁止 ptrace read（用于访问 `/proc/<pid>/root`） | 调试/跨容器诊断、共享 PID 的边车受影响 | AppArmor/BPF |
| disallow-access-kallsyms | 禁止读 `/proc/kallsyms` | 性能/诊断、某些 tracer 读取符号会受影响 | AppArmor/BPF |
| disallow-abuse-user-ns | 禁用借 user namespace 获得的 CAP_SYS_ADMIN | 需 user namespace 的 rootless/沙箱组件受影响 | AppArmor/BPF |
| disallow-create-user-ns | 禁止创建 user namespace | rootless/隔离类组件受影响 | **Seccomp** |
| disallow-load-all-bpf-prog | 禁止任意 eBPF 加载 | 任何依赖 eBPF 的组件都受影响 | **Seccomp** |
| disallow-load-bpf-via-setsockopt | 禁止 setsockopt 加载 cBPF | 依赖老式 socket filter 的组件受影响 | **Seccomp** |
| disallow-userfaultfd-creation | 禁止 userfaultfd | 极低，通常仅漏洞利用使用 | **Seccomp** |

能力规则（同属 hardening 选择，AppArmor/BPF）：

| 规则 | 用途 / 风险 |
|---|---|
| disable-cap-all | 禁用全部能力 → 最严；任何需要非默认能力的操作都会触发日志 |
| disable-cap-all-except-net-bind-service | 仅保留 NET_BIND_SERVICE（<1024 端口）；需其他能力的操作触发日志 |
| disable-cap-privileged | 禁用特权能力集合，保留容器运行时默认能力 |

> 注：`disable-cap-[CAP]` 是**规则族占位符，不是可写入 CRD 的规则 ID**。要禁用单个能力时，
> 从 catalog 的 capability 规则集合中选择具体 ID（如 `disable-cap-net-raw`），仅当该能力审计
> 事件出现时才归因，不能从文件/挂载操作推断；不要把 `disable-cap-[CAP]` 字符串直接写入策略。

## 二、attackProtectionRules（攻击防护）

| 规则 | 用途 | 误伤风险 | enforcer |
|---|---|---|---|
| mitigate-sa-leak | 禁止读 ServiceAccount token/CA/namespace | **需访问 apiserver（如 operator、client-go、k8s 探针、leader 选举）的工作负载会被拦**，最常见误伤 | AppArmor/BPF |
| mitigate-disk-device-number-leak | 禁止读 `/proc/partitions`、mountinfo | `mount`/`df` 及读取 mountinfo 的库受影响 | AppArmor/BPF |
| mitigate-overlayfs-leak | 禁止读 mounts/mountinfo | 同上；mount 命令受影响 | AppArmor/BPF |
| mitigate-host-ip-leak | 禁止读 ARP 表 | 网络诊断、读取 `/proc/net/arp` 的组件受影响 | AppArmor/BPF |
| disable-write-etc | 禁止写 `/etc` | **运行时要写 `/etc` 的应用（写 resolv/hosts、配置、证书）会被拦**，常见误伤 | AppArmor/BPF |
| disable-access-passwd | 禁止读写 `/etc/passwd` | 需读 passwd 的 NSS/用户管理受影响 | AppArmor/BPF |
| disable-access-shadow | 禁止访问 `/etc/shadow` | 一般低 | AppArmor/BPF |
| disable-access-ssh-dir | 禁止访问 `.ssh` | 需要 SSH/密钥的组件受影响 | AppArmor/BPF |
| disable-write-skills | 禁止写 skills 目录 | 应用要写该目录时受影响 | **仅 AppArmor** |
| disable-busybox | 禁执行 busybox | **alpine/busybox 基础镜像、运行时用 busybox 调试会被拦**，常见误伤 | AppArmor/BPF |
| disable-shell | 禁 sh/bash/dash | 启动脚本用 shell、需要 exec shell 的会被拦；常有软链到 busybox | AppArmor/BPF |
| disable-wget | 禁 wget | 启动时用 wget 拉配置/健康检查会被拦 | AppArmor/BPF |
| disable-curl | 禁 curl | 启动时用 curl 拉配置/健康检查会被拦 | AppArmor/BPF |
| disable-chmod | 禁执行 chmod 程序 | 启动脚本 chmod 会被拦 | AppArmor/BPF |
| disable-chmod-x-bit | 禁止设置可执行位 | 需运行时 chmod +x（下载后执行）会被拦 | **Seccomp** |
| disable-chmod-s-bit | 禁止设置 SUID/SGID | 一般低 | **Seccomp** |
| disable-su-sudo | 禁 su/sudo | 提权脚本受影响 | AppArmor/BPF |
| disable-network | 禁一切网络 | **任何联网服务都被拦**，最严，仅适合完全离线计算 | AppArmor/BPF |
| disable-inet | 禁 IPv4 | 只影响 IPv4；纯 IPv6 不受影响 | AppArmor/BPF |
| disable-ipv4 | 禁 IPv4 | 同上（别名语义，以 catalog ID 为准） | AppArmor/BPF |
| disable-inet6 | 禁 IPv6 | 只影响 IPv6 | AppArmor/BPF |
| disable-ipv6 | 禁 IPv6 | 同上 | AppArmor/BPF |
| disable-unix-domain-socket | 禁 UDS | **进程间大量使用 UDS（本地通信）的应用受影响** | AppArmor/BPF |
| disable-icmp | 禁 ICMP | ping/健康检查用 ICMP 受影响 | AppArmor/BPF |
| disable-tcp | 禁 TCP | TCP 服务被拦 | AppArmor/BPF |
| disable-udp | 禁 UDP | UDP 服务被拦 | AppArmor/BPF |
| block-access-to-kube-apiserver | 禁连 kube-apiserver | **需访问 apiserver 的工作负载被拦** | **仅 BPF** |
| block-access-to-container-runtime | 禁访问 docker/containerd/crio.sock | 需容器运行时 socket 的组件（CI/守护进程）受影响 | AppArmor/BPF |
| block-access-to-metadata-service | 禁常见云 metadata IP | 需要访问 metadata（取凭据/地域）的应用受影响 | **仅 BPF** |
| block-access-to-aws-metadata-service | 禁 AWS metadata IP | 需读 AWS metadata 的应用受影响 | **仅 BPF** |
| block-access-to-volc-metadata-service | 禁火山 metadata IP | 需读火山 metadata 的应用受影响 | **仅 BPF** |
| block-access-to-alibaba-metadata-service | 禁阿里 metadata IP | 需读阿里 metadata 的应用受影响 | **仅 BPF** |
| block-access-to-oci-metadata-service | 禁 OCI metadata IP | 需读 OCI metadata 的应用受影响 | **仅 BPF** |

归因边界：`disallow-access-procfs-root` 只匹配 ptrace read；`disable-shell/busybox/curl/wget/chmod`
只匹配对应可执行文件的 exec 行为，单纯 `getattr/open/read` 不成立。不要把这类少量明确边界扩展
成不完整的全量事件签名表；无法从官方规则实现确定表达的部分继续交给模型并保持 unmatched。

## 三、vulMitigationRules（漏洞缓解，临时补丁性质）

| 规则 | 用途 | 误伤风险 | enforcer |
|---|---|---|---|
| cgroups-lxcfs-escape-mitigation | 禁写 release_agent/devices.allow 等 cgroup 文件 | 手动管理 cgroup 的组件受影响 | AppArmor/BPF |
| runc-override-mitigation | 禁写 `/**/runc` | 一般低 | AppArmor/BPF |
| dirty-pipe-mitigation | 禁 splice | 大量使用 splice 的零拷贝/转发程序受影响 | **Seccomp** |
| ingress-nightmare-mitigation | 禁访问 ingress-nginx admission service | 一般低 | **仅 BPF** |
| copy-fail-mitigation | 禁 AF_ALG socket | 一般低 | AppArmor/BPF |

## 使用纪律

- 协助选规则 = 在用户同意的范围内，根据**目标行为是否会用到**该规则保护的对象来取舍；
  不确定业务是否会触发时，倾向先保留观察、用违规日志验证，而不是直接删规则。
- 能力类规则只能由 capability 审计事件证明，不从文件/网络操作推断。
- 本表解释“规则做什么、可能误伤谁”，不替代规则 ID 的确定性校验。
