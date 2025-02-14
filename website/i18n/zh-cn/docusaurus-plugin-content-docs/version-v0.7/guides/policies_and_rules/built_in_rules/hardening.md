---
sidebar_position: 1
description: 减少系统攻击面的规则。
---

# 容器加固

## 加固具有特权的容器
### `disallow-write-core-pattern`

禁止改写 procfs 的 core_pattern。

:::note[说明]
攻击者可能会在特权容器（**Privileged Container**）中，通过改写 procfs core_pattern，来实施容器逃逸。或者在特权容器（**w/ CAP_SYS_ADMIN**）中，卸载特定挂载点后改写 procfs core_pattern，来实施容器逃逸。
:::

:::info[原理与影响]
禁止修改 procfs 的 core_pattern。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-mount-securityfs`

禁止挂载 securityfs。

:::note[说明]
攻击者可能会在特权容器（**w/ CAP_SYS_ADMIN**）中，以读写权限挂载新的 securityfs 并对其进行修改。
:::

:::info[原理与影响]
禁止挂载新的 securityfs。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-mount-procfs`

禁止重新挂载 procfs。

:::note[说明]
攻击者可能会在特权容器（**w/ CAP_SYS_ADMIN**）中，以读写权限重新挂载 procfs，然后再通过改写 core_pattern 等方式进行容器逃逸、修改系统配置。
:::

:::info[原理与影响]
1. 禁止挂载新的 procfs。
2. 禁止使用 bind, rbind, move, remount 选项重新挂载 `/proc**`。
3. 使用 BPF enforcer 时，还将禁止卸载 `/proc**`。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-write-release-agent`

禁止改写 cgroupfs 的 release_agent。

:::note[说明]
攻击者可能会在特权容器（**Privileged Container**）中，通过改写 cgroupfs release_agent，来实施容器逃逸。
:::

:::info[原理与影响]
禁止修改 cgroupfs 的 release_agent。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-mount-cgroupfs`

禁止重新挂载 cgroupfs。

:::note[说明]
攻击者可能会在特权容器（**w/ CAP_SYS_ADMIN**）中，以读写权限重新挂载 cgroupfs。然后再通过改写 release_agent、设备访问权限等方式进行容器逃逸、修改系统配置。
Attackers may attempt to escape from containers (**w/ CAP_SYS_ADMIN**) by remounting cgroupfs with read-write permissions. Subsequently, they can modify release_agent and device access permissions, among other things.
:::

:::info[原理与影响]
1. 禁止挂载新的 cgroupfs。
2. 禁止使用 bind, rbind, move, remount 选项重新挂载 `/sys/fs/cgroup**`。
3. 禁止使用 rbind 选项重新挂载 `/sys**`。
4. 使用 BPF enforcer 时，还将禁止卸载 `/sys**`。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-debug-disk-device`

禁止调试磁盘设备。

:::note[说明]
攻击者可能会在特权容器（**Privileged Container**）中，通过调试宿主机磁盘设备，从而实现宿主机文件的读写。

建议配合 [disable-cap-mknod](#disable-cap-cap) 使用，从而防止攻击者利用 mknod 创建新的设备文件，从而绕过此规则。
:::

:::info[原理与影响]
动态获取宿主机磁盘设备文件，并禁止在容器内以读写权限访问。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-mount-disk-device`

禁止挂载宿主机磁盘设备并访问。

:::note[说明]
攻击者可能会在特权容器（**Privileged Container**）中，挂载宿主机磁盘设备，从而实现宿主机文件的读写。

建议配合 [disable-cap-mknod](#disable-cap-cap) 使用，从而防止攻击者利用 mknod 创建新的设备文件，从而绕过此规则。
:::

:::info[原理与影响]
动态获取宿主机磁盘设备文件，并禁止在容器内挂载。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-mount`

禁用 mount 系统调用。

:::note[说明]
[MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) 常被用于权限提升、容器逃逸等攻击。而几乎所有的微服务应用都无需 mount 操作，因此建议使用此规则限制容器内进程访问 mount 系统调用。

注：当 `spec.policy.privileged` 为 false 时，将默认禁用 `mount()` 系统调用。
:::

:::info[原理与影响]
禁用 mount 系统调用。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-umount`

禁用 umount 系统调用。

:::note[说明]
[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) 可被用于卸载敏感的挂载点（例如 maskedPaths），从而导致权限提升、信息泄露。而几乎所有的微服务应用都无需 umount 操作，因此建议使用此规则限制容器内进程访问 `umount()` 系统调用。
:::

:::info[原理与影响]
禁用 umount 系统调用。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::



### `disallow-insmod`

禁止加载内核模块。

:::note[说明]
攻击者可能会在特权容器中（**w/ CAP_SYS_MODULE**），通过执行内核模块加载命令 insmod，向内核中注入代码。
:::

:::info[原理与影响]
禁用 CAP_SYS_MODULE。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-load-bpf-prog`, `disallow-load-ebpf`

禁止加载除 BPF_PROG_TYPE_SOCKET_FILTER 和 BPF_PROG_TYPE_CGROUP_SKB 类型外的 eBPF 程序。

:::note[说明]
攻击者可能会在特权容器中（**w/ CAP_SYS_ADMIN, CAP_BPF**），加载 ebpf Program 实现数据窃取和创建 rootkit 后门。

在 Linux 5.8 之前，需要 CAP_SYS_ADMIN 才能加载除 BPF_PROG_TYPE_SOCKET_FILTER 和 BPF_PROG_TYPE_CGROUP_SKB 类型以外的 eBPF 程序。自 Linux 5.8 开始，需要 CAP_SYS_ADMIN 或 CAP_BPF 才能加载这些 eBPF 程序。与此同时，加载某些类型的 eBPF 程序还需要 CAP_NET_ADMIN 或 CAP_PERFMON。

注：规则 ID `disallow-load-ebpf` 将会被弃用，请使用 `disallow-load-bpf-prog`。
:::

:::info[原理与影响]
禁用 CAP_SYS_ADMIN 和 CAP_BPF。

推荐您使用内置规则 [disallow-load-all-bpf-prog](#disallow-load-all-bpf-prog) 来禁止容器加载任意类型的 eBPF 程序，从而减少内核攻击面。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-access-procfs-root`

禁止访问进程文件系统的根目录。

:::note[说明]
本策略禁止容器内进程访问进程文件系统的根目录（即 `/proc/[PID]/root`），防止攻击者利用共享 pid ns 的进程进行攻击。

攻击者可能会在共享了宿主机 pid ns、与其他容器共享 pid ns 的容器环境中，通过读写 `/proc/*/root` 来访问容器外的进程文件系统，实现信息泄露、权限提升、横向移动等攻击。
:::

:::info[原理与影响]
禁用 [PTRACE_MODE_READ](https://man7.org/linux/man-pages/man2/ptrace.2.html) 权限。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-access-kallsyms`

禁止读取内核符号文件。

:::note[说明]
攻击者可能会在特权容器中（**w/ CAP_SYSLOG**），通过读取内核符号文件来获取内核模块地址。从而绕过 KASLR 防护，降低内核漏洞的难度与成本。
:::

:::info[原理与影响]
禁止读取 `/proc/kallsyms` 文件。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


## 禁用能力

### `disable-cap-all`

禁用所有 capabilities。

:::note[说明]
禁用所有 capabilities
:::

:::info[原理与影响]
无
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disable-cap-all-except-net-bind-service`

禁用除 net_bind_service 外的 capabilities。

:::note[说明]
禁用除 net-bind-service 以外的 capabilities.

此规则符合 Pod Security Standards 的 [*Restricted Policy*](https://kubernetes.io/concepts/security/pod-security-standards/#restricted) 要求。
:::

:::info[原理与影响]
无
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disable-cap-privileged`

禁用特权 capability。

:::note[说明]
禁用所有的特权 capabilities（可直接造成逃逸、影响宿主机可用性的 capabilities），仅允许运行时的[默认 capabilities](https://github.com/containerd/containerd/blob/release/1.7/oci/spec.go#L115)。

此规则符合 Pod Security Standards 的 [*Baseline Policy*](https://kubernetes.io/concepts/security/pod-security-standards/#restricted) 要求，但 net_raw capability 除外。
:::

:::info[原理与影响]
无
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disable-cap-[CAP]`

禁用特定 capability。

:::note[说明]
禁用任意指定的 capabilities，请将 [CAP] 替换为 [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) 中的值，例如 disable-cap-net-raw。
:::

:::info[原理与影响]
无
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


## 阻断内核漏洞利用向量

### `disallow-abuse-user-ns`

禁止滥用 User Namespace。

:::note[说明]
User Namespace 可以被用于增强容器隔离性。但它的出现同时也增大了内核的攻击面，或使得某些内核漏洞更容易被利用。攻击者可以在容器内，通过创建 User Namespace 来获取全部特权，从而扩大内核攻击面。

禁止容器进程通过 User Namesapce 滥用 CAP_SYS_ADMIN 特权可降低内核攻击面，阻断部分内核漏洞的利用路径。在未设置 `kernel.unprivileged_userns_clone=0` 或 `user.max_user_namespaces=0` 的系统上，可通过此规则来为容器进行加固。

可参考下面的链接了解更多。
* [Security analysis of user namespaces and rootless containers](https://tore.tuhh.de/entities/publication/716d05a6-08ce-48e1-bec3-817eb15e2944)
* [CVE-2024-26808](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-26808_cos/docs/exploit.md)
* [CVE-2021-22555](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md)
:::

:::info[原理与影响]
禁用 CAP_SYS_ADMIN。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::


### `disallow-create-user-ns`

禁止创建 User Namespace。

:::note[说明]
User Namespace 可以被用于增强容器隔离性。但它的出现同时也增大了内核的攻击面，或使得某些内核漏洞更容易被利用。攻击者可以在容器内，通过创建 User Namespace 来获取全部特权，从而扩大内核攻击面。

禁止容器进程创建新的 User Namesapce 从而获取 CAP_SYS_ADMIN 特权可降低内核攻击面，阻断部分内核漏洞的利用路径。在未设置 `kernel.unprivileged_userns_clone=0` 或 `user.max_user_namespaces=0` 的系统上，可通过此规则来加固容器。

可参考下面的链接了解更多。
* [Security analysis of user namespaces and rootless containers](https://tore.tuhh.de/entities/publication/716d05a6-08ce-48e1-bec3-817eb15e2944)
* [CVE-2024-26808](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-26808_cos/docs/exploit.md)
* [CVE-2021-22555](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md)
:::

:::info[原理与影响]
禁止创建 User Namespace。
:::

:::tip[支持的强制访问控制器]
* Seccomp
:::


### `disallow-load-all-bpf-prog`

禁止加载任意类型的 eBPF 程序。

:::note[说明]
攻击者无需任何特权就可以加载 `BPF_PROG_TYPE_SOCKET_FILTER` 或 `BPF_PROG_TYPE_CGROUP_SKB` 类型的 eBPF 程序。因此，攻击者可以尝试使用这些类型的 eBPF 程序进行网络数据包嗅探，或利用 eBPF 验证器和 JIT 引擎的漏洞实现容器逃逸。

禁止容器进程加载 eBPF 程序可降低内核攻击面，阻断部分内核漏洞的利用路径。在未设置 `kernel.unprivileged_bpf_disabled=0` 的系统上，可通过此规则来加固容器。

可参考下面的链接了解更多。
* [Taking the Elevator down to ring 0](https://blog.lumen.com/taking-the-elevator-down-to-ring-0)
* [CVE-2022-23222](https://www.openwall.com/lists/oss-security/2022/01/18/2)
* [CVE-2021-31440](https://www.zerodayinitiative.com/blog/2021/5/26/cve-2021-31440-an-incorrect-bounds-calculation-in-the-linux-kernel-ebpf-verifier)
* [CVE-2021-3490](https://www.crowdstrike.com/en-us/blog/exploiting-cve-2021-3490-for-container-escapes/)
* [CVE-2020-8835](https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification)
:::

:::info[原理与影响]
禁止通过 `bpf` 系统调用和 `BPF_PROG_LOAD` 参数加载任意类型的 eBPF 程序。
:::

:::tip[支持的强制访问控制器]
* Seccomp
:::
