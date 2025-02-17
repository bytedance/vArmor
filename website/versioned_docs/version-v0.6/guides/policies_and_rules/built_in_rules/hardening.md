---
sidebar_position: 1
description: Rules to reduce the attack surface of system.
---

# Hardening
These rules are used for reduce the attack surface of system, such as blocking common escape vectors for containers has privileges, disabling capabilities, and blocking certain kernel vulnerability exploitation vectors.

## Securing Privileged Containers

### `disallow-write-core-pattern`

Prohibit modifying procfs' core_pattern.

:::note[Description]
Attackers may attempt container escape by modifying the procfs core_pattern in a **privileged container** or, in a container (**w/ CAP_SYS_ADMIN**), unmounting specific mount points and then modifying the procfs core_pattern to execute a container escape.
:::

:::info[Principle & Impact]
Disallow writing to the procfs' core_pattern file.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-securityfs`

Prohibit mounting securityfs.

:::note[Description]
Attackers may attempt container escape in containers (**w/ CAP_SYS_ADMIN**) by mounting securityfs with read-write permissions and subsequently modifying it.
:::

:::info[Principle & Impact]
Disallow mounting of new security file systems.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-procfs`

Prohibit remounting procfs.

:::note[Description]
Attackers may attempt container escape in containers (**w/ CAP_SYS_ADMIN**) by remounting procfs with read-write permissions and subsequently modifying the core_pattern, among other things.
:::

:::info[Principle & Impact]
1. Disallow mounting of new proc file systems.
2. Prohibit using bind, rbind, move, remount options to remount `/proc**`.
3. When using BPF enforcer, it also prevents unmounting `/proc**`.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-write-release-agent`

Prohibit modifying cgroupfs' release_agent.

:::note[Description]
Attackers may attempt container escape within **privileged container** by directly modifying the cgroupfs release_agent.
:::

:::info[Principle & Impact]
Disallow writing to the cgroupfs' release_agent file.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-cgroupfs`

Prohibit remounting cgroupfs.

:::note[Description]
Attackers may attempt to escape from containers (**w/ CAP_SYS_ADMIN**) by remounting cgroupfs with read-write permissions. Subsequently, they can modify release_agent and device access permissions, among other things.
:::

:::info[Principle & Impact]
1. Disallow mounting new cgroup file systems.
2. Prohibit using bind, rbind, move, remount options to remount `/sys/fs/cgroup**`.
3. Prohibit using rbind option to remount `/sys**`.
4. When using BPF enforcer, it also prevents unmounting `/sys**`.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-debug-disk-device`

Prohibit debugging of disk devices.

:::note[Description]
Attackers may attempt to read and write host machine files by debugging host machine disk devices within a **privileged container**.

It is recommended to use this rule in conjunction with [disable-cap-mknod](#disable-cap-cap) to prevent attackers from bypassing the rule with mknod.
:::

:::info[Principle & Impact]
Dynamically acquire host disk devices and restrict container access them with read-write permissions.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-disk-device`

Prohibit mounting of host's disk devices.

:::note[Description]
Attackers may attempt to mount host machine disk devices within a **privileged container**, thereby gaining read-write access to host machine files.

It is recommended to use this rule in conjunction with [disable-cap-mknod](#disable-cap-cap) to prevent attackers from bypassing the rule with mknod.
:::

:::info[Principle & Impact]
Dynamically acquire host machine disk device files and prevent mounting within containers.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount`

Disable the mount system call.

:::note[Description]
[MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) is often used for privilege escalation, container escapes, and other attacks. Most microservices applications do not require mount operations. Therefore, it is recommended to use this rule to restrict container processes from using the `mount()` system call.

Note: The mount system call will be disabled by default if the `spec.policy.privileged` field is false.
:::

:::info[Principle & Impact]
Disable the mount system call.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-umount`

Disable the umount system call.

:::note[Description]
[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) can be used to remove the attachment of topmost mount points(such as maskedPaths), leading to privilege escalation and information disclosure. Most microservices applications do not require umount operations. Therefore, it is recommended to use this rule to restrict container processes from using the `umount()` system call.
:::

:::info[Principle & Impact]
Disable the umount system call.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-insmod`

Prohibit loading kernel modules.

:::note[Description]
Attackers may attempt to inject code into the kernel within a container (**w/ CAP_SYS_MODULE**) by executing kernel module loading command.
:::

:::info[Principle & Impact]
Disable CAP_SYS_MODULE.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-load-bpf-prog`, `disallow-load-ebpf`

Prohibit loading eBPF programs, except for those of the BPF_PROG_TYPE_SOCKET_FILTER and BPF_PROG_TYPE_CGROUP_SKB types.

:::note[Description]
Attackers may load eBPF programs within a container (**w/ CAP_SYS_ADMIN, CAP_BPF**) to theft data or create rootkit.

Before Linux 5.8, loading eBPF programs, except for those of the BPF_PROG_TYPE_SOCKET_FILTER and BPF_PROG_TYPE_CGROUP_SKB types, needs CAP_SYS_ADMIN. Since Linux 5.8, loading eBPF programs, except for those types, needs CAP_SYS_ADMIN or CAP_BPF. And some types of eBPF programs also require CAP_NET_ADMIN or CAP_PERFMON.

The id of `disallow-load-ebpf` rule will be deprecated, please use `disallow-load-bpf-prog` instead.
:::

:::info[Principle & Impact]
Disable CAP_SYS_ADMIN & CAP_BPF.

It is recommended to use the [disallow-load-all-bpf-prog](#disallow-load-all-bpf-prog) rule to prohibit loading any types of eBPF programs to reduce the attack surface of kernel.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-access-procfs-root`

Prohibit accessing process's root directory.

:::note[Description]
This policy prohibits processes within containers from accessing the root directory of the process filesystem (i.e., `/proc/[PID]/root`), preventing attackers from exploiting shared PID namespaces to launch attacks.

Attackers may attempt to access the process filesystem outside the container by reading and writing to `/proc/*/root` in environments where the PID namespace is shared with the host or other containers. This could lead to information disclosure, privilege escalation, lateral movement, and other attacks.
:::

:::info[Principle & Impact]
Disable [PTRACE_MODE_READ](https://man7.org/linux/man-pages/man2/ptrace.2.html) permission.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-access-kallsyms`

Prohibit accessing kernel exported symbol.

:::note[Description]
Attackers may attempt to leak the base address of kernel modules from containers (**w/ CAP_SYSLOG**) by reading the kernel's exported symbol definitions file. This assists attackers in bypassing KASLR protection to exploit kernel vulnerabilities more easily.
:::

:::info[Principle & Impact]
Disallow reading `/proc/kallsyms` file.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


## Disabling Capabilities

### `disable-cap-all`

Disable all capabilities.

:::note[Description]
Disable all capabilities.
:::

:::info[Principle & Impact]
None
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disable-cap-all-except-net-bind-service`

Disable all capabilities except for NET_BIND_SERVICE.

:::note[Description]
Disable all capabilities except for NET_BIND_SERVICE.

This rule complies with the [*Restricted Policy*](https://kubernetes.io/concepts/security/pod-security-standards/#restricted) of the Pod Security Standards.
:::

:::info[Principle & Impact]
None
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disable-cap-privileged`

Disable privileged capabilities.

:::note[Description]
Disable all privileged capabilities that can directly lead to escapes or affect host availability. Only allow the [default capabilities](https://github.com/containerd/containerd/blob/release/1.7/oci/spec.go#L115).

This rule complies with the [*Baseline Policy*](https://kubernetes.io/concepts/security/pod-security-standards/#restricted) of the Pod Security Standards, except for the NET_RAW capability.
:::

:::info[Principle & Impact]
None
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disable-cap-[CAP]`

Disable specified capability.

:::note[Description]
Disable any specified capabilities, replacing [CAP] with the values from [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), for example, disable-cap-net-raw.
:::

:::info[Principle & Impact]
None
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


## Blocking Exploit Vectors

### `disallow-abuse-user-ns`

Prohibit abusing user namespaces.

:::note[Description]
User namespaces can be used to enhance container isolation. However, it also increases the kernel's attack surface, making certain kernel vulnerabilities easier to exploit. Attackers can use a container to create a user namespace, gaining full privileges and thereby expanding the kernel's attack surface.

Disallowing container processes from abusing CAP_SYS_ADMIN privileges via user namespaces can reduce the kernel's attack surface and block certain exploitation paths for kernel vulnerabilities.

This rule can be used to harden containers on systems where `kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0` is not set or applicable.

Refer to the following links for further information.
* [Security analysis of user namespaces and rootless containers](https://tore.tuhh.de/entities/publication/716d05a6-08ce-48e1-bec3-817eb15e2944)
* [CVE-2024-26808](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-26808_cos/docs/exploit.md)
* [CVE-2021-22555](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md)
:::

:::info[Principle & Impact]
Disable CAP_SYS_ADMIN.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-create-user-ns`

Prohibit creating user namespace.

:::note[Description]
User namespaces can be used to enhance container isolation. However, it also increases the kernel's attack surface, making certain kernel vulnerabilities easier to exploit. Attackers can use a container to create a user namespace, gaining full privileges and thereby expanding the kernel's attack surface.

Disallowing container processes from creating new user namespaces can reduce the kernel's attack surface and block certain exploitation paths for kernel vulnerabilities.

This rule can be used to harden containers on systems where `kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0` is not set or applicable.

Refer to the following links for further information.
* [Security analysis of user namespaces and rootless containers](https://tore.tuhh.de/entities/publication/716d05a6-08ce-48e1-bec3-817eb15e2944)
* [CVE-2024-26808](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-26808_cos/docs/exploit.md)
* [CVE-2021-22555](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/writeup.md)
:::

:::info[Principle & Impact]
Disallow creating user namespace.
:::

:::tip[Supported Enforcer]
* Seccomp
:::


### `disallow-load-all-bpf-prog`

Prohibit loading any types of eBPF programs.

:::note[Description]
Attackers can load `BPF_PROG_TYPE_SOCKET_FILTER` or `BPF_PROG_TYPE_CGROUP_SKB` types of extended BPF (eBPF) programs without privileged permission.
So they may use these types of eBPF programs to sniff network data package, or exploit vulnerabilities of the BPF verifier or JIT engine to achieve container escape.

This rule can be used to harden containers on systems where `kernel.unprivileged_bpf_disabled=0`.

Refer to the following links for further information.
* [Taking the Elevator down to ring 0](https://blog.lumen.com/taking-the-elevator-down-to-ring-0)
* [CVE-2022-23222](https://www.openwall.com/lists/oss-security/2022/01/18/2)
* [CVE-2021-31440](https://www.zerodayinitiative.com/blog/2021/5/26/cve-2021-31440-an-incorrect-bounds-calculation-in-the-linux-kernel-ebpf-verifier)
* [CVE-2021-3490](https://www.crowdstrike.com/en-us/blog/exploiting-cve-2021-3490-for-container-escapes/)
* [CVE-2020-8835](https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification).
:::

:::info[Principle & Impact]
Disallow loading any types of eBPF programs via `bpf` syscall with `BPF_PROG_LOAD` parameters.
:::

:::tip[Supported Enforcer]
* Seccomp 🏷️ v0.6.2
:::


### `disallow-load-bpf-via-setsockopt`

Prohibit loading classic BPF programs via setsockopt system call

:::note[Description]
Attackers can load classic BPF (cBPF) programs via the `setsockopt` syscall without privileged permission. 
They may use this way to perform some BPF JIT spraying. This can be a powerful means to exploit kernel vulnerabilities. Because this exploit vector does not rely on any capability and is outside the control of the `kernel.unprivileged_bpf_disabled` sysctl.

Refer to the following links for further information.
* [CVE-2024-36972 vulnerability description](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-36972_lts_cos/docs/vulnerability.md)
* [CVE-2024-36972 exploit description](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-36972_lts_cos/docs/exploit.md)
:::

:::info[Principle & Impact]
Disallow loading classic BPF programs via `setsockopt` syscall with `SO_ATTACH_FILTER` or `SO_ATTACH_REUSEPORT_CBPF` parameter.

It is recommended to use it in conjunction with the [disallow-load-all-bpf-prog](#disallow-load-all-bpf-prog) rule to prohibit loading any types of extended BPF programs.
:::

:::tip[Supported Enforcer]
* Seccomp 🏷️ v0.6.3
:::


### `disallow-userfaultfd-creation`

Prohibit creating userfaultfd objects.

:::note[Description]
In Linux kernel exploits, `userfaultfd` is often abused by attackers to manipulate the timing of memory accesses, thus assisting in the implementation of exploits (such as conditional race vulnerabilities, UAF vulnerabilities). Its core function is to precisely control the processing timing of page errors (Page Fault), creating a predictable vulnerability trigger window for attackers.

Since Linux 5.11, the global variable `sysctl_unprivileged_userfaultfd` in kernel fs/userfaultfd.c is initialized to 0, and a userfaultfs object can be created only if the process has SYS_CAP_PTRACE permissions.

This rule can be used to harden containers on systems where `kernel.unprivileged_userfaultfd=1`. And the `userfaultfd` syscall is also disabled in the default Seccomp profile of the container runtime.
:::

:::info[Principle & Impact]
Disallow calling the `userfaultfd` system call.
:::

:::tip[Supported Enforcer]
* Seccomp 🏷️ v0.6.3
:::
