---
sidebar_position: 1
description: Rules to reduce the attack surface of system.
---

# Hardening

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



### `disallow-load-ebpf`

Prohibit loading eBPF programs.

:::note[Description]
Attackers may load eBPF programs within a container (**w/ CAP_SYS_ADMIN & CAP_BPF**) to theft data or create rootkit.

Note: CAP_BPF was introduced starting from Linux 5.8.
:::

:::info[Principle & Impact]
Disable CAP_SYS_ADMIN & CAP_BPF.
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
:::

:::info[Principle & Impact]
Disallow creating user namespace.
:::

:::tip[Supported Enforcer]
* Seccomp
:::

