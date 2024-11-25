---
sidebar_position: 1
description: Rules to reduce the attack surface of system.
---

# Hardening

## Securing Privileged Containers
### `disallow-write-core-pattern`

Prohibit modifying procfs' core_pattern.

:::info[Description]
Attackers may attempt container escape by modifying the procfs core_pattern in a **privileged container** or, in a container (**w/ CAP_SYS_ADMIN**), unmounting specific mount points and then modifying the procfs core_pattern to execute a container escape.
:::

:::tip[Principle & Impact]
Disallow writing to the procfs' core_pattern file.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-securityfs`

Prohibit mounting securityfs.

:::info[Description]
Attackers may attempt container escape in containers (**w/ CAP_SYS_ADMIN**) by mounting securityfs with read-write permissions and subsequently modifying it.
:::

:::tip[Principle & Impact]
Disallow mounting of new security file systems.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-procfs`

Prohibit remounting procfs.

:::info[Description]
Attackers may attempt container escape in containers (**w/ CAP_SYS_ADMIN**) by remounting procfs with read-write permissions and subsequently modifying the core_pattern, among other things.
:::

:::tip[Principle & Impact]
1. Disallow mounting of new proc file systems.
2. Prohibit using bind, rbind, move, remount options to remount `/proc**`.
3. When using BPF enforcer, it also prevents unmounting `/proc**`.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-write-release-agent`

Prohibit modifying cgroupfs' release_agent.

:::info[Description]
Attackers may attempt container escape within **privileged container** by directly modifying the cgroupfs release_agent.
:::

:::tip[Principle & Impact]
Disallow writing to the cgroupfs' release_agent file.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-mount-cgroupfs`

Prohibit remounting cgroupfs.

:::info[Description]
Attackers may attempt to escape from containers (**w/ CAP_SYS_ADMIN**) by remounting cgroupfs with read-write permissions. Subsequently, they can modify release_agent and device access permissions, among other things.
:::

:::tip[Principle & Impact]
1. Disallow mounting new cgroup file systems.
2. Prohibit using bind, rbind, move, remount options to remount `/sys/fs/cgroup**`.
3. Prohibit using rbind option to remount `/sys**`.
4. When using BPF enforcer, it also prevents unmounting `/sys**`.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::


### `disallow-debug-disk-device`

Prohibit debugging of disk devices.

:::info[Description]
Attackers may attempt to read and write host machine files by debugging host machine disk devices within a **privileged container**.

It is recommended to use this rule in conjunction with [disable-cap-mknod](#disable-cap-cap) to prevent attackers from bypassing the rule with mknod.
:::

:::tip[Principle & Impact]
Dynamically acquire host disk devices and restrict container access them with read-write permissions.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-mount-disk-device`

Prohibit mounting of host's disk devices.

:::info[Description]
Attackers may attempt to mount host machine disk devices within a **privileged container**, thereby gaining read-write access to host machine files.

It is recommended to use this rule in conjunction with [disable-cap-mknod](#disable-cap-cap) to prevent attackers from bypassing the rule with mknod.
:::

:::tip[Principle & Impact]
Dynamically acquire host machine disk device files and prevent mounting within containers.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-mount`

Disable the mount system call.

:::info[Description]
[MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) is often used for privilege escalation, container escapes, and other attacks. Most microservices applications do not require mount operations. Therefore, it is recommended to use this rule to restrict container processes from using the `mount()` system call.

Note: The mount system call will be disabled by default if the `spec.policy.privileged` field is false.
:::

:::tip[Principle & Impact]
Disable the mount system call.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-umount`

Disable the umount system call.

:::info[Description]
[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) can be used to remove the attachment of topmost mount points(such as maskedPaths), leading to privilege escalation and information disclosure. Most microservices applications do not require umount operations. Therefore, it is recommended to use this rule to restrict container processes from using the `umount()` system call.
:::

:::tip[Principle & Impact]
Disable the umount system call.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-insmod`

Prohibit loading kernel modules.

:::info[Description]
Attackers may attempt to inject code into the kernel within a container (**w/ CAP_SYS_MODULE**) by executing kernel module loading command.
:::

:::tip[Principle & Impact]
Disable CAP_SYS_MODULE.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-load-ebpf`

Prohibit loading eBPF programs.

:::info[Description]
Attackers may load eBPF programs within a container (**w/ CAP_SYS_ADMIN & CAP_BPF**) to theft data or create rootkit.

Note: CAP_BPF was introduced starting from Linux 5.8.
:::

:::tip[Principle & Impact]
Disable CAP_SYS_ADMIN & CAP_BPF.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-access-procfs-root`

Prohibit accessing process's root directory.

:::info[Description]
This policy prohibits processes within containers from accessing the root directory of the process filesystem (i.e., `/proc/[PID]/root`), preventing attackers from exploiting shared PID namespaces to launch attacks.

Attackers may attempt to access the process filesystem outside the container by reading and writing to `/proc/*/root` in environments where the PID namespace is shared with the host or other containers. This could lead to information disclosure, privilege escalation, lateral movement, and other attacks.
:::

:::tip[Principle & Impact]
Disable [PTRACE_MODE_READ](https://man7.org/linux/man-pages/man2/ptrace.2.html) permission.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-access-kallsyms`

Prohibit accessing kernel exported symbol.

:::info[Description]
Attackers may attempt to leak the base address of kernel modules from containers (**w/ CAP_SYSLOG**) by reading the kernel's exported symbol definitions file. This assists attackers in bypassing KASLR protection to exploit kernel vulnerabilities more easily.
:::

:::tip[Principle & Impact]
Disallow reading `/proc/kallsyms` file.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::


## Disabling Capabilities

### `disable-cap-all`

Disable all capabilities.

:::info[Description]
Disable all capabilities.
:::

:::tip[Principle & Impact]
None
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-cap-all-except-net-bind-service`

Disable all capabilities except for NET_BIND_SERVICE.

:::info[Description]
Disable all capabilities except for NET_BIND_SERVICE.

This rule complies with the [*Restricted Policy*](https://kubernetes.io/concepts/security/pod-security-standards/#restricted) of the Pod Security Standards.
:::

:::tip[Principle & Impact]
None
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-cap-privileged`

Disable privileged capabilities.

:::info[Description]
Disable all privileged capabilities that can directly lead to escapes or affect host availability. Only allow the [default capabilities](https://github.com/containerd/containerd/blob/release/1.7/oci/spec.go#L115).

This rule complies with the [*Baseline Policy*](https://kubernetes.io/concepts/security/pod-security-standards/#restricted) of the Pod Security Standards, except for the NET_RAW capability.
:::

:::tip[Principle & Impact]
None
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-cap-[CAP]`

Disable specified capability.

:::info[Description]
Disable any specified capabilities, replacing [CAP] with the values from [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), for example, disable-cap-net-raw.
:::

:::tip[Principle & Impact]
None
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



## Blocking Exploit Vectors

### `disallow-abuse-user-ns`

Prohibit abusing user namespaces.

:::info[Description]
User namespaces can be used to enhance container isolation. However, it also increases the kernel's attack surface, making certain kernel vulnerabilities easier to exploit. Attackers can use a container to create a user namespace, gaining full privileges and thereby expanding the kernel's attack surface.

Disallowing container processes from abusing CAP_SYS_ADMIN privileges via user namespaces can reduce the kernel's attack surface and block certain exploitation paths for kernel vulnerabilities.

This rule can be used to harden containers on systems where `kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0` is not set or applicable.
:::

:::tip[Principle & Impact]
Disable CAP_SYS_ADMIN.
:::

:::danger[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-create-user-ns`

Prohibit creating user namespace.

:::info[Description]
User namespaces can be used to enhance container isolation. However, it also increases the kernel's attack surface, making certain kernel vulnerabilities easier to exploit. Attackers can use a container to create a user namespace, gaining full privileges and thereby expanding the kernel's attack surface.

Disallowing container processes from creating new user namespaces can reduce the kernel's attack surface and block certain exploitation paths for kernel vulnerabilities.

This rule can be used to harden containers on systems where `kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0` is not set or applicable.
:::

:::tip[Principle & Impact]
Disallow creating user namespace.
:::

:::danger[Supported Enforcer]
* Seccomp
:::

