---
sidebar_position: 2
description: Rules against penetration tactics in the container environment.
---

# Attack Protection

## Mitigating Information Leakage

### `mitigate-sa-leak`

Mitigating ServiceAccount token leakage.

:::note[Description]
This rule prohibits container processes from reading sensitive Service Account-related information, including tokens, namespaces, and CA certificates. It helps prevent security risks arising from the leakage of Default ServiceAccount or misconfigured ServiceAccount. In the event that attackers gain access to a container through an RCE vulnerability, they often seek to further infiltrate by leaking ServiceAccount information.

In most user scenarios, there is no need for Pods to communicate with the API Server using ServiceAccounts. However, by default, Kubernetes still sets up default ServiceAccounts for Pods that do not require communication with the API Server.
:::

:::info[Principle & Impact]
Disallow reading ServiceAccount-related files.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `mitigate-disk-device-number-leak`

Mitigating host disk device number leakage.

:::note[Description]
Attackers may attempt to obtain host disk device numbers for subsequent container escape by reading the container process's mount information.
:::

:::info[Principle & Impact]
isallow reading `/proc/[PID]/mountinfo` and `/proc/partitions` files.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `mitigate-overlayfs-leak`

Mitigating container overlayfs path leakage.

:::note[Description]
Attackers may attempt to obtain the overlayfs path of the container's rootfs on the host by accessing the container process's mount information, which could be used for subsequent container escape.
:::

:::info[Principle & Impact]
Disallow reading `/proc/mounts`, `/proc/[PID]/mounts`, and `/proc/[PID]/mountinfo` files.

This rule may impact some functionality of the mount command or syscall within containers.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `mitigate-host-ip-leak`

Mitigating host IP leakage.

:::note[Description]
After gaining access to a container through an RCE vulnerability, attackers often attempt further network penetration attacks. Therefore, restricting attackers from obtaining sensitive information such as host IP, MAC, and network segments through this vector can increase the difficulty and cost of their network penetration activities.
:::

:::info[Principle & Impact]
Disallow reading ARP address resolution tables (such as `/proc/net/arp`, `/proc/[PID]/net/arp`)
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disallow-metadata-service`

Disallow access to the metadata service.

:::note[Description]
This rule prohibits container processes from accessing the cloud server's Instance Metadata Service, including two reserved local addresses: **100.96.0.96** and **169.254.169.254**.

Attackers, upon gaining code execution privileges within a container, may attempt to access the cloud server's Metadata Service for information disclosure. In certain scenarios, attackers may obtain sensitive information, leading to privilege escalation and lateral movement.
:::

:::info[Principle & Impact]
Prohibit connections to Instance Metadata Services' IP addresses.
:::

:::tip[Supported Enforcer]
* BPF
:::



## Disabling Sensitive Operations

### `disable-write-etc`

Prohibit writing to the `/etc` directory.

:::note[Description]
Attackers may attempt privilege escalation by modifying sensitive files in the `/etc` directory, such as altering `/etc/bash.bashrc` for watering hole attacks, editing `/etc/passwd` and `/etc/shadow` to add users for persistence, or modifying nginx.conf or `/etc/ssh/ssh_config` for persistence.
:::

:::info[Principle & Impact]
Disallow writing to the `/etc` directory.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-busybox`

Prohibit the execution of busybox command.

:::note[Description]
Some application services are packaged using base images like busybox or alpine. This also provides attackers with a lot of convenience, as they can use busybox to execute commands and assist in their attacks.
:::

:::info[Principle & Impact]
Prohibit the execution of busybox command.

If containerized services rely on busybox or related bash commands, enabling this policy may lead to runtime errors.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-shell`

Prohibit the creation of Unix shells.

:::note[Description]
After gaining remote code execution privileges through an RCE vulnerability, attackers may use a reverse shell to gain arbitrary command execution capabilities within the container.

This rule prohibits container processes from creating new Unix shells, thus defending against reverse shell.
:::

:::info[Principle & Impact]
Prohibit the creation of Unix shells.

Some base images may symlink sh to `/bin/busybox`. In this scenario, it's also necessary to prohibit the execution of busybox.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-wget`

Prohibit the execution of wget command.

:::note[Description]
Attackers may use the wget command to download malicious programs for subsequent attacks, such as persistence, privilege escalation, network scanning, cryptocurrency mining, and more.

This rule limits file downloads by prohibiting the execution of the wget command.
:::

:::info[Principle & Impact]
Prohibit the execution of wget.

Some base images may symlink wget to `/bin/busybox`. In this scenario, it's also necessary to prohibit the execution of busybox.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-curl`

Prohibit the execution of curl command.

:::note[Description]
Attackers may use the curl command to initiate network access and download malicious programs from external sources for subsequent attacks, such as persistence, privilege escalation, network scanning, cryptocurrency mining, and more.

This rule limits network access by prohibiting the execution of the curl command.
:::

:::info[Principle & Impact]
Prohibit the execution of curl command.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-chmod`

Prohibit the execution of chmod command.

:::note[Description]
When attackers gain control over a container through vulnerabilities, they typically attempt to download additional attack code or tools into the container for further attacks, such as privilege escalation, lateral movement, cryptocurrency mining, and more. In this attack chain, attackers often use the chmod command to modify file permissions for execution.
:::

:::info[Principle & Impact]
Prohibit the execution of chmod command.

Some base images may symlink wget to `/bin/busybox`. In this scenario, it's also necessary to prohibit the execution of busybox command.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



### `disable-chmod-x-bit`

Prohibit setting the execute/search bit of a file.

:::note[Description]
When attackers gain control over a container through vulnerabilities, they typically attempt to download additional attack code or tools into the container for further attacks, such as privilege escalation, lateral movement, cryptocurrency mining, and more. In this attack chain, attackers might use the chmod syscalls to modify file permissions for execution.
:::

:::info[Principle & Impact]
Prohibit setting the execute/search bit of a file with `chmod`, `fchmod`, `fchmodat`, `fchmodat2` syscalls.
:::

:::tip[Supported Enforcer]
* Seccomp
:::



### `disable-chmod-s-bit`

Prohibit setting the SUID/SGID bit of a file.

:::note[Description]
In some scenarios, attackers may attempt to invoke chmod syscalls to perform privilege elevation attacks by setting the file's s-bit (set-user-ID, set-group-ID).
:::

:::info[Principle & Impact]
Prohibit setting the set-user-ID/set-group-ID bit of a file with `chmod`, `fchmod`, `fchmodat`, `fchmodat2` syscalls
:::

:::tip[Supported Enforcer]
* Seccomp
:::



### `disable-su-sudo`

Prohibit the execution of su and sudo command.

:::note[Description]
When processes within a container run as non-root users, attackers often need to escalate privileges to the root user for further attacks. The sudo and su commands are common local privilege escalation avenues.
:::

:::info[Principle & Impact]
Prohibit the execution of sudo and su command.

Some base images may symlink su to `/bin/busybox`. In this scenario, it's also necessary to prohibit the execution of busybox command.
:::

:::tip[Supported Enforcer]
* AppArmor
* BPF
:::



## Restricting Specific Executable


It extends the use cases of [Mitigating Information Leakage](#mitigating-information-leakage) and [Disabling Sensitive Operations](#disabling-sensitive-operations), it allows user to apply restrictions only to specific executable programs within containers.

:::note[Description]
Restricting specified executable programs serves two purposes:
1. Preventing sandbox policies from affecting the execution of application services within containers.
2. Restricting specified executable programs within containers increases the cost and difficulty for attackers

For example, this feature can be used to restrict programs like busybox, bash, sh, curl within containers, preventing attackers from using them to execute sensitive operations. Meanwhile, the application services is unaffected by sandbox policies and can continue to access ServiceAccount tokens and perform other tasks normally.

*Note: Due to the implementation principles of BPF LSM, this feature cannot be provided by the BPF enforcer.*
:::

:::info[Principle & Impact]
Enable sandbox restrictions for specified executable programs.
:::

:::tip[Supported Enforcer]
* Apprmor
:::

