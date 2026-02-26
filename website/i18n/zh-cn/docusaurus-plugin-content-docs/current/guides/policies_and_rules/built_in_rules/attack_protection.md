---
sidebar_position: 2
description: 针对容器环境中渗透手法的规则。
---

# 攻击防护

这些规则针对容器内的常见渗透手法进行防护，例如缓解容器信息泄露、禁用敏感行为等。

## 缓解信息泄露

### `mitigate-sa-leak`

缓解 ServiceAccount 泄露。

:::note[说明]
此规则禁止容器进程读取 ServiceAccount 相关的敏感信息，包括 token、namespace、ca 证书。避免 default SA 泄漏、错误配置的 SA 泄漏带来的安全风险，攻击者通过 RCE 漏洞获取 k8s 容器内的权限后，常倾向于通过泄漏其 SA 信息来进行进一步的渗透入侵活动。

在大部分用户场景中，并不需要使用 SA 与 API Server 进行通信。而默认情况下，k8s 会为不需要与 API Server 通信的 Pod 设置 default SA。
:::

:::info[原理与影响]
禁止 ServiceAccount 文件的读操作。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `mitigate-disk-device-number-leak`

缓解宿主机磁盘设备号泄露。

:::note[说明]
攻击者可能会通过读取容器进程的挂载信息来获取宿主机磁盘设备的设备号，从而用于后续的容器逃逸。
:::

:::info[原理与影响]
禁止容器进程读取 `/proc/[PID]/mountinfo`, `/proc/partitions`。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `mitigate-overlayfs-leak`

缓解容器 overlayfs 路径泄露。

:::note[说明]
攻击者可能会通过获取容器进程的挂载信息来获取容器进程 rootfs 在宿主机中的 overlayfs 路径，从而用于后续的容器逃逸。
:::

:::info[原理与影响]
禁止读取 `/proc/mounts`、`/proc/[PID]/mounts`、`/proc/[PID]/mountinfo` 文件。

此规则可能会影响容器内 mount 命令的部分功能。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `mitigate-host-ip-leak`

缓解宿主机 IP 泄露。

:::note[说明]
攻击者通过 RCE 漏洞获取 k8s 容器内的权限后，会尝试进一步的网络渗透攻击。因此，限制攻击者借此获取宿主机 IP、MAC 地址、网段等敏感信息，可增加攻击者进行网络渗透的难度和成本。
:::

:::info[原理与影响]
禁止容器进程读取 ARP 地址解析表（`/proc/net/arp`、`/proc/[PID]/net/arp` 等），从而获取宿主机 IP 和 Mac 地址等敏感信息。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `block-access-to-metadata-service`

禁止访问云服务器的常用 metadata service。

:::note[说明]
此规则禁止容器进程访问常用云服务商的 Instance Metadata Service，包括 **169.254.169.254**（IPv4）和 **fd00:ec2::254**（AWS EC2 的 IPv6）用于 AWS、GCP、Azure 和 OpenStack，以及 **100.96.0.96** 用于 Volc Engine 和 BytePlus。

为了获得更好的性能和更细粒度的控制，可以考虑使用针对特定云服务商的规则，如 [`block-access-to-aws-metadata-service`](#block-access-to-aws-metadata-service)、[`block-access-to-volc-metadata-service`](#block-access-to-volc-metadata-service)、[`block-access-to-alibaba-metadata-service`](#block-access-to-alibaba-metadata-service) 或 [`block-access-to-oci-metadata-service`](#block-access-to-oci-metadata-service)。

攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。
:::

:::info[原理与影响]
禁止连接 Instance Metadata Services 的 IP 地址。
:::

:::tip[支持的强制访问控制器]
* BPF
:::

### `block-access-to-aws-metadata-service`

禁止访问 AWS、GCP、Azure 和 OpenStack 的 metadata service。

:::note[说明]
此规则禁止容器进程访问 AWS、GCP、Azure 和 OpenStack 的 Instance Metadata Service，包括 **169.254.169.254**（IPv4）和 **fd00:ec2::254**（AWS EC2 的 IPv6）。

攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。
:::

:::info[原理与影响]
禁止连接 Instance Metadata Services 的 IP 地址。
:::

:::tip[支持的强制访问控制器]
* BPF
:::

### `block-access-to-volc-metadata-service`

禁止访问 Volc Engine 和 BytePlus 的 metadata service。

:::note[说明]
此规则禁止容器进程访问 Volc Engine 和 BytePlus 的 Instance Metadata Service，包括 **100.96.0.96**。

攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。
:::

:::info[原理与影响]
禁止连接 Instance Metadata Services 的 IP 地址。
:::

:::tip[支持的强制访问控制器]
* BPF
:::

### `block-access-to-alibaba-metadata-service`

禁止访问阿里云（Aliyun）的 metadata service。

:::note[说明]
此规则禁止容器进程访问阿里云的 Instance Metadata Service，包括 **100.100.100.200**。

攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。
:::

:::info[原理与影响]
禁止连接 Instance Metadata Services 的 IP 地址。
:::

:::tip[支持的强制访问控制器]
* BPF
:::

### `block-access-to-oci-metadata-service`

禁止访问 Oracle Cloud Infrastructure (OCI) 的 metadata service。

:::note[说明]
此规则禁止容器进程访问 Oracle Cloud Infrastructure 的 Instance Metadata Service，包括 **192.0.0.192**。

攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。
:::

:::info[原理与影响]
禁止连接 Instance Metadata Services 的 IP 地址。
:::

:::tip[支持的强制访问控制器]
* BPF
:::

## 禁止敏感操作

### `disable-write-etc`

禁止写入 /etc 目录。

:::note[说明]
攻击者可能会通过修改 /etc 目录中的敏感文件来实施权限提升，例如修改 /etc/bash.bashrc 等实施水坑攻击、修改 /etc/passwd 和 /etc/shadow 添加用户进行持久化、修改 nginx.conf 或 /etc/ssh/ssh_config 进行持久化等。
:::

:::info[原理与影响]
禁止写入 /etc 目录。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-busybox`

禁止执行 busybox 命令。

:::note[说明]
某些应用服务会以 busybox, alpine 等作为基础镜像进行打包，而这些镜像一般会使用 busybox 工具箱作为基础命令行工具的可执行程序。这也给攻击者提供了很多便利，攻击者可以利用 busybox 执行命令辅助攻击。
:::

:::info[原理与影响]
禁止 busybox 执行。

若容器内服务依赖 busybox 或相关 bash 命令，开启此策略会导致运行出错。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-shell`

禁止创建 Unix Shell。

:::note[说明]
攻击者通过 RCE 漏洞获取服务的远程代码执行权限后，通常会借助 reverse shell 获取容器内任意命令执行能力。

此规则禁止容器进程创建新的 Unix shell，从而实施反弹 shell 等攻击手段。
:::

:::info[原理与影响]
禁止 Unix Shell 执行。

有些基础镜像会动态链接 sh 到 `/bin/busybox`，此情况下还需配合 [disable-busybox](#disable-busybox) 策略使用。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-wget`

禁止通过 wget 命令下载文件。

:::note[说明]
攻击者通常会借助 wget 命令从外部下载攻击程序进行随后的攻击（驻留、权限提升、网络扫描、挖矿等）。

此规则通过禁止执行 wget 命令来限制文件下载。
:::

:::info[原理与影响]
禁止 wget 执行。

有些基础镜像会动态链接 wget 到 `/bin/busybox`，此情况下还需配合 [disable-busybox](#disable-busybox) 策略使用。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-curl`

禁止通过 curl 命令下载文件。

:::note[说明]
攻击者通常会借助 curl 命令发起网络访问、从外部下载攻击程序进行随后的攻击（驻留、权限提升、网络扫描、挖矿等）。

此规则禁止容器进程通过 curl 命令访问网络。
:::

:::info[原理与影响]
禁止 curl 执行。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-chmod`

禁止通过 chmod 修改文件权限。

:::note[说明]
当攻击者通过漏洞获取容器内的控制权后，通常会尝试下载其他攻击代码、工具到容器内实施进一步的攻击（权限提升、横向渗透、挖矿等）。在这个攻击链路中，攻击者通常会利用 chmod 命令修改文件的执行权限。
:::

:::info[原理与影响]
禁止 chmod 执行。

有些基础镜像会动态链接 chmod 到 /bin/busybox，此情况下还需配合 [disable-busybox](#disable-busybox) 策略使用。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-chmod-x-bit`

禁止设置文件的可执行属性。

:::note[说明]
当攻击者通过漏洞获取容器内的控制权后，通常会尝试下载其他攻击代码、工具到容器内实施进一步的攻击（权限提升、横向渗透、挖矿等）。在这个攻击链路中，攻击者通常会调用 chmod 相关系统调用。
:::

:::info[原理与影响]
禁止通过 chmod 相关系统调用（`chmod`、`fchmod`、`fchmodat`、`fchmodat2`），设置文件的 execute/search 权限。
:::

:::tip[支持的强制访问控制器]
* Seccomp
:::

### `disable-chmod-s-bit`

禁止设置文件的 SUID/SGID 属性。

:::note[说明]
在某些场景下，攻击者可能会尝试调用 chmod 系列的系统调用（chmod/fchmod/fchmodat/fchmodat2），通过设置文件的 s 标记位（set-user-ID, set-group-ID）来实施权限提升攻击。
:::

:::info[原理与影响]
禁止通过 chmod 相关系统调用（`chmod`、`fchmod`、`fchmodat`、`fchmodat2`），设置文件的 set-user-ID/set-group-ID 属性。
:::

:::tip[支持的强制访问控制器]
* Seccomp
:::

### `disable-su-sudo`

禁止执行 sudo、su 命令。

:::note[说明]
当容器内的进程以非 root 用户运行时，攻击者需要先提权至 root 用户进行后续攻击。而 sudo/su 命令是本地提权的常见途径之一。
:::

:::info[原理与影响]
禁止 sudo、su 执行。

有些基础镜像会动态链接 su 到 `/bin/busybox`，此情况下还需配合 [disable-busybox](#disable-busybox) 策略使用。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

## 其他
### `disable-network`
禁止所有网络访问。

:::note[说明]
您可以使用此规则禁止容器访问网络。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-inet`, `disable-ipv4`
禁止使用 inet4 地址的网络访问。

:::note[说明]
您可以使用此规则禁止容器进程通过 IPv4 地址访问网络。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-inet6`, `disable-ipv6`
禁止使用 inet6 地址的网络访问。

:::note[说明]
您可以使用此规则禁止容器进程通过 IPv6 地址访问网络。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-unix-domain-socket`
禁止使用 UDS 地址的网络访问。

:::note[说明]
您可以使用此规则禁止容器进程通过 UNIX domain socket 地址访问网络。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-icmp`
禁止使用 ICMP 网络协议。

:::note[说明]
您可以使用此规则禁止容器进程使用 ICMP 网络协议。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-tcp`
禁止使用 TCP 网络协议。

:::note[说明]
您可以使用此规则禁止容器进程使用 TCP 网络协议。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `disable-udp`
禁止使用 UDP 网络协议。

:::note[说明]
您可以使用此规则禁止容器进程使用 UDP 网络协议。
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

### `block-access-to-kube-apiserver`

禁止访问 kube-apiserver。

:::note[说明]
此规则禁止容器进程访问 kube-apiserver，包括两个内网地址：默认命名空间中 kubernetes 服务的 ClusterIP 及其端点。

攻击者在获得容器内的代码执行权限或存在 SSRF 漏洞时，可能会尝试访问 kube-apiserver 以进行敏感操作。在某些情况下，攻击者可能会获取敏感信息或提升权限。 
:::

:::info[原理与影响]
禁止连接到 kube-apiserver。
:::

:::tip[支持的强制访问控制器]
* BPF
:::

### `block-access-to-container-runtime`

禁止访问容器运行时的套接字。

:::note[说明]
此规则旨在通过禁止容器访问 Docker、containerd 和 CRI-O 的关键 Unix 域套接字，缓解由 [CVE-2024-0132](https://nvidia.custhelp.com/app/answers/detail/a_id/5582) 和 [CVE-2025-23359](https://nvidia.custhelp.com/app/answers/detail/a_id/5616) 等漏洞引发的容器逃逸风险。

这些套接字是容器运行时的控制接口。正如 CVE-2024-0132 的漏洞利用所示，攻击者若突破容器隔离（例如通过漏洞将宿主机根文件系统挂载到容器内），可借助这些套接字启动特权容器、操控主机资源，进而完全攻陷主机或 Kubernetes 集群。
:::

:::info[原理与影响]
此规则禁止容器访问 `docker.sock`、`containerd.sock` 或 `crio.sock` 文件。它针对攻击链中的关键环节：即便攻击者成功利用漏洞突破初始容器隔离（例如以只读模式挂载宿主机文件系统），通过阻断对套接字文件的访问，也能阻止其利用容器运行时来提升权限（例如启动具有完全主机访问权限的特权容器）。

这种缓解措施符合 “纵深防御” 策略，侧重于阻断逃逸后的横向移动，而非仅依赖修复根源漏洞。

可参考下面的链接了解更多。
* [How Wiz found a Critical NVIDIA AI vulnerability:  Deep Dive into a container escape (CVE-2024-0132)](https://www.wiz.io/blog/nvidia-ai-vulnerability-deep-dive-cve-2024-0132)
:::

:::tip[支持的强制访问控制器]
* AppArmor
* BPF
:::

## 限制特定可执行文件

此规则对 “[缓解信息泄露](#mitigating-information-leakage)”、“[禁止敏感操作](#disabling-sensitive-operations)”、“[其他](#others)” 三类内置规则的使用场景进行了扩充，使用户可以只对容器内的特定可执行文件及其子进程进行限制。

:::note[说明]
对指定的可执行文件进行限制，可用于实现两个目的：
1. 避免沙箱策略影响容器内应用服务的正常执行。
2. 对容器内指定可执行文件进行限制，增加攻击者成本和难度。

例如，可以利用此功能对容器中的 busybox、bash、sh、curl 进行限制，阻止攻击者利用它们来执行敏感操作。与此同时，应用服务的运行则不受沙箱策略的限制，可以正常执行读取 ServiceAccount token 等敏感操作。

*注：受限于 BPF LSM 的实现原理，BPF enforcer 无法**安全地**提供此功能。*
:::

:::info[原理与影响]
为特定可执行文件开启沙箱限制。
:::

:::tip[支持的强制访问控制器]
* Apprmor
:::

示例：
```yaml
  policy:
    enforcer: AppArmor
    mode: EnhanceProtect
    enhanceProtect:
      attackProtectionRules:
      # All processes in the container are confined by the `disable-write-etc` rule.
      - rules: 
        - disable-write-etc
      // highlight-start
      # Only the executable files listed below and their child processes are confined by the listed rules.
      - rules:
        - mitigate-sa-leak
        - disable-network
        - disable-chmod-x-bit
        targets:
        - "/bin/sh"
        - "/usr/bin/sh"
        - "/bin/dash"
        - "/usr/bin/dash"
        - "/bin/bash"
        - "/usr/bin/bash"
        - "/bin/busybox"
        - "/usr/bin/busybox"
      // highlight-end
```
