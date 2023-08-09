# The Policy Manual
## 策略语法
vArmor 基于 AppArmor enforcer 和 BPF enforcer 的策略语法开发了内置策略。与此同时，vArmor 也支持用户按照对应语法自定义策略。

### AppArmor enforcer
AppArmor enforcer 支持用户根据 AppArmor 的语法自定义规则
* 语法参见 [syntax of security profiles for AppArmor](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) 和 [AppArmor_Core_Policy_Reference](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference)
* 使用方式
  * 在 .spec.policy.enhanceProtect.appArmorRawRules[] 中添加自定义 rule
  * 请确保每条 rule 以 ',' 结尾

### BPF enforcer (WIP)
BPF enforcer 支持用户根据语法自定义规则，每类规则的数量上限为 50 条。每个节点支持最多对 100 个容器开启沙箱。

* 文件权限定义

  | 权限 | 缩写 | 隐含权限 | 备注 |
  |-----|-----|---------|-----|
  |read|r|-<br>rename<br>hard link|禁止读<br>禁止利用 rename **oldpath** newpath 绕过 oldpath 的读限制<br>禁止利用 ln **TARGET** LINK_NAME 绕过 TARGET 的读限制
  |write|w|-<br>append<br>rename<br>hard link<br>symbol link<br>chmod<br>chown|禁止写<br>禁止利用 O_APPEND flag 绕过 map_file_to_perms() 实现追加写操作<br>禁止利用 rename oldpath **newpath** 绕过 newpath 的写限制<br>禁止利用 ln TARGET **LINK_NAME** 绕过 LINK_NAME 的写限制<br>禁止利用创建软链接（符号链接）绕过目标文件的写限制<br>WIP<br>WIP
  |exec|x|-|禁止执行
  |append|a|-|禁止追加写

* 文件路径匹配

  BPF enfocer 支持根据路径 Pattern 对文件进行匹配，并支持两种匹配模式（精确匹配、通配匹配），匹配 Pattern 的最大长度限制为 64 字节。
  * 精确匹配
  * 通配匹配

    |通配符|语法|样例|备注|
    |-----|---|---|----|
    |*|- 仅用于匹配叶子结点的文件名<br>- 匹配 dot 文件，但不匹配 . 和 .. 文件<br>- 仅支持单个 *，且不支持 \*\* 和 * 一起出现|- fi\* 代表匹配任意以 fi 开头的文件名<br>- *le 代表匹配任意以 le 结尾的文件名<br>- *.log 代表匹配任意以 .log 结尾的文件名|此通配符的行为可能会在后续版本中发生改变|
    |\**|- 在多级目录中，匹配零个、一个、多个字符<br>- 匹配 dot 文件，但不匹配 . 和 .. 文件<br>- 仅支持单个 \*\*，且不支持 ** 和 * 一起出现|- /tmp/\*\*/33 代表匹配任意以 /tmp 开头，且以 /33 结尾的文件，包含 /tmp/33<br>- /tmp/\*\* 代表匹配任意以 /tmp 开头的文件、目录<br>- /tm** 代表匹配任意以 /tm 开头的文件、目录<br>- /t**/33 代表匹配任意以 /t 开头，以 /33 结尾的文件、目录
  
* 网络地址匹配
  * 当前 vArmor 支持对指定的 IP 地址、IP 地址块（CIDR 块）、端口进行外联访问控制
  * 当指定了 IP 地址、IP 地址块，但未指定端口时，默认对所有端口生效
  * 具体请参见 [NetworkEgressRule](./usage_instructions.zh_CN.md#VarmorPolicy)


## 内置策略 (WIP)
**vArmor** 提供 5 种类型的内置策略和自定义接口，以满足不同的防护需求。由于 AppArmor LSM 和 BPF LSM 的差异，不同 enforcer 所支持的规则和语法会有所区别。

（注：不同 enforcer 所支持的内置策略与语法仍旧处于开发中）

| 模式 | 类型 | 子类 | 规则名称 & ID | 适用容器 | 说明 | 原理 & 影响 | 支持的 enforcer |
|-----|-----|-----|---------------|---------|------|------------|----------------|
|**AlwaysAllow**|**Always Allow**|-|-|ALL|在容器启动时不对其施加任何限制，可在稍后变更配置，从而在无需重启工作负载的情况下动态调整防护策略。|-|AppArmor<br>BPF
|**RuntimeDefault**|**Runtime Default**|-|-|Unprivileged|使用与容器运行时组件相同的默认策略（如 containerd 的 [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go)）进行基础防护，防护强度较弱。（受限于强制访问控制的差异，BPF enforcer 相比 AppArmor enforcer 存在一定裁剪）|-|AppArmor<br>BPF
|**EnhanceProtect**|**Hardening**|阻断特权容器的常见逃逸向量|禁止改写 procfs core_pattern<br><br>`disallow_write_core_pattern`|Privileged|攻击者可能会在特权容器中，直接改写特权容器内的 procfs core_pattern，以此来实施容器逃逸。|禁止修改 procfs 的 core_pattern|AppArmor<br>BPF
|              |         |                      |禁止重新挂载 procfs<br><br>`disallow_mount_procfs`|Privileged|攻击者可能会在特权容器（CAP_SYS_ADMIN）中，以读写权限重新挂载 procfs，然后改写 core_pattern 进行容器逃逸。|禁止挂载 proc 类型的文件系统|AppArmor
|              |         |                      |禁止改写 cgroupfs release_agent<br><br>`disallow_write_release_agent`|Privileged|攻击者可能会在特权容器中，通过直接改写 cgroupfs release_agent 进行容器逃逸。|禁止修改 cgroupfs 的 release_agent|AppArmor<br>BPF
|              |         |                      |禁止重新挂载 cgroupfs<br><br>`disallow_mount_cgroupfs`|Privileged|攻击者可能会在特权容器（CAP_SYS_ADMIN）中，以读写权限挂载 cgroupfs。然后通过改写 release_agent、设备访问权限等方式实现容器逃逸。|禁止挂载 cgroup 类型的文件系统|AppArmor
|              |         |                      |禁止调试磁盘设备<br><br>`disallow_debug_disk_device`|Privileged|攻击者可能会在特权容器中，通过调试宿主机磁盘设备，从而实现宿主机文件的读写。|动态获取宿主机磁盘设备文件，并禁止在容器内以读写权限访问|AppArmor
|              |         |                      |禁止挂载宿主机磁盘设备并访问<br><br>`disallow_mount_disk_device`|Privileged|攻击者可能会在特权容器中，挂载宿主机磁盘设备，从而实现宿主机文件的读写。|动态获取宿主机磁盘设备文件，并禁止在容器内挂载|AppArmor
|              |         |                      |禁用 mount 系统调用<br><br>`disallow_mount`|Privileged|攻击者可能会在特权容器中（CAP_SYS_ADMIN），通过 bind mount 方式重新挂载宿主机的敏感文件系统，然后通过改写 procfs core_pattern、cgroupfs release_agent、设备访问权限等方式实现容器逃逸。|禁用 mount 系统调用|AppArmor
|              |         |                      |禁止加载内核模块<br><br>`disallow_insmod`|Privileged|攻击者可能会在特权容器中（CAP_SYS_MODULE），通过执行内核模块加载命令 insmod，向内核中注入代码。|禁用 cap_sys_module|AppArmor<br>BPF
|              |         |                      |禁止加载 ebpf Program<br><br>`disallow_load_ebpf`|ALL|攻击者可能会在特权容器中（CAP_SYS_ADMIN & CAP_BPF），加载 ebpf Program 实现数据窃取和隐藏。<br><br>注：CAP_BPF 自 Linux 5.8 引入。|禁用 cap_sys_admin, cap_bpf|AppArmor<br>BPF
|              |         |                      |禁止访问进程文件系统的根目录<br><br>`disallow_access_procfs_root`|ALL|本策略禁止容器内进程访问进程文件系统的根目录（即 /proc/[PID]/root），防止攻击者利用共享 pid ns 的进程进行攻击。<br><br>攻击者可能会在共享了宿主机 pid ns、与其他容器共享 pid ns 的容器环境中，即通过读写 /proc/*/root 来访问容器外的进程文件系统，实现信息泄露、权限提升、横向移动等攻击。|禁止访问进程文件系统的根目录|AppArmor
|              |         |禁用 capabilities|禁用所有 capabilities<br><br>`disable_cap_all`|ALL|禁用所有 capabilities 或任意指定的 capabilities|-|AppArmor<br>BPF
|              |         |                |禁用特权 capability<br><br>`disable_cap_privileged`|ALL|禁用所有的特权 capabilities（可直接造成逃逸的 capabilities），仅允许部分非特权 capabilities|-|AppArmor<br>BPF
|              |         |                |禁用任意 capability<br><br>`disable_cap_XXXX`|ALL|禁用任意指定的 capabilities，请将 cap_XXXX 替换为 man capabilities 中的值，例如 disable_cap_net_raw|-|AppArmor<br>BPF
|              |         |阻断部分内核漏洞利用向量|禁止滥用 user namespace<br><br>`disallow_abuse_user_ns`|ALL|user namespace 可以被用于增强容器隔离性。但它的出现同时也增大了内核的攻击面，或使得某些内核漏洞更容易被利用。攻击者可以在容器内，通过创建 user namespace 来获取全部特权，从而扩大内核攻击面。<br><br>禁止容器进程通过 user namesapce 获取 cap_sys_admin 特权可用于降低内核攻击面，阻断部分内核漏洞的利用路径。<br>在未设置 kernel.unprivileged_userns_clone=0 或 user.max_user_namespace=0 的系统上，可通过此规则来为容器进行加固。|限制通过 User Namespace 滥用 cap_sys_admin |AppArmor<br>BPF
|              |**Attack Protection**|容器信息泄露缓解|缓解 Service Account 泄露<br><br>`mitigate-sa-leak`|ALL|此规则禁止容器进程读取 Service Account 相关的敏感信息，包括 token、namespace、CA 证书。避免 Default SA 泄漏、错误配置的 SA 泄漏带来的安全风险，攻击者通过 RCE 漏洞获取 k8s 容器内的权限后，非常倾向于通过泄漏其 SA 信息来进行进一步的渗透入侵活动。<br><br>在大部分用户场景中，并不需要使用 SA 与 API Server 进行通信。而默认情况下，k8s 会为不需要与 API Server 通信的 Pod 设置 Default SA。|禁止 Service Account 文件的读操作|AppArmor<br>BPF
|              |                 |             |缓解宿主机磁盘设备号泄露<br><br>`mitigate-disk-device-number-leak`|ALL|此规则禁止容器进程读取 /proc/[PID]/mountinfo, /proc/partitions。<br><br>攻击者可能会通过读取容器进程的挂载信息来获取宿主机磁盘设备的设备号，从而用于后续的容器逃逸。|禁止 mountinfo, partitions 的读操作|AppArmor<br>BPF
|              |                 |             |缓解容器 overlayfs 路径泄露<br><br>`mitigate-overlayfs-leak`|ALL|此规则禁止容器进程通过读取特定文件（/proc/mounts、/proc/[PID]/mounts、/proc/[PID]/mountinfo 等）的内容获取容器的 overlayfs 路径。<br><br>攻击者可能会通过获取容器进程的挂载信息来获取容器进程 rootfs 在宿主机中的 overlayfs 路径，从而用于后续的容器逃逸。|禁止 mounts, mountinfo 文件的读操作<br><br>此规则可能会影响容器内 mount 命令的部分功能|AppArmor<br>BPF
|              |                 |             |缓解宿主机 IP 泄露<br><br>`mitigate-host-ip-leak`|ALL|此规则禁止容器进程读取 ARP 地址解析表（/proc/net/arp、/proc/[PID]/net/arp 等），从而获取宿主机 IP 和 Mac 地址等敏感信息<br><br>攻击者通过 RCE 漏洞获取 k8s 容器内的权限后，会尝试进一步的网络渗透攻击。因此，限制攻击者借此获取宿主机 IP 及其网段等敏感信息，可增加攻击者进行网络渗透的难度和成本。|禁止 arp 文件的读操作|AppArmor<br>BPF
|              |                 |             |禁止访问云服务器的 metadata service<br><br>`disallow-metadata-service`|ALL|此规则禁止容器进程访问云服务器的 Instance Metadata Service。包含两个本地链接保留地址：100.96.0.96 和 169.254.169.254<br><br>攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。|禁止对 Instance Metadata Services 的 IP 地址发起连接请求|BPF
|              |                 |禁止执行敏感操作|禁止写入 /etc 目录<br><br>`disable-write-etc`|ALL|此规则禁止容器内进程写入 /etc 目录。<br><br>攻击者可能会通过修改 /etc 目录中的敏感文件来实施权限提升，例如修改 /etc/bash.bashrc 等实施水坑攻击、修改 /etc/passwd 和 /etc/shadow 添加用户进行持久化、修改 nginx.conf 或 /etc/ssh/ssh_config 进行持久化等。|禁止 /etc 目录及其文件的写操作|AppArmor<br>BPF
|              |                 |              |禁止执行 busybox 命令<br><br>`disable-busybox`|ALL|此规则禁止容器进程执行 busybox 命令。<br><br>某些应用服务会以 busybox, alpine 等作为基础镜像进行打包，而这些镜像一般会使用 busybox 工具箱作为基础命令行工具的可执行程序。这也给攻击者提供了很多便利，攻击者可以利用 busybox 执行命令辅助攻击。|禁止 busybox 执行<br><br>若容器的 entrypoint 和运行依赖 sh，开启此策略会导致运行出错|AppArmor<br>BPF
|              |                 |              |禁止创建 Unix shell<br><br>`disable-shell`|ALL|此规则禁止容器进程创建新的 Unix shell，从而实施反弹 shell 等攻击手段。<br><br>攻击者通过 RCE 漏洞获取服务的远程代码执行权限后，通常会借助反弹 shell 获取服务所在容器的任意命令执行能力。|禁止 shell 执行<br><br>有些基础镜像会动态链接 sh 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用|AppArmor<br>BPF
|              |                 |              |禁止通过 wget 命令下载文件<br><br>`disable-wget`|ALL|此规则禁止容器进程执行 wget 命令。<br><br>攻击者通常会借助 wget 命令从外部下载攻击程序进行随后的攻击（驻留、权限提升、网络扫描、挖矿等）。|禁止 wget 执行<br><br>有些基础镜像会动态链接 wget 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用|AppArmor<br>BPF
|              |                 |              |禁止通过 curl 命令下载文件<br><br>`disable-curl`|ALL|此规则禁止容器进程执行 curl 命令。<br><br>攻击者通常会借助 curl 命令发起网络访问、从外部下载攻击程序进行随后的攻击（驻留、权限提升、网络扫描、挖矿等）。|禁止 curl 执行|AppArmor<br>BPF
|              |                 |              |禁止通过 chmod 修改文件权限<br><br>`disable-chmod`|ALL|此规则禁止容器进程执行 chmod 命令。<br><br>当攻击者通过漏洞获取容器内的控制权后，通常会尝试下载其他攻击代码、工具到容器内实施进一步的攻击（权限提升、横向渗透、挖矿等）。在这个攻击链路中，攻击者通常会利用 chmod 命令修改文件的执行权限。|禁止 chmod 执行<br><br>有些基础镜像会动态链接 chmod 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用<br><br>（TODO: BPF Enforcer 增加 path_chmod hook 点）|AppArmor<br>BPF
|              |                 |              |禁止执行 sudo、su 命令<br><br>`disable-su-sudo`|ALL|此规则禁止容器进程执行 sudo/su 命令进行权限提升。<br><br>当容器内的进程以非 root 用户运行时，攻击者需要先提权至 root 用户进行后续攻击。而 sudo/su 命令是本地提权的常见途径之一。|禁止 sudo、su 执行<br><br>有些基础镜像会动态链接 su 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用|AppArmor<br>BPF
|              |                 |特定可执行文件沙箱限制|-|ALL|此规则对 “容器信息泄漏缓解” 和 “容器敏感命令限制” 两类策略的应用场景进行了扩充，使用户可以对容器内的任意可执行文件实施沙箱限制。<br><br>对指定的可执行文件开启任意防护策略，实现两个目的：<br>1). 避免沙箱策略影响容器内应用服务的正常行为<br>2). 对容器内指定可执行文件进行沙箱限制，增加攻击者成本和难度。<br><br>例如：可以利用此能力对容器中的 busybox、bash、sh、curl 进行限制，禁止利用它们来泄露 ServiceAccount token、泄露宿主机 IP 等。从而增大攻击者获得容器的反弹 shell 后实施后续攻击的难度与成本。与此同时，容器 Entrypoint 指向的应用服务的行为则不受这些沙箱策略的限制，可以正常获取 ServiceAccount token 等，从而避免沙箱策略影响应用服务的正常行为。<br><br>注：受限于 BPF LSM 的实现原理，BPF enforcer 无法提供此功能|为特定可执行文件开启沙箱限制|AppArmor
|              |**Vulnerability Mitigation**|-|缓解 cgroups & lxcfs 逃逸<br><br>`cgroups_lxcfs_escape_mitigation`|ALL|若用户将宿主机的 /sys/fs/cgroup 挂载进了容器，或者使用了 lxcfs 为容器提供资源视图。在这两种场景下可能存在容器逃逸风险，攻击者以在容器内改写 cgroup 子文件系统实施容器逃逸。|AppArmor Enforcer 阻止在容器内修改：<br>/\*\*/release_agent, <br>/\*\*/devices/device.allow,<br>/\*\*/devices/\*\*/device.allow, <br>/\*\*/devices/cgroup.procs,<br>/\*\*/devices/\*\*/cgroup.procs,<br>/\*\*/devices/task,<br>/\*\*/devices/\*\*/task,<br><br>BPF Enforcer 阻止在容器内修改：<br>/\*\*/release_agent<br>/\*\*/devices.allow<br>/\*\*/cgroup.procs<br>/\*\*/devices/tasks<br>|AppArmor<br>BPF
