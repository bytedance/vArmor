# 策略模式与内置规则
[English](built_in_rules.md) | 简体中文

## 策略模式
可通过 [VarmorPolicy](usage_instructions.zh_CN.md#varmorpolicy)/[VarmorClusterPolicy](usage_instructions.zh_CN.md#varmorclusterpolicy) 对象的 `spec.policy.mode` 字段来指定运行模式。不同 enforcers 支持的模式如下表所示。

|运行模式|AppArmor|BPF|Seccomp|说明|
|------|--------|----|-------|---|
|AlwaysAllow|[x]|[x]|-|在容器启动时不对其施加任何强制访问控制
|RuntimeDefault|[x]|[x]|-|使用与容器运行时组件相同的默认策略（如 containerd 的 [cri-containerd.apparmor.d](https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go)）进行基础防护
|EnhanceProtect|[x]|[x]|[x]|- 支持 5 类[内置规则](built_in_rules.zh_CN.md#内置规则)和自定义接口，以满足不同的防护需求。<br>- 默认在 RuntimeDefault 模式的基础上进行增强防护（当 `spec.policy.enhanceProtect.privileged` 为 `nil` 或 `false` 时）<br>- 支持在 AlwaysAllow 模式的基础上进行增强防护（当 `spec.policy.enhanceProtect.privileged` 为 `true`）
|BehaviorModeling|[x]|[ ]|[x]|- 利用 BPF & Audit 等技术同时对多个工作负载进行行为建模<br>- 行为模型保存在对应的 [ArmorProfileModel](../apis/varmor/v1beta1/armorprofilemodel_types.go) 对象中<br>- 不可切换防护模式<br>- 请参见 [The BehaviorModeling Mode](behavior_modeling.md)
|DefenseInDepth|[x]|-|[x]|基于行为模型 [ArmorProfileModel](../apis/varmor/v1beta1/armorprofilemodel_types.go) 对工作负载进行防护

注意：vArmor 策略支持动态切换运行模式（限 EnhanceProtect, RuntimeDefault, AlwaysAllow, DefenseInDepth）、更新沙箱规则，而无需重启工作负载。但当使用 Seccomp enforcer 时，需要重启工作负载来使 Seccomp Profile 的变更生效。


## 内置规则
**vArmor** 支持使用在 **EnhanceProtect** 模式下使用内置规则和自定义接口来定义防护策略，当前支持的内置规则及其分类如下表所示。

注意：<br>- 不同 enforcer 所支持的内置策略与语法仍旧处于开发中。<br>- 不同 enforcer 所能支持的规则和语法会有所区别。例如 AppArmor enforcer 不支持细粒度的网络访问控制，BPF 不支持对指定的可执行程序进行访问控制等。<br>

| 类别 | 子类 | 规则名称 & ID | 适用容器 | 说明 | 原理 & 影响 | 支持的 enforcer |
|-----|-----|---------------------------------------------|---------|------|------------|----------------|
|**Hardening**|阻断特权容器的常见逃逸向量|禁止改写 procfs core_pattern<br><br>`disallow-write-core-pattern`|Privileged|攻击者可能会在特权容器（**Privileged Container**）中，通过改写 procfs core_pattern，来实施容器逃逸。或者在特权容器（**w/ CAP_SYS_ADMIN**）中，卸载特定挂载点后改写 procfs core_pattern，来实施容器逃逸。|禁止修改 procfs 的 core_pattern|AppArmor<br>BPF
|         |                      |禁止挂载 securityfs<br><br>`disallow-mount-securityfs`|Privileged|攻击者可能会在特权容器（**w/ CAP_SYS_ADMIN**）中，以读写权限挂载新的 securityfs 并对其进行修改。|禁止挂载新的 securityfs|AppArmor<br>BPF
|         |                      |禁止重新挂载 procfs<br><br>`disallow-mount-procfs`|Privileged|攻击者可能会在特权容器（**w/ CAP_SYS_ADMIN**）中，以读写权限重新挂载 procfs，然后再通过改写 core_pattern 等方式进行容器逃逸、修改系统配置。|1. 禁止挂载新的 procfs<br><br>2. 禁止使用 bind, rbind, move, remount 选项重新挂载 `/proc**` <br><br>3. 使用 BPF enforcer 时，还将禁止卸载 `/proc**`|AppArmor<br>BPF
|         |                      |禁止改写 cgroupfs release_agent<br><br>`disallow-write-release-agent`|Privileged|攻击者可能会在特权容器（**Privileged Container**）中，通过改写 cgroupfs release_agent，来实施容器逃逸。|禁止修改 cgroupfs 的 release_agent|AppArmor<br>BPF
|         |                      |禁止重新挂载 cgroupfs<br><br>`disallow-mount-cgroupfs`|Privileged|攻击者可能会在特权容器（**w/ CAP_SYS_ADMIN**）中，以读写权限重新挂载 cgroupfs。然后再通过改写 release_agent、设备访问权限等方式进行容器逃逸、修改系统配置。|1. 禁止挂载新的 cgroupfs<br><br>2. 禁止使用 bind, rbind, move, remount 选项重新挂载 `/sys/fs/cgroup**`<br><br>3. 禁止使用 rbind 选项重新挂载 `/sys**`<br><br>4. 使用 BPF enforcer 时，还将禁止卸载 `/sys**` |AppArmor<br>BPF
|         |                      |禁止调试磁盘设备<br><br>`disallow-debug-disk-device`|Privileged|攻击者可能会在特权容器（**Privileged Container**）中，通过调试宿主机磁盘设备，从而实现宿主机文件的读写。<br><br>建议配合 `disable_cap_mknod` 使用，从而防止攻击者利用 mknod 创建新的设备文件，从而绕过此规则|动态获取宿主机磁盘设备文件，并禁止在容器内以读写权限访问|AppArmor<br>BPF
|         |                      |禁止挂载宿主机磁盘设备并访问<br><br>`disallow-mount-disk-device`|Privileged|攻击者可能会在特权容器（**Privileged Container**）中，挂载宿主机磁盘设备，从而实现宿主机文件的读写。<br><br>建议配合 `disable_cap_mknod` 使用，从而防止攻击者利用 mknod 创建新的设备文件，从而绕过此规则|动态获取宿主机磁盘设备文件，并禁止在容器内挂载|AppArmor<br>BPF
|         |                      |禁用 mount 系统调用<br><br>`disallow-mount`|Privileged|[MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) 常被用于权限提升、容器逃逸等攻击。而几乎所有的微服务应用都无需 mount 操作，因此建议使用此规则限制容器内进程访问 mount 系统调用。<br><br>注：当 spec.policy.privileged 为 false 时，将默认禁用 mount 系统调用。|禁用 mount 系统调用|AppArmor<br>BPF
|         |                      |禁用 umount 系统调用<br><br>`disallow-umount`|ALL|[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) 可被用于卸载敏感的挂载点（例如 maskedPaths），从而导致权限提升、信息泄露。而几乎所有的微服务应用都无需 umount 操作，因此建议使用此规则限制容器内进程访问 umount 系统调用。|禁用 umount 系统调用|AppArmor<br>BPF
|         |                      |禁止加载内核模块<br><br>`disallow-insmod`|Privileged|攻击者可能会在特权容器中（**w/ CAP_SYS_MODULE**），通过执行内核模块加载命令 insmod，向内核中注入代码。|禁用 CAP_SYS_MODULE|AppArmor<br>BPF
|         |                      |禁止加载 ebpf Program<br><br>`disallow-load-ebpf`|ALL|攻击者可能会在特权容器中（**w/ CAP_SYS_ADMIN & CAP_BPF**），加载 ebpf Program 实现数据窃取和隐藏。<br><br>注：CAP_BPF 自 Linux 5.8 引入。|禁用 CAP_SYS_ADMIN, CAP_BPF|AppArmor<br>BPF
|         |                      |禁止访问进程文件系统的根目录<br><br>`disallow-access-procfs-root`|ALL|本策略禁止容器内进程访问进程文件系统的根目录（即 /proc/[PID]/root），防止攻击者利用共享 pid ns 的进程进行攻击。<br><br>攻击者可能会在共享了宿主机 pid ns、与其他容器共享 pid ns 的容器环境中，通过读写 /proc/*/root 来访问容器外的进程文件系统，实现信息泄露、权限提升、横向移动等攻击。|禁用 PTRACE_MODE_READ 权限|AppArmor<br>BPF
|         |                      |禁止读取内核符号文件<br><br>`disallow-access-kallsyms`|ALL|攻击者可能会在特权容器中（**w/ CAP_SYS_ADMIN**），通过读取内核符号文件来获取内核模块地址。从而绕过 KASLR 防护，降低内核漏洞的难度与成本。|禁止读取 /proc/kallsyms 文件|AppArmor<br>BPF
|         |禁用 capabilities|禁用所有 capabilities<br><br>`disable-cap-all`|ALL|禁用所有 capabilities|-|AppArmor<br>BPF
|         |                |禁用特权 capability<br><br>`disable-cap-privileged`|ALL|禁用所有的特权 capabilities（可直接造成逃逸、影响宿主机可用性的 capabilities）。仅允许非特权 capabilities，即 Container Runtime 默认授予容器的 capabilities。|-|AppArmor<br>BPF
|         |                |禁用任意 capability<br><br>`disable-cap-XXXX`|ALL|禁用任意指定的 capabilities，请将 XXXX 替换为 man capabilities 中的值，例如 disable-cap-net-raw|-|AppArmor<br>BPF
|         |阻断部分内核漏洞利用向量|禁止滥用 User Namespace<br><br>`disallow-abuse-user-ns`|ALL|User Namespace 可以被用于增强容器隔离性。但它的出现同时也增大了内核的攻击面，或使得某些内核漏洞更容易被利用。攻击者可以在容器内，通过创建 User Namespace 来获取全部特权，从而扩大内核攻击面。<br><br>禁止容器进程通过 User Namesapce 滥用 CAP_SYS_ADMIN 特权可用于降低内核攻击面，阻断部分内核漏洞的利用路径。<br>在未设置 kernel.unprivileged_userns_clone=0 或 user.max_user_namespaces=0 的系统上，可通过此规则来为容器进行加固。|限制通过 User Namespace 滥用 CAP_SYS_ADMIN |AppArmor<br>BPF
|         |                    |禁止创建 User Namespace<br><br>`disallow-create-user-ns`|ALL|User Namespace 可以被用于增强容器隔离性。但它的出现同时也增大了内核的攻击面，或使得某些内核漏洞更容易被利用。攻击者可以在容器内，通过创建 User Namespace 来获取全部特权，从而扩大内核攻击面。<br><br>禁止容器进程创建新的 User Namesapce 从而获取 CAP_SYS_ADMIN 特权可用于降低内核攻击面，阻断部分内核漏洞的利用路径。<br>在未设置 kernel.unprivileged_userns_clone=0 或 user.max_user_namespaces=0 的系统上，可通过此规则来为容器进行加固。|禁止创建 User Namespace|Seccomp
|**Attack Protection**|缓解信息泄露|缓解 ServiceAccount 泄露<br><br>`mitigate-sa-leak`|ALL|此规则禁止容器进程读取 ServiceAccount 相关的敏感信息，包括 token、namespace、ca 证书。避免 default SA 泄漏、错误配置的 SA 泄漏带来的安全风险，攻击者通过 RCE 漏洞获取 k8s 容器内的权限后，常倾向于通过泄漏其 SA 信息来进行进一步的渗透入侵活动。<br><br>在大部分用户场景中，并不需要使用 SA 与 API Server 进行通信。而默认情况下，k8s 会为不需要与 API Server 通信的 Pod 设置 default SA。|禁止 ServiceAccount 文件的读操作|AppArmor<br>BPF
|                 |             |缓解宿主机磁盘设备号泄露<br><br>`mitigate-disk-device-number-leak`|ALL|此规则禁止容器进程读取 /proc/[PID]/mountinfo, /proc/partitions。<br><br>攻击者可能会通过读取容器进程的挂载信息来获取宿主机磁盘设备的设备号，从而用于后续的容器逃逸。|禁止 mountinfo, partitions 的读操作|AppArmor<br>BPF
|                 |             |缓解容器 overlayfs 路径泄露<br><br>`mitigate-overlayfs-leak`|ALL|禁止读取 /proc/mounts、/proc/[PID]/mounts、/proc/[PID]/mountinfo 文件。<br><br>攻击者可能会通过获取容器进程的挂载信息来获取容器进程 rootfs 在宿主机中的 overlayfs 路径，从而用于后续的容器逃逸。|禁止 mounts, mountinfo 文件的读操作<br><br>此规则可能会影响容器内 mount 命令的部分功能|AppArmor<br>BPF
|                 |             |缓解宿主机 IP 泄露<br><br>`mitigate-host-ip-leak`|ALL|此规则禁止容器进程读取 ARP 地址解析表（/proc/net/arp、/proc/[PID]/net/arp 等），从而获取宿主机 IP 和 Mac 地址等敏感信息<br><br>攻击者通过 RCE 漏洞获取 k8s 容器内的权限后，会尝试进一步的网络渗透攻击。因此，限制攻击者借此获取宿主机 IP、MAC 地址、网段等敏感信息，可增加攻击者进行网络渗透的难度和成本。|禁止 ARP 文件的读操作|AppArmor<br>BPF
|                 |             |禁止访问云服务器的 metadata service<br><br>`disallow-metadata-service`|ALL|此规则禁止容器进程访问云服务器的 Instance Metadata Service。包含两个本地链接保留地址：100.96.0.96 和 169.254.169.254<br><br>攻击者获取容器内的代码执行权限后，会尝试访问云服务器的 Metadata Service 来进行信息泄露。在某些场景下，攻击者可能会获取敏感信息，从而进行权限提升、横向渗透。|禁止连接 Instance Metadata Services 的 IP 地址|BPF
|                 |禁止敏感操作|禁止写入 /etc 目录<br><br>`disable-write-etc`|ALL|攻击者可能会通过修改 /etc 目录中的敏感文件来实施权限提升，例如修改 /etc/bash.bashrc 等实施水坑攻击、修改 /etc/passwd 和 /etc/shadow 添加用户进行持久化、修改 nginx.conf 或 /etc/ssh/ssh_config 进行持久化等。|禁止写入 /etc 目录|AppArmor<br>BPF
|                 |              |禁止执行 busybox 命令<br><br>`disable-busybox`|ALL|此规则禁止容器进程执行 busybox 命令。<br><br>某些应用服务会以 busybox, alpine 等作为基础镜像进行打包，而这些镜像一般会使用 busybox 工具箱作为基础命令行工具的可执行程序。这也给攻击者提供了很多便利，攻击者可以利用 busybox 执行命令辅助攻击。|禁止 busybox 执行<br><br>若容器内服务依赖 busybox 或相关 bash 命令，开启此策略会导致运行出错|AppArmor<br>BPF
|                 |              |禁止创建 Unix Shell<br><br>`disable-shell`|ALL|此规则禁止容器进程创建新的 Unix shell，从而实施反弹 shell 等攻击手段。<br><br>攻击者通过 RCE 漏洞获取服务的远程代码执行权限后，通常会借助 reverse shell 获取容器内任意命令执行能力。|禁止 Unix Shell 执行<br><br>有些基础镜像会动态链接 sh 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用|AppArmor<br>BPF
|                 |              |禁止通过 wget 命令下载文件<br><br>`disable-wget`|ALL|此规则通过禁止执行 wget 命令来限制文件下载。<br><br>攻击者通常会借助 wget 命令从外部下载攻击程序进行随后的攻击（驻留、权限提升、网络扫描、挖矿等）。|禁止 wget 执行<br><br>有些基础镜像会动态链接 wget 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用|AppArmor<br>BPF
|                 |              |禁止通过 curl 命令下载文件<br><br>`disable-curl`|ALL|此规则禁止容器进程执行 curl 命令。<br><br>攻击者通常会借助 curl 命令发起网络访问、从外部下载攻击程序进行随后的攻击（驻留、权限提升、网络扫描、挖矿等）。|禁止 curl 执行|AppArmor<br>BPF
|                 |              |禁止通过 chmod 修改文件权限<br><br>`disable-chmod`|ALL|此规则禁止容器进程执行 chmod 命令。<br><br>当攻击者通过漏洞获取容器内的控制权后，通常会尝试下载其他攻击代码、工具到容器内实施进一步的攻击（权限提升、横向渗透、挖矿等）。在这个攻击链路中，攻击者通常会利用 chmod 命令修改文件的执行权限。|禁止 chmod 执行<br><br>有些基础镜像会动态链接 chmod 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用<br><br>（TODO: BPF Enforcer 增加 path_chmod hook 点）|AppArmor<br>BPF
|                 |              |禁止设置文件的可执行属性<br><br>`disable-chmod-x-bit`|ALL|此规则禁止容器进程通过 chmod 相关系统调用，修改文件属性，创建可执行文件。<br><br>当攻击者通过漏洞获取容器内的控制权后，通常会尝试下载其他攻击代码、工具到容器内实施进一步的攻击（权限提升、横向渗透、挖矿等）。在这个攻击链路中，攻击者通常会调用 chmod 相关系统调用(chmod/fchmod/fchmodat/fchmodat2)，设置文件的可执行属性。|禁止通过 chmod 相关系统调用，设置文件的 execute/search 属性。|Seccomp
|                 |              |禁止执行 sudo、su 命令<br><br>`disable-su-sudo`|ALL|此规则禁止容器进程执行 sudo/su 命令进行权限提升。<br><br>当容器内的进程以非 root 用户运行时，攻击者需要先提权至 root 用户进行后续攻击。而 sudo/su 命令是本地提权的常见途径之一。|禁止 sudo、su 执行<br><br>有些基础镜像会动态链接 su 到 /bin/busybox，此情况下还需配合“禁止执行 busybox 命令”策略使用|AppArmor<br>BPF
|                 |限制特定可执行文件|-|ALL|此规则对 “容器信息泄漏缓解” 和 “容器敏感命令限制” 两类策略的使用场景进行了扩充，使用户可以只对容器内的特定可执行文件及其子进程进行限制。<br><br>对指定的可执行文件进行限制，实现两个目的：<br>1). 避免沙箱策略影响容器内应用服务的正常执行<br>2). 对容器内指定可执行文件进行限制，增加攻击者成本和难度。<br><br>例如，可以利用此功能对容器中的 busybox、bash、sh、curl 进行限制，阻止攻击者利用它们来执行敏感操作。与此同时，应用服务的运行则不受沙箱策略的限制，可以正常执行读取 ServiceAccount token 等敏感操作。<br><br>注：受限于 BPF LSM 的实现原理，BPF enforcer 无法提供此功能|为特定可执行文件开启沙箱限制|AppArmor
|**Vulnerability Mitigation**|-|缓解 cgroups & lxcfs 逃逸<br><br>`cgroups-lxcfs-escape-mitigation`|ALL|若用户将宿主机的 cgroupfs 挂载进容器，或使用 lxcfs 为容器提供资源视图。在这两种场景下可能存在容器逃逸风险，攻击者可以在容器内改写 cgroupfs 实施容器逃逸。<br><br>此规则也可用于防御 CVE-2022-0492 漏洞利用。|AppArmor Enforcer 阻止在容器内修改：<br>/\*\*/release_agent, <br>/\*\*/devices/device.allow,<br>/\*\*/devices/\*\*/device.allow, <br>/\*\*/devices/cgroup.procs,<br>/\*\*/devices/\*\*/cgroup.procs,<br>/\*\*/devices/task,<br>/\*\*/devices/\*\*/task,<br><br>BPF Enforcer 阻止在容器内修改：<br>/\*\*/release_agent<br>/\*\*/devices.allow<br>/\*\*/cgroup.procs<br>/\*\*/devices/tasks<br>|AppArmor<br>BPF
|                            |-|缓解通过改写 runc 实现的容器逃逸<br><br>`runc-override-mitigation`|ALL|本策略用于缓解通过改写宿主机 runc 从而实现容器逃逸的漏洞，例如 [CVE-2019-5736](https://github.com/advisories/GHSA-gxmr-w5mj-v8hh)。|禁止改写 /**/runc 文件|AppArmor<br>BPF
|                            |-|缓解利用 Dirty Pipe 漏洞实现的容器逃逸<br><br>`dirty-pipe-mitigation`|ALL|本策略用于防御利用 [CVE-2022-0847 (Dirty Pipe)](https://dirtypipe.cm4all.com/) 漏洞进行容器逃逸的攻击，您可以使用此规则在升级内核前对容器进行加固。<br><br>注：尽管禁用 splice 系统调用可能会对一些软件包产生问题，但对大多数合法应用来说都不会产生影响，因为这个系统调用的使用相对罕见。|禁止调用 splice syscall|Seccomp
|||THIS_IS_A_PLACEHOLDER_PLACEHOLDE|
