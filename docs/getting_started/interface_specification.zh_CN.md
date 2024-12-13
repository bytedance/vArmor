# 接口说明
[English](interface_specification.md) | 简体中文

## VarmorPolicySpec / VarmorClusterPolicySpec

|字段|子字段|子字段|描述|
|---|-----|-----|---|
|target|kind<br />*string*|-|用于指定防护目标的 Workloads 类型。<br />可用值: Deployment, StatefulSet, DaemonSet, Pod。|
|      |name<br />*string*|-|可选字段。用于指定防护目标的对象名称。|
|      |containers<br />*string array*|-|可选字段。用于指定防护目标的容器名，如果为空默认对 Workloads 中的所有容器开启沙箱防护。（不含 initContainers, ephemeralContainers）|
|      |selector<br />*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|可选字段。用于根据标签选择器识别防护目标，并开启沙箱防护。<br /><br />注意 selector 字段与 name 字段互斥，不能同时存在。|
|policy|enforcer<br />*string*|-|指定要使用的 LSM。<br />可用值: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp|
|      |mode<br />*string*|-|用于指定防护模式。<br />可用值：AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth|
|      |enhanceProtect|hardeningRules<br />*string array*|可选字段。用于指定要使用的内置加固规则。|
|      ||attackProtectionRules<br />*[AttackProtectionRules](#attackprotectionrules) array*|可选字段。用于指定要使用的内置规则。|
|      ||vulMitigationRules<br />*string array*|可选字段。用于指定要使用的内置规则。|
|      ||appArmorRawRules<br />*string array*|可选字段。用于设置自定义的 AppArmor 黑名单规则。每条规则必须以逗号结尾，请参考 [AppArmor 语法](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) 进行编写。|
|      ||bpfRawRules<br />*[BpfRawRules](#bpfrawrules)*|可选字段。用于支持用户设置自定义的 BPF 黑名单规则。|
|      ||syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|可选字段。用于支持用户使用 Seccomp enforcer 设置自定义的 Syscall 黑名单规则。请参考 [此文档](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) 创建自定义规则。|
|      ||privileged<br />*bool*|可选字段。当对特权容器进行加固，请务必将此值设置为 true。若为 false，将在 **RuntimeDefault** 模式的基础上构造 AppArmor/BPF Profiles。若为 ture，则在 **AlwaysAllow** 模式的基础上构造 AppArmor/BPF Profiles。<br /><br />注意：当为 true 时，vArmor 不会为目标构造 Seccomp Profiles。（默认值：false）|
|      ||auditViolations<br />*bool*|可选字段. 用于审计违反沙箱策略的行为。此特性当前支持 AppArmor 和 BPF enforcers，任何违反沙箱策略的行为都会被记录到宿主机的 `/var/log/varmor/violations.log` 文件中。（默认值：false）|
|      |modelingOptions|duration<br />*int*|动态建模的时间。（单位：分钟）[实验功能]|
|updateExistingWorkloads<br />*bool*|-|-|可选字段。用于指定是否对符合条件的工作负载进行滚动更新，从而在 Policy 创建或删除时，对目标工作负载开启或关闭防护。（默认值：false）<br /><br />注意：vArmor 只会对 Deployment、StatefulSet、DaemonSet 类型的工作负载进行滚动更新，如果 `.spec.target.kind` 为 Pod，需要您自行重建 Pod 来开启或关闭防护。|
|      ||PLACEHOLDER_PLACEHOLD|

## AttackProtectionRules

|字段|描述|
|---|----|
|rules<br />*string array*|要使用的内置规则列表。|
|targets<br />*string array*|可选字段。对指定可执行文件列表开启 rules 中的内置规则。可执行文件必须使用全路径，并且仅 AppArmor enforcer 支持此特性。|
|PLACEHOLDER||

## BpfRawRules

|字段|子字段|描述|
|---|-----|---|
|files<br />*FileRule array*    |pattern<br />*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配文件路径、文件名称。|
|                             |permissions<br />*string array*|禁止使用的权限，其中 write 权限隐式包含 append, rename, hard link, symbol link 权限。<br />可用值：`all(*), read(r), write(w), append(a), exec(e)`|
|processes<br />*FileRule array*|-|同上|
|network<br />*NetworkRule*     |sockets<br />*[NetworkSocketRule](#networksocketrule) array*|对套接字 [SOCKET(2)](https://man7.org/linux/man-pages/man2/socket.2.html) 创建行为进行访问控制。|
|                               |egresses<br />*[NetworkEgressRule](#networkegressrule) array*|对外联请求进行访问控制。|
|ptrace<br />*PtraceRule*       |strictMode<br />*bool*|可选字段。如果设置为 false，将允许进程对同一容器内其他进程执行 trace、read 操作，以及允许进程被同一容器内其他进程执行 traceby、readby 操作。如果设置为 true，则将禁止容器内所有进程的 trace、read、traceby、readby 操作。（默认值：false）|
|                             |permissions<br />*string array*|禁止使用 ptrace 相关操作。<br />可用值: `all(*), trace, read, traceby, readby`<br />- trace: 禁止跟踪其他进程<br />- read: 禁止读取其他进程<br />- traceby: 禁止被其他进程跟踪，宿主机进程除外<br />- readby: 禁止被其他进程读取，宿主机进程除外|
|mounts<br />*MountRule array*  |sourcePattern<br />*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配 [MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) 的 source，[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) 的 target，以及 MOVE_MOUNT(2) 的 from_pathname。|
|                             |fstype<br />*string*|任意字符串（最大长度 16 bytes），用于匹配文件系统类型，`*` 代表匹配任意文件系统。|
|                             |flags<br />*string array*|禁止使用的 mount flags，它们与 AppArmor 的 [MOUNT FLAGS](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) 类似。<br />可用值：`all(*), ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`|
|PLACEHOLDER_|PLACEHOLDER_PLACEHOD|

## NetworkSocketRule
|字段|描述|
|---|----|
|domains<br />*string array*|可选字段。用于指定禁止使用的套接字通信域。<br />可用值：`all(*), unix, inet, ax25, ipx, appletalk, netrom, bridge, atmpvc, x25, inet6, rose, netbeui, security, key, netlink, packet, ash, econet, atmsvc, rds, sna, irda, pppox, wanpipe, llc, ib, mpls, can, tipc, bluetooth, iucv, rxrpc, isdn, phonet, ieee802154, caif, alg, nfc, vsock, kcm, qipcrtr, smc, xdp, mctp`|
|types<br />*string array*|可选字段。用于指定禁止使用的套接字通信语义。<br />可用值：`all(*), stream, dgram, raw, rdm, seqpacket, dccp, packet`|
|protocols<br />*string array*|可选字段。用于指定禁止使用的套接字特定协议。<br />可用值：`all(*), icmp, tcp, udp`<br /><br />注意：protocols 和 types 字段互斥，不能同时存在。|
|PLACEHOLDER|

## NetworkEgressRule

|字段|描述|
|---|----|
|ipBlock<br />*string*|可选字段。可使用任意标准的 CIDR，支持 IPv6。用于对指定 CIDR 范围内的 IP 地址进行外联限制，例如<br />* 192.168.1.1/24 代表 192.168.1.0 ~ 192.168.1.255 范围内的 IP 地址。<br />* 2001:db8::/32 代表 2001:db8:: ~ 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 范围内的 IP 地址。|
|ip<br />*string*|可选字段。任意标准的 IP 地址，支持 IPv6，用于对特定的 IP 地址进行外联限制。<br /><br />注意：同一个 NetworkEgressRule 中，IP 和 IPBlock 字段互斥，不能同时存在。|
|port<br />*int*|可选字段。用于对指定的端口进行外联限制，当为空时，默认对（匹配 IP 地址的）所有端口进行外联限制。否则仅对特定端口进行控制。<br />可用值：`1~65535`|
|PLACEHOLDER||
