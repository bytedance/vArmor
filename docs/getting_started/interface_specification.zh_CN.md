# 接口说明
[English](interface_specification.md) | 简体中文


## VarmorPolicy / VarmorClusterPolicy

| 字段 | 描述 |
|-----|------|
|apiVersion<br />*string*|APIVersion 定义了对象这种表示形式的带版本的模式。服务器应将识别出的模式转换为最新的内部值，并可拒绝识别不出的值。更多信息：https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources|
|kind<br />*string*|Kind 是一个字符串值，代表此对象所表示的 REST 资源。服务器可以从客户端提交请求的端点推断出该值。不可更新。采用驼峰命名法。更多信息：https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds|
|metadata<br />*ObjectMeta*|标准对象的元数据。更多信息：https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata|
|spec<br />*[VarmorPolicySpec](#varmorpolicyspec)*|Spec 描述了用于加固目标工作负载的所需策略。|
|status<br />*[VarmorPolicyStatus](#varmorpolicystatus)*|Status 描述了所观察到的策略状态。|

## VarmorPolicySpec

| 字段 | 描述 |
|-----|------|
|target<br />*[Target](#target)*|Target 指定了你想要加固的工作负载及其容器。|
|policy<br />*[Policy](#policy)*|Policy 指定了你想要使用哪些强制访问控制器、模式，以及规则来加固目标。|
|updateExistingWorkloads<br />*bool*|可选字段。UpdateExistingWorkloads 用于指定是否对符合条件的工作负载进行滚动更新，从而在 Policy 创建或删除时，对目标工作负载开启或关闭防护。（默认值：false）<br /><br />注意：vArmor 只会对 Deployment、StatefulSet、DaemonSet 类型的工作负载进行滚动更新，如果 `.spec.target.kind` 为 Pod，需要您自行重建 Pod 来开启或关闭防护。

### Target

| 字段 | 描述 |
|-----|------|
|kind<br />*string*|Kind 用于指定防护目标的类型。<br />可用值: Deployment, StatefulSet, DaemonSet, Pod。|
|name<br />*string*|可选字段。Name 用于在策略的命名空间或所有命名空间中指定特定的工作负载。|
|containers<br />*string array*|可选字段。Containers 用于指定容器的名称。如果为空，将对工作负载内的所有容器（不包括 initContainers 和 ephemeralContainers）启用沙箱保护。|
|selector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|可选字段。Selector 是一个标签选择器，用于选择策略命名空间或所有命名空间中的工作负载。此字段遵循标准的标签选择器语义。<br /><br />请注意，selector 字段与 name 字段互斥。|

### Policy

| 字段 | 描述 |
|-----|------|
|enforcer<br />*string*|Enforcer 指定使用哪种安全机制进行强制访问控制。 <br />可用值：AppArmor, BPF, Seccomp, NetworkProxy, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, BPFNetworkProxy, AppArmorBPFSeccomp|
|mode<br />*string*|Mode 用于指定防护模式。<br />可用值：AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth|
|enhanceProtect<br />*[EnhanceProtect](#enhanceprotect)*|EnhanceProtect 用于配置 EnhanceProtect 模式。它允许您设置内置规则和自定义规则，以生成保护工作负载的配置文件（即 Profile），并控制配置文件的行为（例如，审计、允许违规行为）。|
|modelingOptions<br />*[ModelingOptions](#modelingoptions)*|ModelingOptions 用于配置 BehaviorModeling 模式。|
|defenseInDepth<br />*[DefenseInDepth](#defenseindepth)*|DefenseInDepth 用于配置 DefenseInDepth 模式。|
|networkProxyConfig<br />*[NetworkProxyConfig](#networkproxyconfig)*|NetworkProxyConfig 用于配置 NetworkProxy enforcer 的网络代理边车容器。|

## EnhanceProtect

| 字段 | 描述 |
|-----|------|
|hardeningRules<br />*string array*|可选字段。HardeningRules 用于指定要使用的加固类内置规则。|
|attackProtectionRules<br />*[AttackProtectionRules](#attackprotectionrules) array*|可选字段。AttackProtectionRules 用于指定要使用的攻击防护类内置规则。|
|vulMitigationRules<br />*string array*|可选字段。VulMitigationRules 用于指定要使用的漏洞缓解类内置规则。|
|appArmorRawRules<br />*[AppArmorRawRules](#apparmorrawrules) array*|可选字段。AppArmorRawRules 用于设置自定义的 AppArmor 规则。|
|bpfRawRules<br />*[BpfRawRules](#bpfrawrules) array*|可选字段。BpfRawRules 用于设置自定义的 BPF 规则。|
|syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|可选字段。SyscallRawRules 用于设置自定义的 Seccomp 规则。请参考 https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp。|
|networkProxyRawRules<br />*[NetworkProxyRules](#networkproxyrules)*|可选字段。NetworkProxyRawRules 用于设置由 NetworkProxy enforcer 通过 sidecar 代理强制执行的网络访问控制规则。这些规则在应用协议层面（L4 域名/SNI 匹配、L7 HTTP 匹配）运行，且独立于 BPF 内核级网络规则。<br /><br />此字段仅在 enforcer 包含 "NetworkProxy" 时生效。|
|privileged<br />*bool*|可选字段。Privileged 用于确定该策略是否适用于特权容器。如果设置为 false，**EnhanceProtect** 模式将在 **RuntimeDefault** 模式之上构建 AppArmor 或 BPF 配置文件。否则，它将在 **AlwaysAllow** 模式之上构建 AppArmor 或 BPF 配置文件。（默认值：false）<br /><br />请注意，如果设置为 true，vArmor 将不会为目标工作负载构建 Seccomp 配置文件。|
|auditViolations<br />*bool*|可选字段。AuditViolations 用于决定是否对违反强制访问控制规则的操作进行审计。如果设置了此字段，任何检测到的违规行为都将记录到主机中的 `/var/log/varmor/violations.log` 文件中。若 allowViolations 设为 true，事件动作会被标记为 `AUDIT`。否则，事件动作会被标记为 `DENIED`。<br /><br />请注意，当 allowViolations 字段设置为 false 时，Seccomp 强制访问控制器不支持对违规行为进行审计。（默认值：false）|
|allowViolations<br />*bool*|可选字段。AllowViolations 用于决定是否允许违反强制访问控制规则的操作。如果设置了此字段，任何检测到的违规行为都将被允许而不是被阻止。（默认值：false）|

### AttackProtectionRules

| 字段 | 描述 |
|-----|------|
|rules<br />*string array*|Rules 是要使用的攻击防护类内置规则列表。|
|targets<br />*string array*|可选字段。Targets 指定规则所适用的可执行文件。可执行文件必须使用全路径。此功能仅在使用 AppArmor enforcer 时有效。|

### AppArmorRawRules

| 字段 | 描述 |
|-----|------|
|rules<br />*string*|Rules 设置自定义的 AppArmor 规则. 您应当自行确保自定义规则符合 [AppArmor 语法](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) 。|
|targets<br />*string*|可选字段。Targets 指定规则所适用的可执行文件。可执行文件必须使用全路径。|

### BpfRawRules

| 字段 | 描述 |
|-----|------|
|files<br />*[FileRule](#filerule) array*|可选字段。Files 指定了文件访问控制规则。|
|processes<br />*[FileRule](#filerule) array*|可选字段。Processes 指定了可执行文件访问控制规则。|
|network<br />*[NetworkRule](#networkrule)*|可选字段。Network 指定了网络访问控制规则。|
|ptrace<br />*[PtraceRule](#ptracerule)*|可选字段。Ptrace 指定了 ptrace 相关访问控制规则。|
|mounts<br />*[MountRule](#mountrule) array*|可选字段。Mounts 指定了文件挂载访问控制规则。|

### FileRule

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|pattern<br />*string*|Pattern 可以是符合策略语法的任意字符串（最大长度为 128 字节），用于匹配文件路径和文件名。|
|permissions<br />*string array*|Permissions 用于指定文件权限。<br />可用值：`all(*), read(r), write(w), append(a), exec(e)`|

### NetworkRule

| 字段 | 描述 |
|-----|------|
|sockets<br />*[NetworkSocketRule](#networksocketrule) array*|可选字段。Sockets 定义了网络套接字规则列表，用于匹配 socket (2) 操作。|
|egress<br />*[NetworkEgressRule](#networkegressrule)*|可选字段。Egress 定义了网络出口规则，用于匹配 connect (2) 的流量。|

### PtraceRule

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|strictMode<br />*bool*|可选字段。StrictMode 用于指示是否对所有源进程和目标进程限制 ptrace 操作。如果设置为 false，将允许进程对同一容器内其他进程执行 trace、read 操作，以及允许进程被同一容器内其他进程执行 traceby、readby 操作。如果设置为 true，则将禁止容器内所有进程的 trace、read、traceby、readby 操作。(默认值：false)|
|permissions<br />*string array*|Permissions 用于指明目标容器的哪些与 ptrace 相关的权限应受到限制。<br />可用值：`all(*), trace, traceby, read, readby` <br /><br />- trace: 禁止跟踪其他进程<br />- read: 禁止读取其他进程<br />- traceby: 禁止被其他进程跟踪（宿主机进程除外） <br />- readby: 禁止被其他进程读取（宿主机进程除外）<br /><br />trace 和 traceby 权限用于写操作，或其他更危险的操作。例如使用 ptrace 附加到另一个进程，或调用 process_vm_writev(2)。<br /><br />read, readby 权限用于读操作，或其他危险程度较低的操作。例如 get_robust_list(2); kcmp(2); 读取 /proc/pid/auxv; 读取 /proc/pid/environ; 读取 /proc/pid/stat; 读取 /proc/pid/ns/* 等。|

### MountRule

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|sourcePattern<br />*string*|SourcePattern 可以是符合策略语法的任意字符串（最大长度为 128 字节），用于匹配 mount (2) 的源参数、umount (2) 的目标参数以及 move_mount (2) 的 from_pathname 参数。|
|fstype<br />*string*|Fstype 用于指定要进行访问控制的文件系统类型（最大长度为 16 字节）。它可以是 `*`，以匹配任何类型。|
|flags<br />*string array*|Flags 用于指定要进行访问控制的挂载标志. 它们与 AppArmor 的 [MOUNT FLAGS LIST](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) 类似. <br />可用值：`all(*), ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`|

### NetworkSocketRule

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|domains<br />*string array*|可选字段。Domains 指定了套接字的通信域。<br />可用值：`all(*), unix, inet, ax25, ipx, appletalk, netrom, bridge, atmpvc, x25, inet6, rose, netbeui, security, key, netlink, packet, ash, econet, atmsvc, rds, sna, irda, pppox, wanpipe, llc, ib, mpls, can, tipc, bluetooth, iucv, rxrpc, isdn, phonet, ieee802154, caif, alg, nfc, vsock, kcm, qipcrtr, smc, xdp, mctp`|
|types<br />*string array*|可选字段。Types 指定了套接字的通信语义。<br />可用值：`all(*), stream, dgram, raw, rdm, seqpacket, dccp, packet`|
|protocols<br />*string array*|可选字段。Protocols 指定了要与套接字一起使用的特定协议。<br />可用值：`all(*), icmp, tcp, udp`<br /><br />请注意，protocols 和 types 字段互斥。|

### NetworkEgressRule

| 字段 | 描述 |
|-----|------|
|toDestinations<br />*[Destination](#destination) Array*|可选字段。ToDestinations 描述了特定端口的 IP 地址或 IP 地址段，用于匹配其流量。请确保每个 IP/CIDR 目标是唯一的，以避免配置模糊。|
|toServices<br />*[Service](#service) Array*|可选字段。ToServices 描述了 Kubernetes Service 及其 Endpoint，用于匹配其流量。请确保 Service 规则间的选择器不重叠。重叠的规则可能会导致未定义行为。|
|toPods<br />*[Pod](#pod) Array*|可选字段。ToPods 用于描述特定端口的 Pod，以匹配其流量。请确保 Pod 规则间的选择器不重叠。重叠的规则可能会导致未定义行为。

<br />请注意:
<br />- toDestinations、toEntities、toServices 和 toPods 字段是逻辑“或”关系。
<br />- 在同一字段内，多个规则间也处于逻辑“或”关系。
<br />- 针对同一 Pod、Service、IP 的重叠规则可能会导致意外的端口组合或冲突。
<br />- 系统不保证对重叠目标进行重复数据删除或冲突解决。用户必须确保这些字段中的规则不会重复定义相同的 Pod、Service、IP，以避免出现不可预测的流量控制行为。
<br />- toServices 规则仅在 Kubernetes 版本为 1.21 或更高版本时生效。
<br />- toPods 规则仅在启用 [Pod Egress Control 功能](installation.zh_CN.md#开启-pod-出口控制)时生效。

### Destination

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|ip<br />*string*|可选字段。IP 在特定 IP 上定义此规则。请使用有效的 IP 文本表示形式，或诸如 `pod-self`、`unspecified` 或 `localhost` 特殊实体。请注意，ip 字段和 cidr 字段是互斥的。<br /><br />- pod-self: 表示 Pod 自身 IP 地址的实体。对于 IPv4 和 IPv6，每个 Pod 最多可分配 1 个地址。<br />- unspecified: 表示全零地址的实体，具体来说，就是 0.0.0.0 和 ::。 它的全称是未指定地址（Unspecified Address），指的是绑定到所有接口。<br />- localhost: 代表环回地址的实体，具体来说，就是 127.0.0.1 和 ::1。|
|cidr<br />*string*|可选字段。CIDR 在特定的无类别域间路由上定义了此规则。请注意，IP 字段和无类别域间路由字段是互斥的。|
|ports<br />*[Port](#port) array*|可选字段。Ports 在特定端口上定义此规则。此列表中的每个条目使用逻辑 “或” 进行组合。如果此字段为空或不存在，则此规则匹配所有端口。如果此字段存在且至少包含一个条目，则此规则匹配列表中的所有端口。|

### Service

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|namespace<br />*string*|可选字段。Namespace 用于指定 Service 所在的命名空间。|
|name<br />*string*|可选字段。Name 通过名称和命名空间对来选择 Service。|
|serviceSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|可选字段。ServiceSelector 是一个标签选择器，用于选择 Service。该字段遵循标准的标签选择器语义。它会选择 namespace 中与 serviceSelector 匹配的 Service。如果 namespace 为空或未指定，它会选择所有命名空间中与 serviceSelector 匹配的 Service。请注意，serviceSelector 字段与 name 字段是互斥的。|

### Pod

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 通过值的组合来确定规则的行为。<br />可用值：`deny, audit`|
|namespace<br />*string*|可选字段。Namespace 用于指定 Pod 所在的命名空间。|
|podSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|PodSelector 是一个标签选择器，用于选择 Pod。该字段遵循标准的标签选择器语义。它会选择 namespace 中与 podSelector 匹配的 Pod。如果 namespace 为空或未指定，它会选择所有命名空间中与 podSelector 匹配的 Pod。|
|ports<br />*[Port](#port) array*|可选字段。Ports 在特定端口上定义此规则。此列表中的每个条目使用逻辑 “或” 进行组合。如果此字段为空或不存在，则此规则匹配所有端口。如果此字段存在且至少包含一个条目，则此规则匹配列表中的所有端口。|

### Port

| 字段 | 描述 |
|-----|------|
|port<br />*uint16*|Port 是用于匹配流量的端口号。端口号必须在 [1, 65535] 范围内。
|endPort<br />*uint16*|可选字段。如果设置了结束端口（endPort），则表示端口范围从起始端口（port）到结束端口（endPort）。结束端口必须大于或等于起始端口，且必须在 [1, 65535] 范围内。|

## ModelingOptions

| 字段 | 描述 |
|-----|------|
|duration<br />*int*| Duration 是建模的时长（以分钟为单位）。建模时长从策略创建时刻开始计算，仅当当前时间早于预期建模完成时间时有效。该字段支持动态调整，可用于尽早结束建模、延长建模时间或重新启动建模，且取值不能为零。|

## DefenseInDepth

| 字段 | 描述 |
|-----|------|
|appArmor<br />*[AppArmorProfile](#apparmorprofile)*|可选字段。AppArmor 为默认拒绝访问控制指定 AppArmor 配置文件和其他自定义规则。|
|seccomp<br />*[SeccompProfile](#seccompprofile)*|可选字段。Seccomp 为默认拒绝访问控制指定 Seccomp 配置文件和其他自定义规则。|
|networkProxy<br />*[NetworkProxyRules](#networkproxyrules)*|可选字段。NetworkProxy 用于设置由 NetworkProxy enforcer 通过 sidecar 代理强制执行的网络访问控制规则。这些规则在应用协议层面（L4 域名/SNI 匹配、L7 HTTP 匹配）运行，且独立于 BPF 内核级网络规则。<br /><br />此字段仅在 enforcer 包含 "NetworkProxy" 时生效。|
|allowViolations<br />*bool*|可选字段。AllowViolations 用于确定是否允许违反强制访问控制规则的操作。如果设置了此字段，任何检测到的违规行为将被允许而非阻止，与此同时会生成并记录一个 `ALLOWED` 动作的审计事件。这可用于收集违规情况，以改进默认拒绝访问控制的配置文件。如果未设置此字段，任何检测到的违规行为将被阻止，并生成和记录一个 `DENIED` 动作的审计事件。(默认值：false)

### AppArmorProfile

| 字段 | 描述 |
|-----|------|
|profileType<br />*string*|ProfileType 指明将应用哪种 AppArmor 配置文件。有效选项包括：BehaviorModel - 将使用通过行为建模模式生成的配置文件。Custom - 将使用在customProfile 字段中定义的自定义配置文件。|
|customProfile<br />*string*|可选字段。CustomProfile 保存用户定义的 AppArmor 配置文件内容。它必须是符合 AppArmor 语法的有效配置文件。如果你希望 vArmor 自动将该配置文件应用于目标工作负载，配置文件的名称必须与 ArmorProfile 对象名称匹配。例如：<br /><br /> abi \<abi/3.0\>,<br /> #include \<tunables/global\><br /> profile varmor-demo-demo-4 flags=(attach_disconnected,mediate_deleted) \{<br />\}<br /><br />配置文件名称 “varmor-demo-demo-4” 与 ArmorProfile 对象名称相同。|
|appArmorRawRules<br />*[AppArmorRawRules](#apparmorrawrules) array*|可选字段。appArmorRawRules 指定自定义的 AppArmor 规则。这些规则将被添加到你指定的 AppArmor 配置文件末尾。|

### SeccompProfile

| 字段 | 描述 |
|-----|------|
|profileType<br />*string*|ProfileType 指明将应用哪种 Seccomp 配置文件。有效选项包括：BehaviorModel - 将使用通过行为建模模式生成的配置文件。Custom - 将使用在 customProfile 字段中定义的自定义配置文件。|
|customProfile<br />*string*|可选字段。CustomProfile 保存用户定义的 Seccomp 配置文件内容。它必须是符合 Seccomp 语法的有效配置文件。请参考[此文档](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp)创建自定义配置文件。|
|syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec/specs-go#LinuxSyscall) array*|可选字段。SyscallRawRules 指定自定义 Seccomp 规则。这些规则将添加到您指定的 Seccomp 配置文件末尾。|

## NetworkProxyConfig

| 字段 | 描述 |
|-----|------|
|mitm<br />*[MITMConfig](#mitmconfig)*|可选字段。配置 TLS Man-in-the-Middle，用于在 HTTP 层面检查加密的 HTTPS 流量。vArmor 自动为每个策略生成自签名 CA，并将 CA bundle 注入应用容器。|
|resources<br />*[ProxyResourceOverride](#proxyresourceoverride)*|可选字段。覆盖代理边车容器的默认资源请求和限制。启用 MITM 时，会自动使用更高的默认值。使用此字段可为特定工作负载需求微调资源配额。|
|proxyUID<br />**int64*|可选字段。ProxyUID 指定代理边车进程在运行时所使用的用户标识（UID）。该用户标识必须与目标应用程序的用户标识不同，因为 iptables 规则依赖此用户标识进行流量区分。此字段在策略创建后无法修改。（默认值：1337）|
|proxyPort<br />**uint16*|可选字段。ProxyPort 用于指定代理边车进程所监听的端口。若目标应用的监听端口与其冲突，可另行指定其他端口。该字段在策略创建后无法修改。（默认值：15001）|
|proxyAdminPort<br />**uint16*|可选字段。ProxyAdminPort 用于指定代理边车进程处理管理请求的监听端口。若目标应用的监听端口与其冲突，可指定其他端口。该字段在策略创建后无法修改。（默认值：15000）|

### MITMConfig

| 字段 | 描述 |
|-----|------|
|domains<br />*string array*|指定哪些 TLS 连接应被终止以进行 L7 检查。只有到这些域名的连接才会被解密；所有其他 TLS 流量原样通过。支持精确匹配（"api.openai.com"）和通配符（"*.openai.com"）。通配符匹配遵循 RFC 6125。|
|headerMutations<br />*[HeaderMutation](#headermutation) array*|可选字段。逐域名的 HTTP 头部注入规则。每个条目的 domain 必须字面等于 `domains` 中的某一项（不执行通配符展开）。通常用于向特定上游服务的请求中注入 API 密钥或认证令牌，实现代理层的集中式凭证管理。|

### HeaderMutation

| 字段 | 描述 |
|-----|------|
|domain<br />*string*|指定此变异应用于哪个 MITM 域名。必须字面等于 `MITMConfig.Domains` 中的某一项。|
|headers<br />*[HeaderAction](#headeraction) array*|要为此域名注入的头部列表。|

### HeaderAction

| 字段 | 描述 |
|-----|------|
|name<br />*string*|HTTP 头部名称（例如 "Authorization"、"x-api-key"）。|
|value<br />*string*|可选字段。字面头部值。用于非敏感值。与 `secretRef` 互斥。|
|secretRef<br />*[SecretKeyRef](#secretkeyref)*|可选字段。引用一个 Kubernetes Secret 键，该键包含头部值。用于 API 密钥或令牌等敏感值。被引用的 Secret 必须由用户在目标工作负载所在的同一命名空间中预先创建。控制器在 reconcile 时读取 Secret 值，并将其内联到 Envoy xDS 配置中。与 `value` 互斥。|

### SecretKeyRef

| 字段 | 描述 |
|-----|------|
|name<br />*string*|Kubernetes Secret 的名称。|
|key<br />*string*|Secret 数据映射中的键。|

### ProxyResourceOverride

| 字段 | 描述 |
|-----|------|
|requests<br />*ResourceList*|可选字段。覆盖代理边车容器的资源请求。仅覆盖指定的资源类型（cpu、memory）；未设置的字段保留内置默认值。|
|limits<br />*ResourceList*|可选字段。覆盖代理边车容器的资源限制。仅覆盖指定的资源类型（cpu、memory）；未设置的字段保留内置默认值。|

内置默认值：

| 模式 | CPU requests | Memory requests | CPU limits | Memory limits |
|------|-------------|----------------|-----------|--------------|
| 非 MITM | 50m | 64Mi | 500m | 256Mi |
| MITM | 100m | 128Mi | 1000m | 512Mi |

## VarmorPolicyStatus

| 字段 | 描述 |
|-----|------|
|profileName<br />*string*|ProfileName 是由策略生成的 AppArmor、BPF 和 Seccomp 配置文件的名称。对于命名空间策略，其格式为 `varmor-{命名空间}-{名称}` ；对于集群范围的策略，其格式为 `varmor-cluster-{命名空间}-{名称}` 。它等同于由策略创建的 ArmorProfile 对象的名称。|
|conditions<br />*[VarmorPolicyCondition](#varmorpolicycondition) array*|Conditions 是一个条件列表，用于指示策略的状态。它可以包含诸如 Created, Updated, Ready 等条件。|
|ready<br />*bool*|Ready 用于指示策略配置文件是否已加载。|
|phase<br />*string*|Phase 用于指示策略的处理阶段。可能的值：Pending, Modeling, Completed, Protecting, Error。<br /><br />注意：您还可以通过获取与当前 VarmorPolicy、VarmorClusterPolicy 对象相对应的ArmorProfile/status 资源，来查明哪个 varmor-agent 出现错误。

### VarmorPolicyCondition

| 字段 | 描述 |
|-----|------|
|type<br />*string*|策略的条件类型。<br />可能的值： Created, Updated, Ready|
|status<br />*ConditionStatus*|条件的状态。<br />可能的值：True, False, Unknown。|
|lastTransitionTime<br />*Time*|该条件上次从一个状态转换为另一个状态的时间。|
|reason<br />*string*|该条件上次发生转换的原因。|
|message<br />*string*|便于人类阅读的消息，用于说明转换的详细信息。|

## NetworkProxyRules

| 字段 | 描述 |
|-----|------|
|egress<br />*[NetworkProxyEgress](#networkproxyegress)*|可选字段。Egress 指定出站（egress）访问控制规则。|

### NetworkProxyEgress

| 字段 | 描述 |
|-----|------|
|defaultAction<br />*string*|DefaultAction 指定未匹配任何规则的连接的默认动作。可用值：deny, allow|
|rules<br />*[NetworkProxyEgressRule](#networkproxyegressrule) array*|可选字段。Rules 指定 L4（连接层）出站访问控制规则。|
|httpRules<br />*[NetworkProxyHTTPRule](#networkproxyhttprule) array*|可选字段。HTTPRules 指定 L7（HTTP 请求层）出站访问控制规则。|

### NetworkProxyEgressRule

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 决定规则的行为。可用值：allow, deny, audit。|
|description<br />*string*|可选字段。Description 是规则用途的人类可读描述。|
|ip<br />*string*|可选字段。IP 指定单个目标 IP 地址。与 cidr 字段互斥。|
|cidr<br />*string*|可选字段。CIDR 指定目标 IP 范围。与 ip 字段互斥。|
|ports<br />*[Port](#port) array*|可选字段。Ports 将规则限制为特定的目标端口。如果为空，则匹配所有端口。|

### NetworkProxyHTTPRule

| 字段 | 描述 |
|-----|------|
|qualifiers<br />*string array*|Qualifiers 决定规则的行为。可用值：allow, deny, audit。|
|description<br />*string*|可选字段。Description 是规则用途的人类可读描述。|
|match<br />*[HTTPMatch](#httpmatch)*|Match 描述 HTTP/HTTPS 流量的匹配条件。|

### HTTPMatch

| 字段 | 描述 |
|-----|------|
|hosts<br />*string array*|可选字段。Hosts 指定要匹配的目标服务域名。支持精确匹配（"api.openai.com"）和通配符（"*.openai.com"）。多个值之间为逻辑“或”关系。|
|ports<br />*[Port](#port) array*|可选字段。Ports 将规则限制为特定的目标端口。|
|paths<br />*[HTTPPathMatch](#httppathmatch) array*|可选字段。Paths 指定 HTTP 请求路径匹配。对于 HTTPS 流量，路径匹配需要配置 MITM。|
|methods<br />*string array*|可选字段。Methods 指定要匹配的 HTTP 方法（例如 GET、POST）。对于 HTTPS 流量，方法匹配需要配置 MITM。|

### HTTPPathMatch

| 字段 | 描述 |
|-----|------|
|exact<br />*string*|可选字段。Exact 指定要精确匹配的路径字符串。|
|prefix<br />*string*|可选字段。Prefix 指定要匹配的路径前缀。|
