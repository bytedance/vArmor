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
|enforcer<br />*string*|Enforcer 指定使用哪种安全机制进行强制访问控制。 <br />可用值：AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp|
|mode<br />*string*|Mode 用于指定防护模式。<br />可用值：AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth|
|enhanceProtect<br />*[EnhanceProtect](#enhanceprotect)*|EnhanceProtect 用于配置 EnhanceProtect 模式。它允许您设置内置规则和自定义规则，以生成保护工作负载的配置文件（即 Profile），并控制配置文件的行为（例如，审计、允许违规行为）。|
|modelingOptions<br />*[ModelingOptions](#modelingoptions)*|ModelingOptions 用于配置 BehaviorModeling 模式。|
|defenseInDepth<br />*[DefenseInDepth](#defenseindepth)*|DefenseInDepth 用于配置 DefenseInDepth 模式。

## EnhanceProtect

| 字段 | 描述 |
|-----|------|
|hardeningRules<br />*string array*|可选字段。HardeningRules 用于指定要使用的加固类内置规则。|
|attackProtectionRules<br />*[AttackProtectionRules](#attackprotectionrules) array*|可选字段。AttackProtectionRules 用于指定要使用的攻击防护类内置规则。|
|vulMitigationRules<br />*string array*|可选字段。VulMitigationRules 用于指定要使用的漏洞缓解类内置规则。|
|appArmorRawRules<br />*[AppArmorRawRules](#apparmorrawrules) array*|可选字段。AppArmorRawRules 用于设置自定义的 AppArmor 规则。|
|bpfRawRules<br />*[BpfRawRules](#bpfrawrules) array*|可选字段。BpfRawRules 用于设置自定义的 BPF 规则。|
|syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|可选字段。SyscallRawRules 用于设置自定义的 Seccomp 规则。请参考 https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp。|
|privileged<br />*bool*|可选字段。Privileged 用于确定该策略是否适用于特权容器。如果设置为 false，**EnhanceProtect** 模式将在 **RuntimeDefault** 模式之上构建 AppArmor 或 BPF 配置文件。否则，它将在 **AlwaysAllow** 模式之上构建 AppArmor 或 BPF 配置文件。（默认值：false）<br /><br />请注意，如果设置为 true，vArmor 将不会为目标工作负载构建 Seccomp 配置文件。|
|auditViolations<br />*bool*|可选字段。AuditViolations 用于决定是否对违反强制访问控制规则的操作进行审计。如果设置了此字段，任何检测到的违规行为都将记录到主机中的 `/var/log/varmor/violations.log` 文件中。<br />请注意，当 allowViolations 字段设置为 false 时，Seccomp 强制访问控制器不支持对违规行为进行审计。（默认值：false）|
|allowViolations<br />*bool*|可选字段。AllowViolations 用于决定是否允许违反强制访问控制规则的操作。如果设置了此字段，任何检测到的违规行为都将被允许而不是被阻止，与此同时将生成并记录一个 “ALLOWED” 类型的审计事件。（默认值：false）|

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
|strictMode<br />*bool*|可选字段。StrictMode 用于指示是否对所有源进程和目标进程限制 ptrace 操作。如果设置为 false，将允许进程对同一容器内其他进程执行 trace、read 操作，以及允许进程被同一容器内其他进程执行 traceby、readby 操作。如果设置为 true，则将禁止容器内所有进程的 trace、read、traceby、readby 操作。(默认值：false)|
|permissions<br />*string array*|Permissions 用于指明目标容器的哪些与 ptrace 相关的权限应受到限制。<br />可用值：`all(*), trace, traceby, read, readby` <br /><br />- trace: 禁止跟踪其他进程<br />- read: 禁止读取其他进程<br />- traceby: 禁止被其他进程跟踪（宿主机进程除外） <br />- readby: 禁止被其他进程读取（宿主机进程除外）<br /><br />trace 和 traceby 权限用于写操作，或其他更危险的操作。例如使用 ptrace 附加到另一个进程，或调用 process_vm_writev(2)。<br /><br />read, readby 权限用于读操作，或其他危险程度较低的操作。例如 get_robust_list(2); kcmp(2); 读取 /proc/pid/auxv; 读取 /proc/pid/environ; 读取 /proc/pid/stat; 读取 /proc/pid/ns/* 等。|

### MountRule

| 字段 | 描述 |
|-----|------|
|sourcePattern<br />*string*|SourcePattern 可以是符合策略语法的任意字符串（最大长度为 128 字节），用于匹配 mount (2) 的源参数、umount (2) 的目标参数以及 move_mount (2) 的 from_pathname 参数。|
|fstype<br />*string*|Fstype 用于指定要进行访问控制的文件系统类型（最大长度为 16 字节）。它可以是 `*`，以匹配任何类型。|
|flags<br />*string array*|Flags 用于指定要进行访问控制的挂载标志. 它们与 AppArmor 的 [MOUNT FLAGS LIST](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) 类似. <br />可用值：`all(*), ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`|

### NetworkSocketRule

| 字段 | 描述 |
|-----|------|
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
<br />- toServices 和 toPods 规则仅在开启 **podServiceEgressControl 特性**时生效，详见[开启 Pod 和 Service 出口控制](../getting_started/installation.zh_CN.md#开启-pod-和-service-出口控制)。

### Destination

| 字段 | 描述 |
|-----|------|
|ip<br />*string*|可选字段。IP 在特定 IP 上定义此规则。请使用有效的 IP 文本表示形式，或诸如 `pod-self`、`unspecified` 或 `localhost` 特殊实体。请注意，ip 字段和 cidr 字段是互斥的。|
|cidr<br />*string*|可选字段。CIDR 在特定的无类别域间路由上定义了此规则。请注意，IP 字段和无类别域间路由字段是互斥的。<br /><br />- pod-self: 一个表示 Pod 自身 IP 地址的实体。对于 IPv4 和 IPv6，每个 Pod 最多可分配 1 个地址。<br />- unspecified: 一种表示全零地址的实体，具体来说，就是0.0.0.0和::。 它的全称是未指定地址（Unspecified Address），指的是绑定到所有接口。<br />- localhost: 一种代表环回地址的实体，具体来说，就是 127.0.0.1 和 ::1。|
|ports<br />*[Port](#port) array*|可选字段。Ports 在特定端口上定义此规则。此列表中的每个条目使用逻辑 “或” 进行组合。如果此字段为空或不存在，则此规则匹配所有端口。如果此字段存在且至少包含一个条目，则此规则匹配列表中的所有端口。|

### Service

| 字段 | 描述 |
|-----|------|
|namespace<br />*string*|可选字段。Namespace 通过名称和命名空间对来选择服务。|
|name<br />*string*|可选字段。Name 通过名称和命名空间对来选择服务。|
|serviceSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|可选字段。ServiceSelector 是一个标签选择器，用于选择服务。该字段遵循标准的标签选择器语义。它会选择所有命名空间中与 serviceSelector 匹配的服务。请注意，serviceSelector 字段与其他字段是互斥的。|

### Pod

| 字段 | 描述 |
|-----|------|
|namespaceSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|可选字段。NamespaceSelector 使用集群范围的标签来选择命名空间。此字段遵循标准的标签选择器语义；如果此字段不存在，则会选择所有命名空间。|
|podSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|PodSelector 是一个标签选择器，用于选择 Pod。该字段遵循标准的标签选择器语义。如果同时设置了 namespaceSelector，那么此规则将选择 namespaceSelector 所选命名空间中与 podSelector 匹配的Pod。否则，它将选择所有命名空间中与 podSelector 匹配的Pod。|
|ports<br />*[Port](#port) array*|可选字段。Ports 在特定端口上定义此规则。此列表中的每个条目使用逻辑 “或” 进行组合。如果此字段为空或不存在，则此规则匹配所有端口。如果此字段存在且至少包含一个条目，则此规则匹配列表中的所有端口。|

### Port

| 字段 | 描述 |
|-----|------|
|port<br />*uint16*|Port 是用于匹配流量的端口号。端口号必须在 [1, 65535] 范围内。
|endPort<br />*uint16*|可选字段。如果设置了结束端口（endPort），则表示端口范围从起始端口（port）到结束端口（endPort）。结束端口必须大于或等于起始端口，且必须在 [1, 65535] 范围内。|

## ModelingOptions

| 字段 | 描述 |
|-----|------|
|duration<br />*int*| Duration 是行为建模所需的分钟数。|

## DefenseInDepth

| 字段 | 描述 |
|-----|------|
|appArmor<br />*[AppArmorProfile](#apparmorprofile)*|可选字段。AppArmor 为默认拒绝访问控制指定 AppArmor 配置文件和其他自定义规则。|
|seccomp<br />*[SeccompProfile](#seccompprofile)*|可选字段。Seccomp 为默认拒绝访问控制指定 Seccomp 配置文件和其他自定义规则。|
|allowViolations<br />*bool*|可选字段。AllowViolations 用于确定是否允许违反强制访问控制规则的操作。如果设置了此字段，任何检测到的违规行为将被允许而非阻止，与此同时会生成并记录一个 “ALLOWED” 审计事件。这可用于收集违规情况，以改进默认拒绝访问控制的配置文件。如果未设置此字段，任何检测到的违规行为将被阻止，并生成和记录一个 “DENIED” 审计事件。(默认值：false)

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
