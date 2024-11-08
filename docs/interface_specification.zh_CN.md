# 接口说明
[English](interface_specification.md) | 简体中文

## VarmorPolicySpec / VarmorClusterPolicySpec

|字段|子字段|子字段|描述|
|---|-----|-----|---|
|target|kind<br>*string*|-|用于指定防护目标的 Workloads 类型。<br>可用值: Deployment, StatefulSet, DaemonSet, Pod。
|      |name<br>*string*|-|可选字段，用于指定防护目标的对象名称。
|      |containers<br>*string array*|-|可选字段，用于指定防护目标的容器名，如果为空默认对 Workloads 中的所有容器开启沙箱防护。（注：不含 initContainers, ephemeralContainers）
|      |selector<br>*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|可选字段，用于根据标签选择器识别防护目标，并开启沙箱防护。
|policy|enforcer<br>*string*|-|指定要使用的 LSM。<br>可用值: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp
|      |mode<br>*string*|-|用于指定防护模式。<br>可用值：AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth
|      |enhanceProtect|hardeningRules<br>*string array*|可选字段，用于指定要使用的内置加固规则。
|      ||attackProtectionRules<br>*[AttackProtectionRules](interface_specification.zh_CN.md#attackprotectionrules) array*|可选字段，用于指定要使用的内置规则。
|      ||vulMitigationRules<br>*string array*|可选字段，用于指定要使用的内置规则。
|      ||appArmorRawRules<br>*string array*|可选字段，用于设置自定义的 AppArmor 黑名单规则。
|      ||bpfRawRules<br>*[BpfRawRules](interface_specification.zh_CN.md#bpfrawrules)*|可选字段，用于支持用户设置自定义的 BPF 黑名单规则。
|      ||syscallRawRules<br>*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|可选字段，用于支持用户使用 Seccomp enforcer 设置自定义的 Syscall 黑名单规则。
|      ||privileged<br>*bool*|可选字段，若要对特权容器进行加固，请务必将此值设置为 true。若为 `false`，将在 **RuntimeDefault** 模式的基础上构造 AppArmor/BPF Profiles。若为 `ture`，则在 **AlwaysAllow** 模式的基础上构造 AppArmor/BPF Profiles。<br><br>注意：当为 `true` 时，vArmor 不会为目标构造 Seccomp Profiles。（默认值：false）
|      ||auditViolations<br />*bool*|可选字段. 用于审计违反沙箱策略的行为。此特性当前支持 AppArmor 和 BPF enforcers，任何违反沙箱策略的行为都会被记录到宿主机的 `/var/log/varmor/violations.log` 文件中。（默认值：false）
|      |modelingOptions|duration<br>*int*|动态建模的时间。（单位：分钟）[实验功能]
|updateExistingWorkloads<br>*bool*|-|-|可选字段，用于指定是否对符合条件的工作负载进行滚动更新，从而在 Policy 创建或删除时，对目标工作负载开启或关闭防护。（默认值：false）<br><br>注意：vArmor 只会对 Deployment, StatefulSet, or DaemonSet 类型的工作负载进行滚动更新，如果 `.spec.target.kind` 为 Pod，需要您自行重建 Pod 来开启或关闭防护。
|      ||PLACEHOLDER_PLACEHOLD|

## AttackProtectionRules

|字段|描述|
|---|----|
|rules<br>*string array*|要使用的内置规则列表。
|targets<br>*string array*|可选字段，仅对指定的可执行文件列表开启 Rules 中的内置规则，此功能仅支持 AppArmor enforcer。
|PLACEHOLDER|

## BpfRawRules

|字段|子字段|描述|
|---|-----|---|
|files<br>*FileRule array*    |pattern<br>*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配文件路径、文件名称。
|                             |permissions<br>*string array*|禁止使用的权限，其中 write 权限隐式包含 append, rename, hard link, symbol link 权限。<br>可用值：`read(r), write(w), append(a), exec(e)`
|processes<br>*FileRule array*|-|同上
|network<br>*NetworkRule*     |egresses<br>*[NetworkEgressRule](interface_specification.zh_CN.md#networkegressrule) array*|对外联请求进行访问控制。
|ptrace<br>*PtraceRule*       |strictMode<br>*bool*|可选字段，如果设置为 false，同一容器内的进程将不受限制。如果将设置为 true，即使是同一容器内的进程也将受到限制。（默认值：false）
|                             |permissions<br>*string array*|禁止使用的权限，可用值: `trace, read, traceby, readby`<br>- `trace`: 禁止进程跟踪其他进程<br>- `read`: 禁止进程读取其他进程<br>- `traceby`: 禁止进程被其他进程跟踪，宿主机进程除外<br>- `readby`: 禁止进程被其他进程读取，宿主机进程除外
|mounts<br>*MountRule array*  |sourcePattern<br>*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配 [MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) 的 source，[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) 的 target，以及 MOVE_MOUNT(2) 的 from_pathname。
|                             |fstype<br>*string*|任意字符串（最大长度 16 bytes），用于匹配文件系统类型，`*` 代表匹配任意文件系统。
|                             |flags<br>*string array*|禁止使用的 mount flags，它们与 AppArmor 的 [MOUNT FLAGS](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) 类似，其中 `all` 代表匹配所有 flags。<br>可用值：`all, ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`
|PLACEHOLDER_|PLACEHOLDER_PLACEHOD|

## NetworkEgressRule

|字段|描述|
|---|----|
|ipBlock<br>*string*|可选字段，可使用任意标准的 CIDR，支持 IPv6。用于对指定 CIDR 范围内的 IP 地址进行外联限制，例如<br>* 192.168.1.1/24 代表 192.168.1.0 ~ 192.168.1.255 范围内的 IP 地址。<br>* 2001:db8::/32 代表 2001:db8:: ~ 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 范围内的 IP 地址。<br>（注：同一个 NetworkEgressRule 中，IPBlock 和 IP 字段互斥，不能同时出现）
|ip<br>*string*|可选字段，任意标准的 IP 地址，支持 IPv6，用于对特定的 IP 地址进行外联限制。
|port<br>*int*|可选字段，用于对指定的端口进行外联限制，当为空时，默认对（匹配 IP 地址的）所有端口进行外联限制。否则仅对特定端口进行控制。<br>可用值：`1~65535`
|PLACEHOLDER|
