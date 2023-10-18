# Interface Instructions
[English](interface_instructions.md) | 简体中文

## VarmorPolicy / VarmorClusterPolicy
### Spec

|字段|子字段|子字段|描述|
|---|-----|-----|---|
|target|kind<br>*string*|-|用于指定防护目标的 Workloads 类型<br>可用值: Deployment, StatefulSet, DaemonSet, Pod
|      |name<br>*string*|-|可选字段，用于指定防护目标的对象名称
|      |containers<br>*string array*|-|可选字段，用于指定防护目标的容器名，如果为空默认对 Workloads 中的所有容器开启沙箱防护（注：不含 initContainers, ephemeralContainers）
|      |selector<br>*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|可选字段，用于根据标签选择器识别防护目标，并开启沙箱防护
|policy|enforcer<br>*string*|-|指定要使用的 LSM，可用值: AppArmor, BPF
|      |mode<br>*string*|-|用于指定防护模式，不同模式的含义详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)<br>可用值：AlwaysAllow, RuntimeDefault, EnhanceProtect, CustomPolicy, DefenseInDepth
|      |enhanceProtect|hardeningRules<br>*string array*|可选字段，用于指定要使用的内置加固规则，详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
|      ||attackProtectionRules<br>*[AttackProtectionRules](interface_instructions.zh_CN.md#attackprotectionrules) array*|可选字段，用于指定要使用的内置规则，详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
|      ||vulMitigationRules<br>*string array*|可选字段，用于指定要使用的内置规则，详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
|      ||appArmorRawRules<br>*string array*|可选字段，用于设置自定义的 AppArmor rules，参见 [AppArmor 语法](policy_manual.zh_CN.md#apparmor-enforcer)
|      ||bpfRawRules<br>*[BpfRawRules](interface_instructions.zh_CN.md#bpfrawrules) array*|可选字段，用于支持用户设置自定义的 BPF rules
|      |defenseInDepth|ModelingDuration<br>*int*|动态建模的时间（单位：分钟）[实验功能]
|      ||autoEnable<br>*bool*|可选字段，用于指定建模完成后是否自动开启防护（默认值：false）[实验功能]
|      |privileged<br>*bool*|-|可选字段，若要对特权容器进行加固，请务必将此值设置为 true。若为空或 `false`，**EnhanceProtect** 模式将在 **RuntimeDefault** 模式的基础上进行增强防护。否则将在 **AlwaysAllow** 模式的基础上进行增强防护（默认值：false）
|      ||PLACEHOLDER_PLACEHOLD|

### AttackProtectionRules

|字段|描述|
|---|----|
|rules<br>*string array*|要使用的内置规则列表，详见 [Built-in Policies](policy_manual.zh_CN.md#内置策略-wip)
|targets<br>*string array*|可选字段，仅对指定的可执行文件列表开启 Rules 中的内置规则，此功能仅支持 AppArmor enforcer
|PLACEHOLDER|

### BpfRawRules

|字段|子字段|描述|
|---|-----|---|
|files<br>*FileRule array*    |pattern<br>*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配文件路径、文件名称<br>文件匹配语法参见 [BPF enforcer 策略语法](policy_manual.zh_CN.md#bpf-enforcer-wip)
|                             |permissions<br>*string array*|禁止使用的权限，其中 write 权限隐式包含 append, rename, hard link, symbol link 权限<br>可用值：`read(r), write(w), append(a), exec(e)`
|processes<br>*FileRule array*|-|同上
|network<br>*NetworkRule*     |egresses<br>*[NetworkEgressRule](interface_instructions.zh_CN.md#networkegressrule) array*|对外联请求进行访问控制
|ptrace<br>*PtraceRule*       |strictMode<br>*bool*|可选字段，true 代表对所有（目标、来源）进程进行限制，false 代表仅对容器外的（目标、来源）进程进行限制（默认值：false）
|                             |permissions<br>*string array*|禁止使用的权限，可用值: `trace, read, traceby, readby`<br>- `trace`: 禁止 trace 其他目标进程<br>- `read`: 禁止 read 其他目标进程<br>- `traceby`: 禁止被其他来源进程 trace（宿主机进程除外）<br>- `readby`: 禁止被其他来源进程 read（宿主机进程除外）
|mounts<br>*MountRule array*  |sourcePattern<br>*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配 [MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) 的 source，[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) 的 target，以及 MOVE_MOUNT(2) 的 from_pathname<br>文件匹配语法参见 [BPF enforcer 策略语法](policy_manual.zh_CN.md#bpf-enforcer-wip)
|                             |fstype<br>*string*|任意字符串（最大长度 16 bytes），用于匹配文件系统类型，`*` 代表匹配任意文件系统 
|                             |flags<br>*string array*|禁止使用的 mount flags，它们与 AppArmor 的 [MOUNT FLAGS](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) 类似，其中 `all` 代表匹配所有 flags<br>可用值：`all, ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`
|PLACEHOLDER_|PLACEHOLDER_PLACEHOD|

### NetworkEgressRule

|字段|描述|
|---|----|
|ipBlock<br>*string*|可选字段，可使用任意标准的 CIDR，支持 IPv6。用于对指定 CIDR 范围内的 IP 地址进行外联限制，例如<br>* 192.168.1.1/24 代表 192.168.1.0 ~ 192.168.1.255 范围内的 IP 地址<br>* 2001:db8::/32 代表 2001:db8:: ~ 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 范围内的 IP 地址<br>（注：同一个 NetworkEgressRule 中，IPBlock 和 IP 字段互斥，不能同时出现）
|ip<br>*string*|可选字段，任意标准的 IP 地址，支持 IPv6，用于对特定的 IP 地址进行外联限制
|port<br>*int*|可选字段，用于对指定的端口进行外联限制，当为空时，默认对（匹配 IP 地址的）所有端口进行外联限制。否则仅对特定端口进行控制<br>可用值：`1~65535`
|PLACEHOLDER|