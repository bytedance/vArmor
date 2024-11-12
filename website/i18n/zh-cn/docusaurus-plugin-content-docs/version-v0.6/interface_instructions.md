# 接口说明
[English](interface_instructions.md) | 简体中文

## VarmorPolicy / VarmorClusterPolicy
### Spec

|字段|子字段|子字段|描述|
|---|-----|-----|---|
|target|kind<br />*string*|-|用于指定防护目标的 Workloads 类型<br />可用值: Deployment, StatefulSet, DaemonSet, Pod
|      |name<br />*string*|-|可选字段，用于指定防护目标的对象名称
|      |containers<br />*string array*|-|可选字段，用于指定防护目标的容器名，如果为空默认对 Workloads 中的所有容器开启沙箱防护（注：不含 initContainers, ephemeralContainers）
|      |selector<br />*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|可选字段，用于根据标签选择器识别防护目标，并开启沙箱防护
|policy|enforcer<br />*string*|-|指定要使用的 LSM，可用值: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp
|      |mode<br />*string*|-|用于指定防护模式，不同模式的含义详见 [内置规则](built_in_rules.zh_CN.md)<br />可用值：AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth
|      |enhanceProtect|hardeningRules<br />*string array*|可选字段，用于指定要使用的内置加固规则，详见 [内置规则](built_in_rules.zh_CN.md)
|      ||attackProtectionRules<br />*[AttackProtectionRules](interface_instructions.zh_CN.md#attackprotectionrules) array*|可选字段，用于指定要使用的内置规则，详见 [内置规则](built_in_rules.zh_CN.md)
|      ||vulMitigationRules<br />*string array*|可选字段，用于指定要使用的内置规则，详见 [内置规则](built_in_rules.zh_CN.md)
|      ||appArmorRawRules<br />*string array*|可选字段，用于设置自定义的 AppArmor 黑名单规则，参见 [AppArmor 语法](interface_instructions.zh_CN.md#apparmor-enforcer)
|      ||bpfRawRules<br />*[BpfRawRules](interface_instructions.zh_CN.md#bpfrawrules) array*|可选字段，用于支持用户设置自定义的 BPF 黑名单规则
|      ||syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|可选字段，用于支持用户使用 Seccomp enforcer 设置自定义的 Syscall 黑名单规则。请参考[此文档](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp)来制定自定义规则。
|      ||privileged<br />*bool*|可选字段，若要对特权容器进行加固，请务必将此值设置为 true。若为 `false`，将在 **RuntimeDefault** 模式的基础上构造 AppArmor/BPF Profiles。若为 `ture`，则在 **AlwaysAllow** 模式的基础上构造 AppArmor/BPF Profiles。<br /><br />注意：当为 `true` 时，vArmor 不会为目标构造 Seccomp Profiles（默认值：false）
|      ||auditViolations<br />*bool*|可选字段. 用于审计违反沙箱策略的行为。此特性当前仅支持 AppArmor enforcer，任何违反沙箱策略的行为都会被记录到系统的审计日志中。若您使用 syslog 或 rsyslog，日志文件的默认路径为 `/var/log/kern.log`。（默认值：false）
|      |modelingOptions|duration<br />*int*|动态建模的时间（单位：分钟）[实验功能]
|updateExistingWorkloads<br />*bool*|-|-|可选字段，用于指定是否对符合条件的工作负载进行滚动更新，从而在 Policy 创建或删除时，对目标工作负载开启或关闭防护（默认值：false）<br /><br />注意：vArmor 只会对 Deployment, StatefulSet, or DaemonSet 类型的工作负载进行滚动更新，如果 `.spec.target.kind` 为 Pod，需要您自行重建 Pod 来开启或关闭防护。
|      ||PLACEHOLDER_PLACEHOLD|

### AttackProtectionRules

|字段|描述|
|---|----|
|rules<br />*string array*|要使用的内置规则列表，详见 [内置规则](built_in_rules.zh_CN.md)
|targets<br />*string array*|可选字段，仅对指定的可执行文件列表开启 Rules 中的内置规则，此功能仅支持 AppArmor enforcer
|PLACEHOLDER|

### BpfRawRules

|字段|子字段|描述|
|---|-----|---|
|files<br />*FileRule array*    |pattern<br />*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配文件路径、文件名称<br />文件匹配语法参见 [BPF enforcer 语法](interface_instructions.zh_CN.md#bpf-enforcer-wip)
|                             |permissions<br />*string array*|禁止使用的权限，其中 write 权限隐式包含 append, rename, hard link, symbol link 权限<br />可用值：`read(r), write(w), append(a), exec(e)`
|processes<br />*FileRule array*|-|同上
|network<br />*NetworkRule*     |egresses<br />*[NetworkEgressRule](interface_instructions.zh_CN.md#networkegressrule) array*|对外联请求进行访问控制
|ptrace<br />*PtraceRule*       |strictMode<br />*bool*|可选字段，true 代表对所有（目标、来源）进程进行限制，false 代表仅对容器外的（目标、来源）进程进行限制（默认值：false）
|                             |permissions<br />*string array*|禁止使用的权限，可用值: `trace, read, traceby, readby`<br />- `trace`: 禁止 trace 其他目标进程<br />- `read`: 禁止 read 其他目标进程<br />- `traceby`: 禁止被其他来源进程 trace（宿主机进程除外）<br />- `readby`: 禁止被其他来源进程 read（宿主机进程除外）
|mounts<br />*MountRule array*  |sourcePattern<br />*string*|任意符合策略语法的文件路径字符串（最大长度 128 bytes），用于匹配 [MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html) 的 source，[UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html) 的 target，以及 MOVE_MOUNT(2) 的 from_pathname<br />文件匹配语法参见 [BPF enforcer 语法](interface_instructions.zh_CN.md#bpf-enforcer-wip)
|                             |fstype<br />*string*|任意字符串（最大长度 16 bytes），用于匹配文件系统类型，`*` 代表匹配任意文件系统 
|                             |flags<br />*string array*|禁止使用的 mount flags，它们与 AppArmor 的 [MOUNT FLAGS](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) 类似，其中 `all` 代表匹配所有 flags<br />可用值：`all, ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`
|PLACEHOLDER_|PLACEHOLDER_PLACEHOD|

### NetworkEgressRule

|字段|描述|
|---|----|
|ipBlock<br />*string*|可选字段，可使用任意标准的 CIDR，支持 IPv6。用于对指定 CIDR 范围内的 IP 地址进行外联限制，例如<br />* 192.168.1.1/24 代表 192.168.1.0 ~ 192.168.1.255 范围内的 IP 地址<br />* 2001:db8::/32 代表 2001:db8:: ~ 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 范围内的 IP 地址<br />（注：同一个 NetworkEgressRule 中，IPBlock 和 IP 字段互斥，不能同时出现）
|ip<br />*string*|可选字段，任意标准的 IP 地址，支持 IPv6，用于对特定的 IP 地址进行外联限制
|port<br />*int*|可选字段，用于对指定的端口进行外联限制，当为空时，默认对（匹配 IP 地址的）所有端口进行外联限制。否则仅对特定端口进行控制<br />可用值：`1~65535`
|PLACEHOLDER|


## 策略语法
vArmor 也支持用户在 `spec.policy.enhanceProtect.appArmorRawRules` 和 `spec.policy.enhanceProtect.bpfRawRules` 中根据语法自定义强制访问控制规则。

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
  |read|r|-<br />rename<br />hard link|禁止读<br />禁止利用 rename **oldpath** newpath 绕过 oldpath 的读限制<br />禁止利用 ln **TARGET** LINK_NAME 绕过 TARGET 的读限制
  |write|w|-<br />append<br />rename<br />hard link<br />symbol link<br />chmod<br />chown|禁止写<br />禁止利用 O_APPEND flag 绕过 map_file_to_perms() 实现追加写操作<br />禁止利用 rename oldpath **newpath** 绕过 newpath 的写限制<br />禁止利用 ln TARGET **LINK_NAME** 绕过 LINK_NAME 的写限制<br />禁止利用创建软链接（符号链接）绕过目标文件的写限制<br />WIP<br />WIP
  |exec|x|-|禁止执行
  |append|a|-|禁止追加写

* 文件路径匹配

  BPF enfocer 支持根据路径 Pattern 对文件进行匹配，并支持两种匹配模式（精确匹配、通配匹配），匹配 Pattern 的最大长度限制为 64 字节。
  * 精确匹配
  * 通配匹配

    |通配符|语法|样例|备注|
    |-----|---|---|----|
    |*|- 仅用于匹配叶子结点的文件名<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 *，且不支持 \*\* 和 * 一起出现|- fi\* 代表匹配任意以 fi 开头的文件名<br />- *le 代表匹配任意以 le 结尾的文件名<br />- *.log 代表匹配任意以 .log 结尾的文件名|此通配符的行为可能会在后续版本中发生改变|
    |\**|- 在多级目录中，匹配零个、一个、多个字符<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 \*\*，且不支持 ** 和 * 一起出现|- /tmp/\*\*/33 代表匹配任意以 /tmp 开头，且以 /33 结尾的文件，包含 /tmp/33<br />- /tmp/\*\* 代表匹配任意以 /tmp 开头的文件、目录<br />- /tm** 代表匹配任意以 /tm 开头的文件、目录<br />- /t**/33 代表匹配任意以 /t 开头，以 /33 结尾的文件、目录
  
* 网络地址匹配
  * 当前 vArmor 支持对指定的 IP 地址、IP 地址块（CIDR 块）、端口进行外联访问控制
  * 当指定了 IP 地址、IP 地址块，但未指定端口时，默认对所有端口生效
  * 具体请参见 [NetworkEgressRule](./interface_instructions.zh_CN.md#networkegressrule)
