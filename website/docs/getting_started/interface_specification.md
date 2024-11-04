---
sidebar_position: 3
description: The interface specification of vArmor.
---

# Interface Specification

## VarmorPolicySpec / VarmorClusterPolicySpec

| Field | Subfield | Subfield | Description |
|-------|----------|----------|-------------|
|target|kind<br />*string*|-|Kind is used to specify the type of workloads for the protection targets.<br />Available values: Deployment, StatefulSet, DaemonSet, Pod
|      |name<br />*string*|-|Optional. Name is used to specify a specific workload name.
|      |containers<br />*string array*|-|Optional. Containers are used to specify the names of the protected containers. If it is empty, sandbox protection will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).
|      |selector<br />*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|Optional. LabelSelector is used to match workloads that meet the specified conditions. <br />*Note: the type of workloads is determined by the KIND field.*
|policy|enforcer<br />*string*|-|Enforcer is used to specify which LSM to use for mandatory access control. <br />Available values: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp
|      |mode<br />*string*|-|Used to specify the protection mode, please refer to the [Built-in Rules](built_in_rules).<br />Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth
|      |enhanceProtect|hardeningRules<br />*string array*|Optional. HardeningRules are used to specify the built-in hardening rules, please refer to the [Built-in Rules](built_in_rules).
|      ||attackProtectionRules<br />*[AttackProtectionRules](interface_instructions#attackprotectionrules) array*|Optional. AttackProtectionRules are used to specify the built-in attack protection rules, please refer to the [Built-in Rules](built_in_rules).
|      ||vulMitigationRules<br />*string array*|Optional. VulMitigationRules are used to specify the built-in vulnerability mitigation rules, please refer to the [Built-in Rules](built_in_rules).
|      ||appArmorRawRules<br />*string array*|Optional. AppArmorRawRules is used to set custom AppArmor rules, each rule must end with a comma, please refer to the [AppArmor Syntax](interface_instructions#apparmor-enforcer).
|      ||bpfRawRules<br />*[BpfRawRules](interface_instructions#bpfrawrules) array*|Optional. BpfRawRules is used to set custom BPF rules.
|      ||syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|Optional. SyscallRawRules is used to set the custom syscalls blocklist rules with Seccomp enforcer. Please refer to [this document](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) to create custom rules.
|      ||privileged<br />*bool*|Optional. Privileged is used to identify whether the policy is for the privileged container. If set to `nil` or `false`, vArmor will build AppArmor or BPF profiles on top of the **RuntimeDefault** mode. Otherwise, it will build AppArmor or BPF profiles on top of the **AlwaysAllow** mode. (Default: false)<br /><br />Note: If set to `true`, vArmor will not build Seccomp profile for the target workloads.
|      ||auditViolations<br />*bool*|Optional. AuditViolations determines whether to audit the actions that violate the mandatory access control rules. Currently, this feature supports only the AppArmor enforcer. Any detected violation will be logged to the system's audit file. If you are using syslog or rsyslog, the default log path is `/var/log/kern.log`. (Default: false)
|      |modelingOptions|duration<br />*int*|[Experimental] Duration is the duration in minutes to modeling. 
|updateExistingWorkloads<br />*bool*|-|-|Optional. UpdateExistingWorkloads is used to indicate whether to perform a rolling update on target existing workloads, thus enabling or disabling the protection of the target workloads when policies are created or deleted. (Default: false)<br /><br />Note: vArmor only performs a rolling update on Deployment, StatefulSet, or DaemonSet type workloads. If `.spec.target.kind` is Pod, you need to rebuild the Pod yourself to enable or disable protection.
|      ||PLACEHOLDER_PLACEHOD|

## AttackProtectionRules

| Field | Description |
|-------|-------------|
|rules<br />*string array*|List of built-in attack protection rules to be used, please refer to the [Built-in Rules](built_in_rules).
|targets<br />*string array*|Optional. Targets are used to specify the workloads to which the policy applies. They must be specified as full paths to executable files, and this feature is only effective when using AppArmor as the enforcer.
|PLACEHOLDER

## BpfRawRules

| Field | Subfield | Description |
|-------|----------|-------------|
|files<br />*FileRule array*    |pattern<br />*string*|Any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching file paths and filenames. Please refer to the [BPF Syntax](interface_instructions#bpf-enforcer-wip).
|                             |permissions<br />*string array*|Permissions are used to specify the file permissions to be disabled.<br />Available values: `read(r), write(w), append(a), exec(e)`
|processes<br />*FileRule array*|-|Same as above.
|network<br />*NetworkRule*     |egresses<br />*[NetworkEgressRule](interface_instructions#networkegressrule) array*|Optional. Egresses are the list of egress rules to be applied to restrict particular IPs and ports.
|ptrace<br />*PtraceRule*       |strictMode<br />*bool*|Optional. If set to false, it restricts ptrace-related permissions only for processes in other containers. If set to true, it restricts ptrace-related permissions for all processes, except those within the init mnt namespace. (Default: false)
|                             |permissions<br />*string array*|Prohibited ptrace-related permissions. Available values: `trace, traceby, read, readby`. <br />- `trace`: prohibiting tracing of other container processes. <br />- `read`: prohibiting reading of other container processes. <br />- `traceby`: prohibiting being traced by other processes (excluding the host processes). <br />- `readby`: prohibiting being read by other processes (excluding the host processes).
|mounts<br />*MountRule array*  |sourcePattern<br />*string*|Any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching the source paramater of [MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html), the target paramater of [UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html), and the from_pathname paramater of MOVE_MOUNT(2). Please refer to the [BPF Syntax](interface_instructions#bpf-enforcer-wip).
|                             |fstype<br />*string*|Any string (maximum length 16 bytes), used for matching the type of filesystem. `'*'` represents matching any filesystem.
|                             |flags<br />*string array*|Prohibited mount flags. They are similar to AppArmor's [MOUNT FLAGS](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html), `'all'` represents matching all mount flags. <br />Available values: `all, ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`
|PLACEHOLDER_|PLACEHOLDER_PLACEHOD|


## NetworkEgressRule
| Field | Description |
|-------|-------------|
|ipBlock<br />*string*|Optional. IPBlock defines policy on a particular IPBlock with CIDR. If this field is set then neither of the IP field can be. For example: <br />* 192.168.1.1/24 represents IP addresses within the range of 192.168.1.0 to 192.168.1.255.<br />* 2001:db8::/32 represents IP addresses within the range of 2001:db8:: to 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
|ip<br />*string*|Optional. IP defines policy on a particular IP. If this field is set then neither of the IPBlock field can be.
|port<br />*int*|Optional. Port defines policy on a particular port. If this field is zero or missing, this rule matches all ports.<br />Available values: `1 to 65535`
|PLACEHOLDER|
