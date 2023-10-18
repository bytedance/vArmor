
# Interface Instructions
English | [简体中文](interface_instructions.zh_CN.md)

## VarmorPolicy / VarmorClusterPolicy
### Spec

| Field | Subfield | Subfield | Description |
|-------|----------|----------|-------------|
|target|kind<br>*string*|-|Kind is used to specify the type of workloads for the protection targets.<br>Available values: Deployment, StatefulSet, DaemonSet, Pod
|      |name<br>*string*|-|Optional. Name is used to specify a specific workload name.
|      |containers<br>*string array*|-|Optional. Containers are used to specify the names of the protected containers. If it is empty, sandbox protection will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).
|      |selector<br>*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|Optional. LabelSelector is used to match workloads that meet the specified conditions. <br>*Note: the type of workloads is determined by the KIND field.*
|policy|enforcer<br>*string*|-|Enforcer is used to specify which LSM to use for mandatory access control. <br>Available values: AppArmor, BPF
|      |mode<br>*string*|-|Used to specify the protection mode, please refer to the [Built-in Rules](built_in_rules.md#built-in-rules).<br>Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, CustomPolicy, DefenseInDepth
|      |enhanceProtect|hardeningRules<br>*string array*|Optional. HardeningRules are used to specify the built-in hardening rules, please refer to the [Built-in Rules](built_in_rules.md#built-in-policies).
|      ||attackProtectionRules<br>*[AttackProtectionRules](interface_instructions.md#attackprotectionrules) array*|Optional. AttackProtectionRules are used to specify the built-in attack protection rules, please refer to the [Built-in Rules](built_in_rules.md#built-in-rules).
|      ||vulMitigationRules<br>*string array*|Optional. VulMitigationRules are used to specify the built-in vulnerability mitigation rules, please refer to the [Built-in Rules](built_in_rules.md#built-in-policies).
|      ||appArmorRawRules<br>*string array*|Optional. AppArmorRawRules is used to set custom AppArmor rules, each rule must end with a comma, please refer to the [AppArmor Syntax](interface_instructions.md#apparmor-enforcer).
|      ||bpfRawRules<br>*[BpfRawRules](interface_instructions.md#bpfrawrules) array*|Optional. BpfRawRules is used to set custom BPF rules.
|      |defenseInDepth|ModelingDuration<br>*int*|[Experimental] ModelingDuration is the duration in minutes to modeling. 
|      ||autoEnable<br>*bool*|[Experimental] Optional. AutoEnable decides whether or not to enable the access control after modeling is complete. (Default: false)
|      |privileged<br>*bool*|-|Optional. Privileged is used to identify whether the policy is for the privileged container. If set to `nil` or `false`, the **EnhanceProtect** mode will build enhanced protection rules on top of the **RuntimeDefault** mode. Otherwise, it will enhance protection on top of the **AlwaysAllow** mode. (Default: false)
|      ||PLACEHOLDER_PLACEHOD|

### AttackProtectionRules

| Field | Description |
|-------|-------------|
|rules<br>*string array*|List of built-in attack protection rules to be used, please refer to the [Built-in Rules](built_in_rules.md#built-in-rules).
|targets<br>*string array*|Optional. Targets are used to specify the workloads to which the policy applies. They must be specified as full paths to executable files, and this feature is only effective when using AppArmor as the enforcer.
|PLACEHOLDER

### BpfRawRules

| Field | Subfield | Description |
|-------|----------|-------------|
|files<br>*FileRule array*    |pattern<br>*string*|Any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching file paths and filenames. Please refer to the [BPF Syntax](interface_instructions.md#bpf-enforcer-wip).
|                             |permissions<br>*string array*|Permissions are used to specify the file permissions to be disabled.<br>Available values: `read(r), write(w), append(a), exec(e)`
|processes<br>*FileRule array*|-|Same as above.
|network<br>*NetworkRule*     |egresses<br>*[NetworkEgressRule](interface_instructions.md#networkegressrule) array*|Optional. Egresses are the list of egress rules to be applied to restrict particular IPs and ports.
|ptrace<br>*PtraceRule*       |strictMode<br>*bool*|Optional. If set to false, it restricts ptrace-related permissions only for processes in other containers. If set to true, it restricts ptrace-related permissions for all processes, except those within the init mnt namespace. (Default: false)
|                             |permissions<br>*string array*|Prohibited ptrace-related permissions. Available values: `trace, traceby, read, readby`. <br>- `trace`: prohibiting tracing of other container processes. <br>- `read`: prohibiting reading of other container processes. <br>- `traceby`: prohibiting being traced by other processes (excluding the host processes). <br>- `readby`: prohibiting being read by other processes (excluding the host processes).
|mounts<br>*MountRule array*  |sourcePattern<br>*string*|Any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching the source paramater of [MOUNT(2)](https://man7.org/linux/man-pages/man2/mount.2.html), the target paramater of [UMOUNT(2)](https://man7.org/linux/man-pages/man2/umount.2.html), and the from_pathname paramater of MOVE_MOUNT(2). Please refer to the [BPF Syntax](interface_instructions.md#bpf-enforcer-wip).
|                             |fstype<br>*string*|Any string (maximum length 16 bytes), used for matching the type of filesystem. `'*'` represents matching any filesystem.
|                             |flags<br>*string array*|Prohibited mount flags. They are similar to AppArmor's [MOUNT FLAGS](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html), `'all'` represents matching all mount flags. <br>Available values: `all, ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`
|PLACEHOLDER_|PLACEHOLDER_PLACEHOD|


### NetworkEgressRule
| Field | Description |
|-------|-------------|
|ipBlock<br>*string*|Optional. IPBlock defines policy on a particular IPBlock with CIDR. If this field is set then neither of the IP field can be. For example: <br>* 192.168.1.1/24 represents IP addresses within the range of 192.168.1.0 to 192.168.1.255.<br>* 2001:db8::/32 represents IP addresses within the range of 2001:db8:: to 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
|ip<br>*string*|Optional. IP defines policy on a particular IP. If this field is set then neither of the IPBlock field can be.
|port<br>*int*|Optional. Port defines policy on a particular port. If this field is zero or missing, this rule matches all ports.<br>Available values: `1 to 65535`
|PLACEHOLDER|


## Syntax
vArmor also allows users to customize Mandatory Access Control rules in `spec.policy.enhanceProtect.appArmorRawRules` and `spec.policy.enhanceProtect.bpfRawRules` based on the syntax.

### AppArmor enforcer
The AppArmor enforcer supports users in customizing policies based on the syntax of AppArmor.
* Refer to the [syntax of security profiles for AppArmor](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) and [AppArmor_Core_Policy_Reference](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference) for the details.
* Usage:
  * Add a custom rule in .spec.policy.enhanceProtect.appArmorRawRules[]
  * Please ensure that each rule ends with a comma


### BPF enforcer (WIP)
The BPF enforcer supports users in customizing policies based on the syntax, with an upper limit of 50 rules per rule type. Each node of Kubernetes can enable sandboxing for up to 100 containers.

* File Permission
  
  | Permission / Permission Abbreviate |  Implied Permissions | Description |
  |------------------------------------|----------------------|-------------|
  |read / r|-<br>rename<br>hard link|Restrict read permission.<br>Prohibit abusing 'rename **oldpath** newpath' to bypass read restrictions on oldpath.<br>Prohibit abusing 'ln **TARGET** LINK_NAME' to bypass read restrictions on TARGET.
  |write / w|-<br>append<br>rename<br>hard link<br>symbol link<br>chmod<br>chown|Restrict write permission.<br>Prohibit using the O_APPEND flag to bypass map_file_to_perms() for append operations.<br>Prohibit abusing 'rename oldpath **newpath**' to bypass write restrictions on newpath.<br>Prohibit abusing 'ln TARGET **LINK_NAME**' to bypass write restrictions on LINK_NAME.<br>Prohibit abusing symlink to bypass write restrictions on the target file.<br>WIP<br>WIP
  |exec / x|-|Prohibit execution permission.
  |append / a|-|Prohibit append permission.

* File Globbing Syntax 
  | Globbing | Description | Examples | Notes |
  |----------|-------------|----------|-------|
  |*|- Used only to match file names.<br>- It will match dot files except the special dot files . and ..<br>- Supports only a single *, and does not support \*\* and * appearing together.|- fi\* matches any file name starting with 'fi'.<br>- *le matches any file name ending with 'le'.<br>- *.log matches any file name ending with '.log'|The behavior of this globbing may change in future versions.|
  |\**|- Match zero, one, or multiple characters in multi-level directories.<br>- It will match dot files except the special dot files . and ..<br>- Supports only a single \*\*, and does not support ** and * appearing together.|- /tmp/\*\*/33 matches any file that starts with /tmp and ends with /33, including /tmp/33.<br>- /tmp/\*\* matches any file or directory that starts with /tmp.<br>- /tm** matches any file or directory that starts with /tm.<br>- /t**/33 matches any file or directory that starts with /t and ends with /33.

* Network Permission
  * Currently, vArmor supports connection access control for specified IP addresses, IP address blocks (CIDR blocks), and ports.
  * When specific IP addresses or IP address blocks are specified without specifying ports, it defaults to affecting all ports.
  * Please refer to [NetworkEgressRule](./interface_instructions.md#networkegressrule) for specific details.
