
# Interface Instructions
English | [简体中文](interface_instructions.zh_CN.md)

## VarmorPolicy
### VarmorPolicySpec

| Field | Subfield | Subfield | Description |
|-------|----------|----------|-------------|
|target|kind<br>*string*|-|Kind is used to specify the type of workloads for the protection targets.<br>Available values: Deployment, StatefulSet, DaemonSet, Pod
|      |name<br>*string*|-|Optional. Name is used to specify a specific workload name.
|      |containers<br>*string array*|-|Optional. Containers are used to specify the names of the protected containers. If it is empty, sandbox protection will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).
|      |selector<br>*[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#labelselector-v1-meta)*|-|Optional. LabelSelector is used to match workloads that meet the specified conditions. <br>*Note: the type of workloads is determined by the KIND field.*
|policy|enforcer<br>*string*|-|Enforcer is used to specify which LSM to use for mandatory access control. <br>Available values: AppArmor, BPF
|      |mode<br>*string*|-|Used to specify the protection mode, please refer to [Built-in Policies](policy_manual.md#built-in-policies-wip).<br>Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, CustomPolicy, DefenseInDepth
|      |enhanceProtect|hardeningRules<br>*string array*|Optional. HardeningRules are used to specify the built-in hardening rules, please refer to [Built-in Policies](policy_manual.md#built-in-policies-wip).
|      ||attackProtectionRules<br>*[AttackProtectionRules](interface_instructions.md#attackprotectionrules) array*|Optional. AttackProtectionRules are used to specify the built-in attack protection rules, please refer to [Built-in Policies](policy_manual.md#built-in-policies-wip).
|      ||vulMitigationRules<br>*string array*|Optional. VulMitigationRules are used to specify the built-in vulnerability mitigation rules, please refer to [Built-in Policies](policy_manual.md#built-in-policies-wip).
|      ||appArmorRawRules<br>*string array*|Optional. AppArmorRawRules is used to set native AppArmor rules, each rule must end with a comma, please refer to [AppArmor Syntax](policy_manual.md#apparmor-enforcer).
|      ||bpfRawRules<br>*[BpfRawRules](interface_instructions.md#bpfrawrules) array*|Optional. BpfRawRules is used to set native BPF rules.
|      |defenseInDepth|ModelingDuration<br>*int*|[Experimental] ModelingDuration is the duration in minutes to modeling. 
|      ||autoEnable<br>*bool*|[Experimental] Optional. AutoEnable decides whether or not to enable the access control after modeling is complete. (Default: false)
|      |privileged<br>*bool*|-|Optional. Privileged is used to identify whether the policy is for the privileged container. Only used for the AppArmor enforcer.
|      ||PLACEHOLDER_PLACE|

### AttackProtectionRules

| Field | Description |
|-------|-------------|
|rules<br>*string array*|List of built-in attack protection rules to be used, please refer to [Built-in Policies](policy_manual.md#built-in-policies-wip).
|targets<br>*string array*|Optional. Targets are used to specify the workloads to which the policy applies. They must be specified as full paths to executable files, and this feature is only effective when using AppArmor as the enforcer.
|PLACEHOLDER||

### BpfRawRules

| Field | Subfield | Description |
|-------|----------|-------------|
|files<br>*FileRule array*    |pattern<br>*string*|Any string (maximum length 64 bytes) that conforms to the policy syntax, used for matching file paths and filenames. Please refer to [BPF Syntax](policy_manual.md#bpf-enforcer-wip).
|                             |permissions<br>*string array*|Permissions are used to specify the file permissions to be disabled. Available values: read(r), write(w), append(a), exec(e)
|processes<br>*FileRule array*|-|Same as above.
|network<br>*NetworkRule*     |egresses<br>*[NetworkEgressRule](interface_instructions.md#networkegressrule) array*|Optional. Egresses are the list of egress rules to be applied to restrict particular IPs and ports.
|ptrace<br>*PtraceRule*       |strictMode<br>*bool*|Optional. If set to false, it restricts ptrace-related permissions only for processes in other containers. If set to true, it restricts ptrace-related permissions for all processes, except those within the init mnt namespace.. (Default: false)
|                             |permissions<br>*string array*|Prohibited ptrace-related permissions. Available values: trace, traceby, read, readby. <br>- trace: prohibiting tracing of other container processes. <br>- read: prohibiting reading of other container processes. <br>- traceby: prohibiting being traced by other processes (excluding the host processes). <br>- readby: prohibiting being read by other processes (excluding the host processes).
|PLACEHOLDER|PLACEHOLDER_PLACEHO|

### NetworkEgressRule
| Field | Description |
|-------|-------------|
|ipBlock<br>*string*|Optional. IPBlock defines policy on a particular IPBlock with CIDR. If this field is set then neither of the IP field can be. For example: <br>* 192.168.1.1/24 represents IP addresses within the range of 192.168.1.0 to 192.168.1.255.<br>* 2001:db8::/32 represents IP addresses within the range of 2001:db8:: to 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
|ip<br>*string*|Optional. IP defines policy on a particular IP. If this field is set then neither of the IPBlock field can be.
|port<br>*int*|Optional. Port defines policy on a particular port. If this field is zero or missing, this rule matches all ports.<br>Available values: 1 to 65535
