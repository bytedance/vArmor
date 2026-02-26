---
sidebar_position: 4
description: The interface specification of vArmor.
---

# Interface Specification

## VarmorPolicy / VarmorClusterPolicy

| Field | Description |
|-------|-------------|
|apiVersion<br />*string*|APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources|
|kind<br />*string*|Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds|
|metadata<br />*ObjectMeta*|Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata|
|spec<br />*[VarmorPolicySpec](#varmorpolicyspec)*|Spec describes the desired policy to be used for hardening the target workloads.|
|status<br />*[VarmorPolicyStatus](#varmorpolicystatus)*|Status describes the observed status of the policy.|

## VarmorPolicySpec

| Field | Description |
|-------|-------------|
|target<br />*[Target](#target)*|Target specifies the workloads and their containers you want to harden.|
|policy<br />*[Policy](#policy)*|Policy specifies which enforcer, mode and rules you want to use to apply to the target.|
|updateExistingWorkloads<br />*bool*|Optional. UpdateExistingWorkloads is used to indicate whether to perform a rolling update on target existing workloads, thus enabling or disabling the protection of the target workloads when policies are created or deleted.  (Default: false)<br /><br />Note: vArmor only performs a rolling update on Deployment, StatefulSet, or DaemonSet type workloads. If `.spec.target.kind` is Pod, you need to rebuild the Pod yourself to enable or disable protection.

### Target

| Field | Description |
|-------|-------------|
|kind<br />*string*|Kind is used to specify the type of workloads for the protection targets.<br />Available values: Deployment, StatefulSet, DaemonSet, Pod|
|name<br />*string*|Optional. Name is used to specify a specific workload in the policy's namespace or all namespace.|
|containers<br />*string array*|Optional. Containers are used to specify the names of the containers. If it is empty, sandbox protection will be enabled for all containers within the workload (excluding initContainers and ephemeralContainers).|
|selector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|Optional. Selector is a label selector which selects workloads in the policy's namespace or all namespace. This field follows standard label selector semantics. <br /><br />Note that the selector field and name field are mutually exclusive.|

### Policy

| Field | Description |
|-------|-------------|
|enforcer<br />*string*|Enforcer is used to specify which security mechanism to use for mandatory access control. <br />Available values: AppArmor, BPF, Seccomp, AppArmorBPF, AppArmorSeccomp, BPFSeccomp, AppArmorBPFSeccomp|
|mode<br />*string*|Mode used to specify the protection mode.<br />Available values: AlwaysAllow, RuntimeDefault, EnhanceProtect, BehaviorModeling, DefenseInDepth|
|enhanceProtect<br />*[EnhanceProtect](#enhanceprotect)*|EnhanceProtect configures the EnhanceProtect mode. It allows you to set built-in and custom rules to generate profiles for workload protection and control the behavior of profiles (e.g., audit or allow violations).|
|modelingOptions<br />*[ModelingOptions](#modelingoptions)*|ModelingOptions configures the BehaviorModeling mode.|
|defenseInDepth<br />*[DefenseInDepth](#defenseindepth)*|DefenseInDepth configures the DefenseInDepth mode.

## EnhanceProtect

| Field | Description |
|-------|-------------|
|hardeningRules<br />*string array*|Optional. HardeningRules are used to specify the built-in hardening rules.|
|attackProtectionRules<br />*[AttackProtectionRules](#attackprotectionrules) array*|Optional. AttackProtectionRules are used to specify the built-in attack protection rules.|
|vulMitigationRules<br />*string array*|Optional. VulMitigationRules are used to specify the built-in vulnerability mitigation rules.|
|appArmorRawRules<br />*[AppArmorRawRules](#apparmorrawrules) array*|Optional. AppArmorRawRules is used to set custom AppArmor rules.|
|bpfRawRules<br />*[BpfRawRules](#bpfrawrules) array*|Optional. BpfRawRules is used to set custom BPF rules.|
|syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec@v1.1.0/specs-go#LinuxSyscall) array*|Optional. SyscallRawRules is used to set the custom syscalls blocklist rules with Seccomp enforcer. Please refer to [this document](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) to create custom rules.|
|privileged<br />*bool*|Optional. Privileged is used to identify whether the policy is for the privileged container. If set to false, the **EnhanceProtect** mode will build AppArmor or BPF profile on top of the **RuntimeDefault** mode. Otherwise, it will build AppArmor or BPF profile on top of the **AlwaysAllow** mode. (Default: false)<br /><br />Note: If set to true, vArmor will not build Seccomp profile for the target workloads.|
|auditViolations<br />*bool*|Optional. AuditViolations determines whether to log the actions that violate the mandatory access control rules. If this field is set, any detected violation will be logged to `/var/log/varmor/violations.log` file in the host. The action of the event will be `AUDIT` if allowViolations is set to true, otherwise it will be `DENIED`.<br /><br />Please note that the Seccomp enforcer does not support auditing violations when the allowViolations field is set to false. (Default: false)|
|allowViolations<br />*bool*|Optional. AllowViolations determines whether to allow the actions that are against mandatory access control rules. If this field is set, any detected violation will be allowed rather than blocked. (Default: false)|

### AttackProtectionRules

| Field | Description |
|-------|-------------|
|rules<br />*string array*|Rules is the list of built-in attack protection rules to be used.|
|targets<br />*string array*|Optional. Targets specifies the executable files for which the rules apply. They must be specified as full paths to the executable files. This feature is only effective when using AppArmor enforcer.|

### AppArmorRawRules

| Field | Description |
|-------|-------------|
|rules<br />*string*|Rules defines the custom AppArmor rules. You should ensure they conform to [AppArmor Syntax](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) on your own.|
|targets<br />*string*|Optional. Targets specifies the executable files for which the rules apply. They must be specified as full paths to the executable files.|

### BpfRawRules

| Field | Description |
|-------|-------------|
|files<br />*[FileRule](#filerule) array*|Optional. Files specifies the file access control rules.|
|processes<br />*[FileRule](#filerule) array*|Optional. Processes specifies the process access control rules.|
|network<br />*[NetworkRule](#networkrule)*|Optional. Network specifies the network access control rules.|
|ptrace<br />*[PtraceRule](#ptracerule)*|Optional. Ptrace specifies the ptrace-based access control rules.|
|mounts<br />*[MountRule](#mountrule) array*|Optional. Mounts specifies mount point access control rules.|

### FileRule

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|pattern<br />*string*|Pattern can be any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching file paths and filenames.|
|permissions<br />*string array*|Permissions are used to specify the file permissions.<br />Available values: `all(*), read(r), write(w), append(a), exec(e)`|

### NetworkRule

| Field | Description |
|-------|-------------|
|sockets<br />*[NetworkSocketRule](#networksocketrule) array*|Optional. Sockets are the list of network socket rules to match traffic for socket(2) operations.|
|egress<br />*[NetworkEgressRule](#networkegressrule)*|Optional. Egress defines network egress rules to match traffic for connect(2) operations.|

### PtraceRule

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|strictMode<br />*bool*|Optional. StrictMode is used to indicate whether to restrict ptrace operations for all source and destination processes. If set to false, it allows a process to perform trace and read operations on other processes within the same container, and also allows a process to be subjected to traceby and readby operations by other processes within the same container. If set to true, it prohibits all trace, read, traceby, and readby operations within the container.(Default: false)|
|permissions<br />*string array*|Permissions are used to indicate which ptrace-related permissions of the target container should be restricted. <br />Available values: `all(*), trace, traceby, read, readby` <br /><br />- trace: prohibiting tracing of other processes. <br />- read: prohibiting reading of other processes. <br />- traceby: prohibiting being traced by other processes (excluding the host processes). <br />- readby: prohibiting being read by other processes (excluding the host processes).<br /><br />The trace, traceby permissions for "write" operations, or other operations that are more dangerous, such as: ptrace attaching (PTRACE_ATTACH) to another process or calling process_vm_writev(2).<br /><br />The read, readby permissions for "read" operations or other operations that are less dangerous, such as: get_robust_list(2); kcmp(2); reading /proc/pid/auxv, /proc/pid/environ, or /proc/pid/stat; or readlink(2) of a /proc/pid/ns/* file.|

### MountRule

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|sourcePattern<br />*string*|SourcePattern can be any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching the source paramater of mount(2), the target paramater of umount(2), and the from_pathname paramater of move_mount(2).|
|fstype<br />*string*|Fstype is used to specify the type of filesystem (maximum length 16 bytes) to enforce. It can be `*` to match any type.|
|flags<br />*string array*|Flags are used to specify the mount flags to enforce. They are almost the same as the [MOUNT FLAGS LIST](https://manpages.ubuntu.com/manpages/focal/man5/apparmor.d.5.html) of AppArmor. <br />Available values: `all(*), ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec, sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime, silent, loud, relatime, norelatime, iversion, noiversion, strictatime, nostrictatime, remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private), make-slave(slave), make-shared(shared), make-runbindable, make-rprivate, make-rslave, make-rshared, umount`|

### NetworkSocketRule

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|domains<br />*string array*|Optional. Domains specifies the communication domains of socket. <br />Available values: `all(*), unix, inet, ax25, ipx, appletalk, netrom, bridge, atmpvc, x25, inet6, rose, netbeui, security, key, netlink, packet, ash, econet, atmsvc, rds, sna, irda, pppox, wanpipe, llc, ib, mpls, can, tipc, bluetooth, iucv, rxrpc, isdn, phonet, ieee802154, caif, alg, nfc, vsock, kcm, qipcrtr, smc, xdp, mctp`|
|types<br />*string array*|Optional. Types specifies the communication semantics of socket. <br />Available values: `all(*), stream, dgram, raw, rdm, seqpacket, dccp, packet`|
|protocols<br />*string array*|Optional. Protocols specifies the particular protocols to be used with the socket. <br />Available values: `all(*), icmp, tcp, udp`<br /><br />Note that the protocols field and types field are mutually exclusive. |

### NetworkEgressRule

| Field | Description |
|-------|-------------|
|toDestinations<br />*[Destination](#destination) Array*|Optional. ToDestinations describes specific IPs or IP blocks with ports to match traffic. Please ensure each IP/CIDR target is unique to avoid configuration ambiguity.|
|toServices<br />*[Service](#service) Array*|Optional. ToServices describes k8s services and their endpoints to match traffic. Please ensure selectors across service rules do NOT overlap. Overlapping rules may cause undefined behavior.|
|toPods<br />*[Pod](#pod) Array*|Optional. ToPods describes pods with ports to match traffic. Please ensure selectors across pod rules do NOT overlap. Overlapping rules may cause undefined behavior.

<br />Notes:
<br />- The toDestinations, toEntities, toServices, and toPods fields are in a logical OR relationship.
<br />- Within the same field, multiple rules are also in a logical OR relationship.
<br />- Overlapping rules targeting the same Pod/Service/IP may cause unintended port combinations or conflicts.
<br />- The system does NOT guarantee deduplication or conflict resolution for overlapping targets. Users must ensure that rules within these fields do NOT repeatedly define the same Pod/Service/IP to avoid unpredictable traffic control behavior.
<br />- The toServices rules only take effect when Kubernetes is v1.21 or higher.
<br />- The toPods rules only take effect when the [Pod Egress Control feature](installation.md#enable-pod-egress-control) is enabled.

### Destination

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|ip<br />*string*|Optional. IP defines this rule on a particular IP. Please use a valid textual representation of an IP, or special entities like `pod-self`, `unspecified` or `localhost`. Note that the ip field and cidr field are mutually exclusive.<br /><br />- pod-self: An entity that represents the Pod's own IP addresses. Pods may be allocated at most 1 address for each of IPv4 and IPv6.<br />- unspecified: An entity that represents the all-zeros address - specifically, 0.0.0.0 and ::. Its full name is unspecified address, referring to binding to all interfaces.<br />- localhost: An entity that represents the loopback addresses - specifically, 127.0.0.1 and ::1.|
|cidr<br />*string*|Optional. CIDR defines this rule on a particular CIDR. Note that the ip field and cidr field are mutually exclusive.|
|ports<br />*[Port](#port) array*|Optional. Ports defines this rule on particular ports. Each item in this list is combined using a logical OR. If this field is empty or not present, this rule matches all ports. If this field is present and contains at least one item, then this rule matches all ports in the list.|

### Service

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|namespace<br />*string*|Optional. Namespace specifies in which namespace to select services.|
|name<br />*string*|Optional. Name selects a service by the name and namespace pair.|
|serviceSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|Optional. ServiceSelector is a label selector which selects services. This field follows standard label selector semantics. It selects the services matching serviceSelector in the namespace. If the namespace field is empty or not present, it selects the services matching serviceSelector in all namespaces. Note that the serviceSelector field and name field are mutually exclusive.|

### Pod

| Field | Description |
|-------|-------------|
|qualifiers<br />*string array*|Qualifiers determine the behavior of the rule via combinations of values.<br />Available values: `deny, audit`|
|namespace<br />*string*|Optional. Namespace specifies in which namespace to select pods.|
|podSelector<br />*[LabelSelector](https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#LabelSelector)*|PodSelector is a label selector which selects pods. This field follows standard label selector semantics. It selects the pods matching podSelector in the namespace. If the namespace field is empty or not present, it selects the pods matching podSelector in all namespaces.|
|ports<br />*[Port](#port) array*|Optional. Ports defines this rule on particular ports. Each item in this list is combined using a logical OR. If this field is empty or not present, this rule matches all ports. If this field is present and contains at least one item, then this rule matches all ports in the list.|

### Port

| Field | Description |
|-------|-------------|
|port<br />*uint16*|Port is the port number to match traffic. The port number must be in the range [1, 65535].
|endPort<br />*uint16*|Optional. If endPort is set, it indicates that the range of ports from port to endPort. The endPort must be equal or greater than port and must be in the range [1, 65535].|

## ModelingOptions

| Field | Description |
|-------|-------------|
|duration<br />*int*| Duration is the duration in minutes for modeling. The modeling duration starts from the moment the policy is created and is only valid if the current time is earlier than the expected modeling completion time. This field supports dynamic adjustment, which can be used to end modeling early, extend the modeling duration, or restart modeling, and its value cannot be zero. |

## DefenseInDepth

| Field | Description |
|-------|-------------|
|appArmor<br />*[AppArmorProfile](#apparmorprofile)*|Optional. AppArmor specifies the AppArmor profile and additional custom rules for the Deny-by-Default protection.|
|seccomp<br />*[SeccompProfile](#seccompprofile)*|Optional. Seccomp specifies the Seccomp profile and additional custom rules for the Deny-by-Default protection.|
|allowViolations<br />*bool*|Optional. AllowViolations determines whether to allow the actions that are against mandatory access control rules. If this field is set, any detected violation will be allowed rather than blocked, and an audit event with the `ALLOWED` action will be generated and logged. This can be used to gather violations for improving Deny-by-Default protection profiles. If this field is not set, any detected violation will be blocked, and an audit event with the `DENIED` action will be generated and logged. (Default: false)

### AppArmorProfile

| Field | Description |
|-------|-------------|
|profileType<br />*string*|ProfileType indicates which kind of AppArmor profile will be applied. Valid options are: BehaviorModel - a profile generated via the BehaviorModeling mode will be used. Custom - a custom profile defined in the customProfile field will be used.|
|customProfile<br />*string*|Optional. CustomProfile holds the user-defined AppArmor profile content. It must be a valid profile that conforms to AppArmor syntax. If you want vArmor to apply the profile to target workloads automatically, the profile's name must match the ArmorProfile object name. For example:<br /><br /> abi \<abi/3.0\>,<br /> #include \<tunables/global\><br /> profile varmor-demo-demo-4 flags=(attach_disconnected,mediate_deleted) \{<br />\}<br /><br /> The profile name "varmor-demo-demo-4" is identical to the ArmorProfile object name.|
|appArmorRawRules<br />*[AppArmorRawRules](#apparmorrawrules) array*|Optional. appArmorRawRules specifies custom AppArmor rules. These rules will be added to the end of the AppArmor profile that you specified.|

### SeccompProfile

| Field | Description |
|-------|-------------|
|profileType<br />*string*|ProfileType indicates which kind of Seccomp profile will be applied. Valid options are: BehaviorModel - a profile generated via the BehaviorModeling mode will be used. Custom - a custom profile defined in the customProfile field will be used.|
|customProfile<br />*string*|Optional. CustomProfile holds the user-defined Seccomp profile content. It must be a valid profile that adheres to Seccomp syntax. Please refer to [this document](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) to create custom profiles.|
|syscallRawRules<br />*[LinuxSyscall](https://pkg.go.dev/github.com/opencontainers/runtime-spec/specs-go#LinuxSyscall) array*|Optional. SyscallRawRules specifies custom Seccomp rules. These rules will be added to the end of the Seccomp profile that you specified.|

## VarmorPolicyStatus

| Field | Description |
|-------|-------------|
|profileName<br />*string*|ProfileName is the name of the AppArmor, BPF and Seccomp profile that is generated by the policy. It is in the format of `varmor-{namespace}-{name}` for namespaced policies or `varmor-cluster-{namespace}-{name}` for cluster-scoped policies. It is equivalent to the name of the ArmorProfile object that is created by the policy.|
|conditions<br />*[VarmorPolicyCondition](#varmorpolicycondition) array*|Conditions is a list of conditions that indicate the status of the policy. It can include conditions such as Created, Updated, Ready, etc.|
|ready<br />*bool*|Ready is used to indicate whether the profile of policy is loaded.|
|phase<br />*string*|Phase is used to indicate the processing phase of the policy.<br />Possible values: Pending, Modeling, Completed, Protecting, Error.<br /><br />Note: You can find out which varmor-agent has an error by getting the ArmorProfile/status resource corresponding to the current VarmorPolicy or VarmorClusterPolicy object.

### VarmorPolicyCondition

| Field | Description |
|-------|-------------|
|type<br />*string*|Type of ArmorProfile condition.<br />Possible values: Created, Updated, Ready|
|status<br />*ConditionStatus*|Status of the condition, <br />Possible values: True, False, Unknown.|
|lastTransitionTime<br />*Time*|Last time the condition transitioned from one status to another.|
|reason<br />*string*|The reason for the condition's last transition.|
|message<br />*string*|A human readable message indicating details about the transition.|
