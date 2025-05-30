---
sidebar_position: 3
description: Customize access control rules in EnhanceProtect mode.
---

# The Custom Rules

vArmor allows users to customize access control rules in [VarmorPolicy](../../getting_started/usage_instructions#varmorpolicy) or [VarmorClusterPolicy](../../getting_started/usage_instructions#varmorclusterpolicy) objects in **EnhanceProtect** mode based on the enforcer syntax.

Note:<br />- The syntax supported by BPF enforcer is still under development.

### AppArmor enforcer

The AppArmor enforcer supports users in customizing policies based on the syntax of AppArmor.

Please refer to the [syntax](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) of security profiles for AppArmor to set custom rules in the [`.spec.policy.enhanceProtect.appArmorRawRules`](../../getting_started/interface_specification.md) field.

**Use case:**

```yaml
policy:
  enforcer: AppArmor
  mode: EnhanceProtect
  enhanceProtect:
    # Audit the actions that violate the mandatory access control rules.
    # Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
    # It's disabled by default.
    auditViolations: true
    attackProtectionRules:
    - rules:
      - disable-chmod
    - rules:
      - mitigate-sa-leak
      targets:
      - "/bin/bash"
      - "/bin/dash"
      - "/bin/sh"
    // highlight-start
    appArmorRawRules:
    - rules: |
        audit deny /etc/hosts r,
        audit deny /etc/shadow r,
    - rules: "audit deny /etc/hostname r,"
      targets:
      - "/bin/bash"
    // highlight-end
```

### Seccomp enforcer

The Seccomp enforcer supports users in customizing policies based on the syntax of OCI specification.

Please refer to this [document](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) to set custom syscalls blocklist rules in the [`.spec.policy.enhanceProtect.syscallRawRules`](../../getting_started/interface_specification.md) field.

**Use case:**

```yaml
policy:
  enforcer: Seccomp
  mode: EnhanceProtect
  enhanceProtect:
    // highlight-start
    syscallRawRules:
    # disallow chmod +x XXX, chmod 111 XXX, chmod 001 XXX, chmod 010 XXX...
    - names:
      - fchmodat
      action: SCMP_ACT_ERRNO
      args:
      - index: 2
        value: 0x40     # S_IXUSR
        valueTwo: 0x40
        op: SCMP_CMP_MASKED_EQ
      - index: 2
        value: 0x8      # S_IXGRP
        valueTwo: 0x8
        op: SCMP_CMP_MASKED_EQ
      - index: 2
        value: 1        # S_IXOTH
        valueTwo: 1
        op: SCMP_CMP_MASKED_EQ
    // highlight-end
```

### BPF enforcer

The BPF enforcer supports users in customizing policies based on the syntax, with an upper limit of 50 rules per rule type. Each node of Kubernetes can enable sandboxing for up to 100 containers.

Please refer to the syntaxes below to set custom rules in the [`.spec.policy.enhanceProtect.bpfRawRules`](../../getting_started/interface_specification.md#bpfrawrules) field.

* **File Permission**
  
  | Permission / Permission Abbreviate |  Implied Permissions | Description |
  |------------------------------------|----------------------|-------------|
  |read / r|-<br />rename<br />hard link|Restrict read permission.<br />Prohibit abusing 'rename **oldpath** newpath' to bypass read restrictions on oldpath.<br />Prohibit abusing 'ln **TARGET** LINK_NAME' to bypass read restrictions on TARGET.
  |write / w|-<br />append<br />rename<br />hard link<br />symbol link<br />chmod<br />chown|Restrict write permission.<br />Prohibit using the O_APPEND flag to bypass map_file_to_perms() for append operations.<br />Prohibit abusing 'rename oldpath **newpath**' to bypass write restrictions on newpath.<br />Prohibit abusing 'ln TARGET **LINK_NAME**' to bypass write restrictions on LINK_NAME.<br />Prohibit abusing symlink to bypass write restrictions on the target file.<br />WIP<br />WIP
  |exec / x|-|Prohibit execution permission.
  |append / a|-|Prohibit append permission.

* **File Globbing Syntax**

  | Globbing | Description | Examples | Notes |
  |----------|-------------|----------|-------|
  |*|- Used only to match file names.<br />- It will match dot files except the special dot files . and ..<br />- Supports only a single *, and does not support \*\* and * appearing together.|- fi\* matches any file name starting with 'fi'.<br />- *le matches any file name ending with 'le'.<br />- *.log matches any file name ending with '.log'|The behavior of this globbing may change in future versions.|
  |\**|- Match zero, one, or multiple characters in multi-level directories.<br />- It will match dot files except the special dot files . and ..<br />- Supports only a single \*\*, and does not support ** and * appearing together.|- /tmp/\*\*/33 matches any file that starts with /tmp and ends with /33, including /tmp/33.<br />- /tmp/\*\* matches any file or directory that starts with /tmp.<br />- /tm** matches any file or directory that starts with /tm.<br />- /t**/33 matches any file or directory that starts with /t and ends with /33.

* **Network Permission**

  * Currently, vArmor supports connection access control for specified IP addresses, IP address blocks (CIDR blocks), and ports.
  * When specific IP addresses or IP address blocks are specified without specifying ports, it defaults to affecting all ports.
  * Please refer to [NetworkEgressRule](../../getting_started/interface_specification.md#networkegressrule) for specific details.


**Use case:**

```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    # Audit the actions that violate the mandatory access control rules.
    # Any detected violation will be logged to /var/log/varmor/violations.log file in the host.
    # It's disabled by default.
    auditViolations: true
    // highlight-start
    bpfRawRules:
      processes:
      - pattern: "**ping"
        permissions:
        - exec
      network:
        egresses:
        - ip: fdbd:dc01:ff:307:9329:268d:3a27:2ca7
        - ipBlock: 192.168.1.1/24 # 192.168.1.0 to 192.168.1.255
          port: 80
        sockets:
        - protocols:
          - "udp"
    // highlight-end
```
