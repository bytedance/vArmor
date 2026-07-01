# The Custom Rules

English | [简体中文](custom_rules.zh_CN.md)

vArmor allows users to customize access control rules in the **EnhanceProtect** and **DefenseInDepth** modes based on the enforcer syntax. AppArmor, BPF, and NetworkProxy control the disposition action and auditing behavior of a rule via its qualifiers, while Seccomp uses the OCI `action` semantics (such as `SCMP_ACT_ERRNO`).

Different enforcers recognize different sets of rule qualifiers, and the actions that can be derived from them are shown in the table below:

| Enforcer | Recognized Qualifiers | Derivable Actions |
| --- | --- | --- |
| AppArmor | Rules are **raw AppArmor text**; qualifiers such as `audit` / `deny` are written directly by the author and are not re-parsed by vArmor | `DENIED` / `AUDIT` |
| BPF | Recognizes only `deny` and `audit` | `DENIED` / `AUDIT` |
| NetworkProxy | Recognizes `allow`, `deny`, and `audit`, combined with `defaultAction` | `DENIED` / `AUDIT` |

> The "Derivable Actions" column refers to actions **derived from rule qualifiers**, so none of them include `ALLOWED`. `ALLOWED` is unrelated to any qualifier; it is produced only in the **DefenseInDepth** mode with `allowViolations=true`, when access not covered by the allowlist is allowed and logged. See [Disposition Actions and Auditing](policy_modes/README.md#disposition-actions-and-auditing) of the policy modes for details.

## AppArmor enforcer

The AppArmor enforcer supports users in customizing policies based on the syntax of AppArmor.

Please refer to this [document](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) to set custom syscalls blocklist rules in the `.spec.policy.enhanceProtect.syscallRawRules` or `.spec.policy.defenseInDepth.seccomp.syscallRawRules` field. Please ensure that each rule ends with a comma.

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
    appArmorRawRules:
    - rules: |
        audit deny /etc/hosts r,
        audit deny /etc/shadow r,
    - rules: "audit deny /etc/hostname r,"
      targets:
      - "/bin/bash"
```

## Seccomp enforcer

The Seccomp enforcer supports users in customizing policies based on the syntax of OCI specification.

Please refer to this [document](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) to set custom syscalls blocklist rules in the `.spec.policy.enhanceProtect.syscallRawRules` or `.spec.policy.defenseInDepth.seccomp.syscallRawRules` field.

**Use case:**

```yaml
policy:
  enforcer: Seccomp
  mode: EnhanceProtect
  enhanceProtect:
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
```

## BPF enforcer

The BPF enforcer supports users in customizing policies based on the syntax, with an upper limit of 50 rules per rule type. Each node of Kubernetes can enable sandboxing for up to 100 containers.

Please refer to [BpfRawRules](../../getting_started/interface_specification.md#bpfrawrules) and the syntaxes below to set custom rules in `.spec.policy.enhanceProtect.bpfRawRules`.

### File Permission
  
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

### Network Permission
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
    bpfRawRules:
      processes:
      - pattern: "**ping"
        permissions:
        - exec
        qualifiers:
        - audit
        - deny
      network:
        egresses:
          toDestinations:
          - ip: fdbd:dc01:ff:307:9329:268d:3a27:2ca7
            qualifiers:
            - audit
          - cidr: 192.168.1.1/24 # 192.168.1.0 to 192.168.1.255
            ports:
            - port: 80
              endPort: 8080
            qualifiers:
            - audit
        sockets:
        - protocols:
          - "udp"
          qualifiers:
          - audit
```

## NetworkProxy enforcer

The NetworkProxy enforcer supports users in customizing network access control rules that operate at the application protocol level via a sidecar proxy.

Unlike BPF network rules which operate at the kernel level, NetworkProxy rules work at L4 (domain/SNI matching) and L7 (HTTP matching). When both BPF and NetworkProxy rules are active, BPF rules execute first at the kernel level; only connections allowed by BPF reach the sidecar proxy for NetworkProxy evaluation.

Please refer to [NetworkProxyRules](../../getting_started/interface_specification.md#networkproxyrules) and the details below to set custom rules in `.spec.policy.enhanceProtect.networkProxyRawRules` or `.spec.policy.defenseInDepth.networkProxy`.

* **L4 Egress Rules**

  Control outbound connections based on destination IP, CIDR, and port. Each rule has qualifiers (`allow`, `deny`, `audit`) that determine its behavior.

* **L7 HTTP Rules**

  Control HTTP/HTTPS traffic at the request level by matching host, path, and method:

  - **hosts**: matched via TLS SNI for HTTPS, or Host header for HTTP. Supports exact match and wildcard (`*.openai.com`).
  - **paths**: exact or prefix matching for request paths. Requires MITM for HTTPS traffic.
  - **methods**: HTTP methods to match (e.g., GET, POST). Requires MITM for HTTPS traffic.

  For HTTPS traffic, HTTP rules require TLS MITM to be configured. Without MITM, only host matching applies and path/method rules are ignored.

* **defaultAction**

  The default action for connections that do not match any rule:
  - `deny`: whitelist mode, only explicitly allowed connections are permitted.
  - `allow`: blacklist mode, only explicitly denied connections are blocked.

  Deny rules take precedence over allow rules. Connections matching neither are subject to `defaultAction`.

  Note on auditing:
  - The NetworkProxy records audit logs only when `defaultAction` is `deny`, or when at least one rule carries the `audit` qualifier; otherwise no audit events are produced.
  - Its reporting channel maps only `deny` → `DENIED` and `audit` → `AUDIT`; it **never produces `ALLOWED`**.

**Use case:**

```yaml
policy:
  enforcer: NetworkProxy
  mode: EnhanceProtect
  enhanceProtect:
    networkProxyRawRules:
      egress:
        defaultAction: deny
        rules:
        - qualifiers:
          - allow
          cidr: 192.168.1.0/24
          ports:
          - port: 80
          - port: 443
        - qualifiers:
          - deny
          - audit
          ip: 10.0.0.1
        httpRules:
        - qualifiers:
          - allow
          match:
            hosts:
            - api.openai.com
            - "*.openai.com"
            ports:
            - port: 443
            paths:
            - prefix: /v1/chat
            methods:
            - POST
        - qualifiers:
          - deny
          match:
            hosts:
            - internal.example.com
  networkProxyConfig:
    proxyUID: 1337
    proxyPort: 15001
    proxyAdminPort: 15000
```

You can also allow all traffic while logging every request for data collection:

```yaml
policy:
  enforcer: NetworkProxy
  mode: EnhanceProtect
  enhanceProtect:
    networkProxyRawRules:
      egress:
        defaultAction: allow
        rules:
        - qualifiers: ["audit"]
          cidr: "0.0.0.0/0"
```
