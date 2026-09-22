---
sidebar_position: 3
description: 在 EnhanceProtect 模式下自定义访问控制规则。
---

# 自定义规则

vArmor 支持用户基于 enforcer 的语法，在 EnhanceProtect 和 DefenseInDepth 模式下自定义访问控制规则。其中 AppArmor、BPF 和 NetworkProxy 通过规则限定词（qualifiers）控制规则的处置动作与审计行为；Seccomp 则使用 OCI 规范的 `action` 语义（如 `SCMP_ACT_ERRNO`）。

不同 enforcer 识别的规则限定词（qualifiers）集合并不相同，据此可推导出的动作如下表所示：

| Enforcer | 可识别的 Qualifiers | 可产生的动作 |
| --- | --- | --- |
| AppArmor | `allow` / `deny` / `audit`，规则为**原始 AppArmor 文本**，由编写者直接写入 | `DENIED` / `AUDIT` |
| BPF | `deny`、`audit` | `DENIED` / `AUDIT` |
| NetworkProxy | `allow`、`deny`、`audit`，并与 `defaultAction` 组合 | `DENIED` / `AUDIT` |

> 表中“可产生的动作”指**由规则限定词推导**出的动作，因此都不含 `ALLOWED`。`ALLOWED` 与任何限定词无关，仅在 **DefenseInDepth 模式**且 `allowViolations=true` 时，对未被允许清单覆盖的访问放行并记录，详见[策略模式的处置动作与审计](policy_modes/index.md#disposition-actions-and-auditing)。

## AppArmor enforcer
AppArmor enforcer 支持用户根据 AppArmor 的语法定制策略。

请参见此 [文档](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) 在 `.spec.policy.enhanceProtect.appArmorRawRules` 或 `.spec.policy.defenseInDepth.appArmor.appArmorRawRules` 字段中设置自定义规则。请确保每条规则以 ',' 结尾。

**示例：**

```yaml
policy:
  enforcer: AppArmor
  mode: EnhanceProtect
  enhanceProtect:
    # Audit the actions that violate the built-in rules.
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

## Seccomp enforcer
Seccomp enforcer 支持用户根据 OCI 规范的语法定制策略。

请参见此 [文档](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) 在 `.spec.policy.enhanceProtect.syscallRawRules` 或 `.spec.policy.defenseInDepth.seccomp.syscallRawRules` 字段中设置自定义的系统调用规则。

**示例：**

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

## BPF enforcer
BPF enforcer 支持用户根据语法定制策略。每类规则的数量上限为 50 条。每个节点支持最多对 100 个容器开启沙箱。

请参考 [BpfRawRules](../../getting_started/interface_specification.md#bpfrawrules) 和以下语法，在 `.spec.policy.enhanceProtect.bpfRawRules` 中设置自定义规则。

* **File Permission**
  
  | 权限 / 权限缩写 | 隐含权限 | 说明 |
  |---------------|---------|-----|
  |read / r|-<br />rename<br />hard link|禁止读<br />禁止利用 rename **oldpath** newpath 绕过 oldpath 的读限制<br />禁止利用 ln **TARGET** LINK_NAME 绕过 TARGET 的读限制
  |write / w|-<br />append<br />rename<br />hard link<br />symbol link<br />chmod<br />chown|禁止写<br />禁止利用 O_APPEND flag 绕过 map_file_to_perms() 实现追加写操作<br />禁止利用 rename oldpath **newpath** 绕过 newpath 的写限制<br />禁止利用 ln TARGET **LINK_NAME** 绕过 LINK_NAME 的写限制<br />禁止利用创建软链接（符号链接）绕过目标文件的写限制<br />WIP<br />WIP
  |exec / x|-|禁止执行
  |append / a|-|禁止追加写

* **File Globbing Syntax**

  BPF enfocer 支持根据路径 Pattern 对文件进行匹配，并支持两种匹配模式（精确匹配、通配匹配），匹配 Pattern 的最大长度限制为 64 字节。

  |通配符|语法|样例|说明|
  |-----|---|---|----|
  |*|- 仅用于匹配叶子结点的文件名<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 *，且不支持 \*\* 和 * 一起出现|- fi\* 代表匹配任意以 fi 开头的文件名<br />- *le 代表匹配任意以 le 结尾的文件名<br />- *.log 代表匹配任意以 .log 结尾的文件名|此通配符的行为可能会在后续版本中发生改变|
  |\**|- 在多级目录中，匹配零个、一个、多个字符<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 \*\*，且不支持 ** 和 * 一起出现|- /tmp/\*\*/33 代表匹配任意以 /tmp 开头，且以 /33 结尾的文件，包含 /tmp/33<br />- /tmp/\*\* 代表匹配任意以 /tmp 开头的文件、目录<br />- /tm** 代表匹配任意以 /tm 开头的文件、目录<br />- /t**/33 代表匹配任意以 /t 开头，以 /33 结尾的文件、目录

* **Network Permission**

  * 当前 vArmor 支持对指定的 IP 地址、IP 地址块（CIDR 块）、端口进行外联访问控制。
  * 当指定了 IP 地址、IP 地址块，但未指定端口时，默认对所有端口生效。
  * 具体请参见 [NetworkEgressRule](../../getting_started/interface_specification.md#networkegressrule)。

**示例：**

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
    // highlight-end
```

## NetworkProxy 执行器 {#networkproxy-enforcer}

完整流程见 [NetworkProxy 指南](../enforcers/networkproxy/index.md)，字段见 [NetworkProxyRules](../../getting_started/interface_specification.md#networkproxyrules)。根据模式使用 enhanceProtect.networkProxyRawRules 或 defenseInDepth.networkProxy。

- L4 规则匹配目标 IP/CIDR 和端口。
- 明文 HTTP/MITM 规则匹配 Host/authority、路径、方法和目标端口。
- TLS 透传时，有 hosts 的 HTTP 规则只匹配 SNI/端口，**忽略路径与方法**；没有 hosts 则不生成 SNI 权限。
- deny 优先；默认拒绝下，匹配的 L4 allow 可以独立于更窄的 HTTP allow 授权。audit 单独不会放行。

下面的**策略片段**仅允许指定明文 HTTP 请求并记录审计：

```yaml
policy:
  enforcer: NetworkProxy
  mode: EnhanceProtect
  enhanceProtect:
    networkProxyRawRules:
      egress:
        defaultAction: deny
        httpRules:
        - qualifiers: [allow, audit]
          match:
            hosts: [backend.example.com]
            ports: [{port: 80}]
            paths: [{prefix: /public/}]
            methods: [GET]
```

HTTPS 路径/方法控制需要 [MITM 和应用信任](../enforcers/networkproxy/tls-and-credentials.md)，完整可执行资源见[快速开始](../enforcers/networkproxy/quick-start.mdx)。

日志同时取决于实际决定和匹配的审计规则。默认允许下静默 deny 无日志；默认拒绝下 allow 无 audit 也无日志。详见[审计矩阵](../enforcers/networkproxy/observability.md#audit-decision-matrix)。NetworkProxy 使用 DENIED/AUDIT，不产生 ALLOWED。
