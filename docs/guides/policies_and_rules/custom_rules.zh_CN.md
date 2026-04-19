# 自定义规则

[English](custom_rules.md) | 简体中文

vArmor 支持用户基于 enforcer 的语法，在 EhanceProtect 模式的 [VarmorPolicy](../../getting_started/usage_instructions.zh_CN.md#varmorpolicy) 或 [VarmorClusterPolicy](../../getting_started/usage_instructions.zh_CN.md#varmorclusterpolicy) 对象中自定义访问控制规则。

注：BPF enforcer 支持的语法在持续开发中。

## AppArmor enforcer

AppArmor enforcer 支持用户根据 AppArmor 的语法定制策略。

请参见此 [文档](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html) 在 `.spec.policy.enhanceProtect.appArmorRawRules` 或 `.spec.policy.defenseInDepth.appArmor.appArmorRawRules` 字段中设置自定义规则。请确保每条规则以 ',' 结尾。

**示例：**

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

Seccomp enforcer 支持用户根据 OCI 规范的语法定制策略。

请参见此 [文档](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) 在 `.spec.policy.enhanceProtect.syscallRawRules` 或 `.spec.policy.defenseInDepth.seccomp.syscallRawRules` 字段中设置自定义的系统调用规则。

**示例：**

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

BPF enforcer 支持用户根据语法定制策略。每类规则的数量上限为 50 条。每个节点支持最多对 100 个容器开启沙箱。

请参考 [BpfRawRules](../../getting_started/interface_specification.md#bpfrawrules) 和以下语法，在 `.spec.policy.enhanceProtect.bpfRawRules` 中设置自定义规则。

### 文件权限定义

  | 权限 / 权限缩写 | 隐含权限 | 说明 |
  |---------------|---------|-----|
  |read / r|-<br />rename<br />hard link|禁止读<br />禁止利用 rename **oldpath** newpath 绕过 oldpath 的读限制<br />禁止利用 ln **TARGET** LINK_NAME 绕过 TARGET 的读限制
  |write / w|-<br />append<br />rename<br />hard link<br />symbol link<br />chmod<br />chown|禁止写<br />禁止利用 O_APPEND flag 绕过 map_file_to_perms() 实现追加写操作<br />禁止利用 rename oldpath **newpath** 绕过 newpath 的写限制<br />禁止利用 ln TARGET **LINK_NAME** 绕过 LINK_NAME 的写限制<br />禁止利用创建软链接（符号链接）绕过目标文件的写限制<br />WIP<br />WIP
  |exec / x|-|禁止执行
  |append / a|-|禁止追加写

* **文件路径匹配**

  BPF enfocer 支持根据路径 Pattern 对文件进行匹配，并支持两种匹配模式（精确匹配、通配匹配），匹配 Pattern 的最大长度限制为 64 字节。

  |通配符|语法|样例|说明|
  |-----|---|---|----|
  |*|- 仅用于匹配叶子结点的文件名<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 *，且不支持 \*\* 和 * 一起出现|- fi\* 代表匹配任意以 fi 开头的文件名<br />- *le 代表匹配任意以 le 结尾的文件名<br />- *.log 代表匹配任意以 .log 结尾的文件名|此通配符的行为可能会在后续版本中发生改变|
  |\**|- 在多级目录中，匹配零个、一个、多个字符<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 \*\*，且不支持 ** 和 * 一起出现|- /tmp/\*\*/33 代表匹配任意以 /tmp 开头，且以 /33 结尾的文件，包含 /tmp/33<br />- /tmp/\*\* 代表匹配任意以 /tmp 开头的文件、目录<br />- /tm** 代表匹配任意以 /tm 开头的文件、目录<br />- /t**/33 代表匹配任意以 /t 开头，以 /33 结尾的文件、目录
  
### 网络地址匹配

* 当前 vArmor 支持对指定的 IP 地址、IP 地址块（CIDR 块）、端口进行外联访问控制
* 当指定了 IP 地址、IP 地址块，但未指定端口时，默认对所有端口生效
* 具体请参见 [NetworkEgressRule](../../getting_started/interface_specification.zh_CN.md#networkegressrule)

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

NetworkProxy enforcer 支持用户基于 sidecar 代理在应用协议层面定制网络访问控制规则。

与 BPF enforcer 在内核层面执行的网络规则不同，NetworkProxy 规则工作在 L4（域名/SNI 匹配）和 L7（HTTP 匹配）层面。当 BPF 和 NetworkProxy 规则同时生效时，BPF 规则先在内核层面执行，只有通过 BPF 规则的连接才会进入 sidecar 代理接受 NetworkProxy 规则评估。

请参考 [NetworkProxyRules](../../getting_started/interface_specification.md#networkproxyrules) 和以下说明，在 `.spec.policy.enhanceProtect.networkProxyRawRules` 或 `.spec.policy.defenseInDepth.networkProxy` 中设置自定义规则。

* **L4 出口规则**

  基于目标 IP、CIDR 和端口控制出站连接。每条规则通过 qualifiers（`allow`、`deny`、`audit`）决定行为。

* **L7 HTTP 规则**

  在请求层面通过匹配 host、path 和 method 控制 HTTP/HTTPS 流量：

  - **hosts**: 对于 HTTPS 通过 TLS SNI 匹配，对于 HTTP 通过 Host header 匹配。支持精确匹配和通配符（如 `*.openai.com`）。
  - **paths**: 对请求路径进行精确或前缀匹配。HTTPS 流量需要配置 MITM 才生效。
  - **methods**: 匹配 HTTP 方法（如 GET、POST）。HTTPS 流量需要配置 MITM 才生效。

  对于 HTTPS 流量，HTTP 规则需要配置 TLS MITM。未配置 MITM 时，仅 hosts 匹配生效，paths 和 methods 规则将被忽略。

* **defaultAction**

  未匹配到任何规则的连接的默认动作：
  - `deny`: 白名单模式，仅显式允许的连接可以通过。
  - `allow`: 黑名单模式，仅显式拒绝的连接会被阻断。

  deny 规则优先于 allow 规则。既不匹配 deny 也不匹配 allow 的连接将按 `defaultAction` 处理。

  关于审计日志的说明：
  - 当 `defaultAction` 为 `deny` 时，被拦截的请求默认会生成审计日志。
  - 当 `defaultAction` 为 `allow` 时，被放行的请求默认**不会**生成审计日志。

**示例：**

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

你也可以放行所有流量，同时记录每条请求用于数据收集：

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
