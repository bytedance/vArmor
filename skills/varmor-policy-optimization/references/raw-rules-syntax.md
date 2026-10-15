# 自定义规则（RawRules）语法

自定义规则直接使用各 enforcer 支持的源结构，不经过内置 ID 翻译。模型负责理解这些对象的字段
层级与格式。本地脚本只做明显的结构类型检查与优化约束，**不是完整 CRD 校验**；字段是否真正合法，
以目标集群的 `kubectl --dry-run=server`（Schema 权威）为准。

注意：不同 RawRules 的"目标"位置不同，**没有统一的 `rules + targets` 格式**。

## 1. appArmorRawRules

规则组数组，`rules` 是 AppArmor 文本（每条通常以逗号结尾），可选 `targets`：

```yaml
appArmorRawRules:
- rules: |
    audit deny /etc/shadow r,
    audit deny /root/.ssh/** rw,
  targets:
  - /bin/sh
```

- qualifier：`audit` 记录，`deny` 拒绝；`audit deny` 是"记录并拒绝"，不是 audit-only。
- 权限：`r`/`w`/`a`/`x` 等。glob：`*` 不跨 `/`，`**` 跨目录层级。
- `allowViolations` 不会改写 appArmorRawRules 的文本。
- 语法是否被接受由目标节点的 AppArmor 加载器决定。

## 2. bpfRawRules

结构化对象，目标分散在各自字段中。

### 文件 / 进程

```yaml
bpfRawRules:
  files:
  - qualifiers: [audit, deny]
    pattern: /etc/example/**
    permissions: [read, write, append]
  processes:
  - qualifiers: [audit]
    pattern: "**/curl"
    permissions: [exec]
```

- `qualifiers`：`audit` 仅记录；含 `deny` 拒绝。
- 文件权限：`all`/`*`/`read`/`r`/`write`/`w`/`append`/`a`；进程用 `exec`/`x`。
- 注意：本地脚本只检查 bpfRawRules 是对象，**深层 pattern/qualifier 约束并不由程序校验**，
  由模型检查与 server dry-run 验证（不要误以为已被确定性校验）。

### 网络

```yaml
bpfRawRules:
  network:
    sockets:
    - qualifiers: [audit, deny]
      domains: [inet, inet6]
      types: [raw]
    egress:
      toDestinations:
      - qualifiers: [deny]
        ip: 169.254.169.254
        cidr: 10.0.0.0/8
        ports:
        - port: 443
          endPort: 450
      toServices:
      - namespace: payment
        name: payment-db
      toPods:
      - namespace: obs
        podSelector:
          matchLabels: {app: gateway}
        ports:
        - port: 4317
```

- 目标在 `domains/types`、`ip/cidr`、`serviceSelector`、`podSelector`、`ports` 中。
- 不同分支/数组元素是逻辑"或"；未配 ports 时匹配该目标所有端口。
- `toServices`/`toPods` 依赖控制面持续解析对象与 Endpoint。

### ptrace / mounts

```yaml
bpfRawRules:
  ptrace:
    qualifiers: [audit, deny]
    strictMode: false
    permissions: [trace, read]
  mounts:
  - qualifiers: [deny]
    pattern: /etc/**
    fstype: ext4
    flags: [ro, bind]
```

- ptrace 权限：`trace`/`traceby`/`read`/`readby`；`strictMode=false` 时同容器进程有默认例外。
- mounts 可匹配 source pattern、fstype 和 flags；mount 规则只在 `privileged=true` 时生成。

## 3. syscallRawRules（OCI LinuxSyscall）

```yaml
syscallRawRules:
- names: [chmod, fchmodat]
  action: SCMP_ACT_ERRNO
  args:
  - index: 2
    op: SCMP_CMP_MASKED_EQ
    value: 64
    valueTwo: 64
```

- `names` 一个或多个 syscall，共享 `action` 与 `args`。
- action：除 `SCMP_ACT_ALLOW`/`SCMP_ACT_LOG` 外均可能阻断（ERRNO、KILL*、TRAP、TRACE、NOTIFY）。
- 参数是原始整数，不含文件路径或 Kubernetes 对象语义。观察期建议用 `SCMP_ACT_LOG`。

## 4. networkProxyRawRules

仅在 enforcer 含 `NetworkProxy` 时生效：

```yaml
networkProxyRawRules:
  egress:
    defaultAction: deny
    rules:
    - qualifiers: [audit]
      match:
        hosts: [api.example.com]
        ports: [{port: 443}]
    httpRules:
    - qualifiers: [audit]
      match:
        hosts: [api.example.com]
        paths: [{prefix: /v1/}]
        methods: [POST]
```

- 目标在 `match.hosts/paths/methods/ports` 中；观察行为由规则的 `audit` qualifier 控制。
- 优化期间 `egress.defaultAction` 必须保持不变（guard 强制）。
