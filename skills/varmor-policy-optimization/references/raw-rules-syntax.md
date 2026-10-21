# Custom Rule (RawRules) Syntax

Custom rules use each enforcer's native structures directly, without built-in ID translation. The model must understand their field
hierarchy and format. Local scripts check only obvious structural types and optimization constraints; **they are not full CRD validators**. Actual field validity
is determined by `kubectl --dry-run=server` against the target cluster (the authoritative schema).

Note: RawRules place targets in different fields; **there is no universal `rules + targets` format**.

## 1. appArmorRawRules

An array of rule groups; `rules` contains AppArmor text (each rule usually ends with a comma), with optional `targets`:

```yaml
appArmorRawRules:
- rules: |
    audit deny /etc/shadow r,
    audit deny /root/.ssh/** rw,
  targets:
  - /bin/sh
```

- Qualifiers: `audit` logs; `deny` blocks; `audit deny` means log and deny, not audit-only.
- Permissions: `r`/`w`/`a`/`x`, etc. Globs: `*` does not cross `/`; `**` spans directory levels.
- `allowViolations` does not rewrite appArmorRawRules text.
- The target node AppArmor loader determines whether syntax is accepted.

## 2. bpfRawRules

A structured object with targets distributed across its fields.

### Files / processes

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

- `qualifiers`: `audit` only logs; including `deny` blocks.
- File permissions: `all`/`*`/`read`/`r`/`write`/`w`/`append`/`a`; process execution uses `exec`/`x`.
- Local scripts check only that bpfRawRules is an object; **deep pattern/qualifier constraints are not programmatically validated**.
  The model must inspect them and verify with server dry-run; do not mistake them for deterministically validated constraints.

### Network

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
        ports:
        - port: 443
          endPort: 450
      - qualifiers: [deny]
        cidr: 10.0.0.0/8
      toServices:
      - qualifiers: [audit, deny]
        namespace: payment
        name: payment-db
      toPods:
      - qualifiers: [audit, deny]
        namespace: obs
        podSelector:
          matchLabels: {app: gateway}
        ports:
        - port: 4317
```

- Targets are in `domains/types`, `ip/cidr`, `serviceSelector`, `podSelector`, and `ports`.
- `ip` and `cidr` are mutually exclusive within one destination rule. Use separate entries for distinct targets.
- Different branches/array elements are OR-ed; omitted ports match all ports for the target.
- `toServices`/`toPods` depend on ongoing control-plane resolution of objects and Endpoints.

### ptrace / mounts

```yaml
bpfRawRules:
  ptrace:
    qualifiers: [audit, deny]
    strictMode: false
    permissions: [trace, read]
  mounts:
  - qualifiers: [deny]
    sourcePattern: /etc/**
    fstype: ext4
    flags: [ro, bind]
```

- Ptrace permissions: `trace`/`traceby`/`read`/`readby`; `strictMode=false` provides a default exception for processes in the same container.
- Mounts match source patterns, fstypes, and flags; mount rules are generated only with `privileged=true`.

## 3. syscallRawRules (OCI LinuxSyscall)

```yaml
syscallRawRules:
- names: [fchmodat]
  action: SCMP_ACT_ERRNO
  args:
  - index: 2
    op: SCMP_CMP_MASKED_EQ
    value: 64
    valueTwo: 64
```

- `names` lists one or more syscalls sharing `action` and `args`.
- Argument indexes are zero-based and syscall-specific: mode is argument 2 for `fchmodat`, but argument 1 for `chmod`. Split rules when argument layouts differ.
- Actions other than `SCMP_ACT_ALLOW`/`SCMP_ACT_LOG` may block (ERRNO, KILL*, TRAP, TRACE, NOTIFY).
- Arguments are raw integers, without file-path or Kubernetes-object semantics. Prefer `SCMP_ACT_LOG` during observation.

## 4. networkProxyRawRules

Effective only when the enforcer includes `NetworkProxy`:

```yaml
networkProxyRawRules:
  egress:
    defaultAction: deny
    rules:
    - qualifiers: [audit]
      ip: 203.0.113.10
      ports: [{port: 443}]
    httpRules:
    - qualifiers: [audit]
      match:
        hosts: [api.example.com]
        paths: [{prefix: /v1/}]
        methods: [POST]
```

- L4 `rules` use `ip`/`cidr` and `ports`; HTTP rules use `match.hosts/paths/methods/ports`. For TLS passthrough, HTTP-rule host criteria match SNI, while paths/methods are ignored.
- `audit` selects logging, not permission: the audit-only examples above still require a matching allow rule under `defaultAction=deny`. It does not override an explicit deny or the default action.
- Keep `egress.defaultAction` unchanged during optimization (enforced by the guard).
