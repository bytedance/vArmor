# EnhanceProtect 语义：规则类别、观察模式与隐式基线

本文件只描述稳定的模式语义。内置规则的合法集合、enforcer 兼容矩阵和聚合能力规则的展开由
`scripts/data/builtin-rules-catalog.json` 维护，不在此重复。

## 1. EnhanceProtect 的规则来源

EnhanceProtect 是 Allow-by-Default：在基础 Profile 上叠加规则。规则来源分两类。

### 1.1 内置规则（用规则名引用）

| 字段 | 结构 | 说明 |
|---|---|---|
| `hardeningRules` | `[]string` | 加固类：逃逸路径、能力管理、挂载/内核接口限制 |
| `vulMitigationRules` | `[]string` | 漏洞缓解类：针对特定漏洞的利用链阻断 |
| `attackProtectionRules` | `[]{rules, targets}` | 攻击防护类；同组规则共享可选 `targets` |

`attackProtectionRules.targets` 只对 **AppArmor** 有效，用于把规则限定到指定可执行文件及其子
进程，通过 AppArmor 子 Profile 实现。它**不产生等价的 BPF 按进程约束**。

`hardeningRules` 和 `vulMitigationRules` 没有规则级 `targets`，归因时不得人为补充。

### 1.2 自定义规则（RawRules，见 raw-rules-syntax.md）

`appArmorRawRules`、`bpfRawRules`、`syscallRawRules`、`networkProxyRawRules`。

## 2. 观察模式

观察模式由两个顶层开关控制：

```yaml
enhanceProtect:
  auditViolations: true
  allowViolations: true
```

| allowViolations | auditViolations | 行为 | action |
|---|---|---|---|
| false | false | 阻断，不主动记录 | 无事件 |
| false | true | 阻断并记录 | `DENIED` |
| true | true | 放行并记录 | `AUDIT` |
| true | false | 放行，不记录 | 无事件 |

观察期目标配置是 `auditViolations=true` + `allowViolations=true`（违规只记录、不拦截）。
校验脚本会自动补全这两个开关，并把该规范化作为 adjustment 明确告知，不会静默修改。

### Seccomp 的特殊性

- 内置 Seccomp 规则在观察模式生成 `SCMP_ACT_LOG`（只记录）。
- 但 **`syscallRawRules` 的 action 由用户指定**：除 `SCMP_ACT_ALLOW/LOG` 外（如 ERRNO、KILL*、TRAP、TRACE、NOTIFY），观察期均可能真实拦截。脚本只作风险 notice，不代为改写。
- Seccomp 事件只携带 syscall，不含参数，无法区分如 chmod 设置的是执行位还是 SUID/SGID 位。

## 3. 隐式基线（重要盲区）

当 `privileged=false`（默认）时，EnhanceProtect **始终隐式叠加 RuntimeDefault 基线**：

- 基线不在策略字段里，因此**无法通过删除规则来消除**，guard 也不允许动它。
- 若某事件归因到基线、但不匹配任何策略原子规则，应在分析中单列为"基线来源（删规则无效）"，
  由用户做结构性决策（接受该限制 / 改 `privileged=true`）。
- `privileged=true` 时：基础模板改为 AlwaysAllow（移除基线），且 **vArmor 不为目标生成 Seccomp
  Profile**。这两个影响同时发生，需要明确告知用户，不能只提其一。

规则归属与实际生效 enforcer 必须以生成逻辑为准：例如 `disallow-create-user-ns` 虽出现在加固
清单，但 AppArmor/BPF 分支不生成规则，实际由 Seccomp 过滤 `unshare(CLONE_NEWUSER)`。
