# 策略模式与默认 Profile

本指南说明 vArmor v0.9.2 各策略模式在未额外添加规则时生成的默认 Profile 语义。它用于解释“策略没有内置/自定义规则，为什么仍有或没有防护”。实际结论仍须以 VP/VCP、AP、Pod 引用和节点已加载 Profile 为准。

## 1. AlwaysAllow

AlwaysAllow 是 vArmor 的无额外强制访问控制对照模式：AppArmor 使用 Allow 模板，BPF Profile 为空，Seccomp 默认动作为 `ALLOW`。它不关闭 Kubernetes、容器运行时、Linux 内核或其他独立安全机制，因此业务仍可能被其他机制拒绝。

## 2. RuntimeDefault

RuntimeDefault 为 AppArmor/BPF 生成 vArmor 的运行时默认基线：

- AppArmor：限制部分 `/proc` 写入、`/proc/sysrq-trigger`、`/proc/*/mem`、`/proc/kmem`、`/proc/kcore` 和敏感 `/sys` 路径，限制 mount，并限制跨 Profile 的 ptrace。
- BPF：限制 `/proc/sysrq-trigger`、`/proc/*/mem`、`/proc/kmem`、`/proc/kcore`、敏感 `/sys` 路径，限制卸载，并限制 ptrace read/trace。
- Seccomp：v0.9.2 在此模式生成 `ALLOW` Profile，以避免既有 Pod 因不能更新 Seccomp 设置而无法正常重启；不要把 RuntimeDefault 视为 vArmor 的 Seccomp syscall 拦截基线。

## 3. EnhanceProtect

EnhanceProtect 为 Allow-by-Default，并叠加用户选择的内置规则和自定义规则。未声明任何规则时：

- `privileged=false`：AppArmor/BPF 仍叠加第 2 节的 RuntimeDefault 基线。
- `privileged=true`：AppArmor/BPF 以 AlwaysAllow 模板/空 Profile 为基础，不叠加该基线。
- Seccomp：生成的 Profile 默认动作为 `ALLOW`；只有实际存在 Seccomp 内置或自定义 syscall 规则时才增加限制。

`allowViolations`、`auditViolations` 改变 EnhanceProtect 规则和基线的阻断/审计方式，但不改变 AppArmor/BPF 是否叠加基线。Seccomp 观察模式只有两者均为 true 时对命中的规则使用 `LOG`，其他组合通常使用 `ERRNO`。

## 4. BehaviorModeling

建模未完成时，AppArmor/BPF/Seccomp 处于 `Complain` 语义以采集行为；Seccomp 默认动作是 `LOG`，并保留基本文件 syscall 的显式允许。建模完成后，该模式自身回到 AlwaysAllow/空 Profile，不自动变成 Deny-by-Default。

其产物是 ArmorProfileModel（APM）。要获得 allowlist 防护，应确认 APM 已生成并被后续 DefenseInDepth 策略引用。

## 5. DefenseInDepth

DefenseInDepth 是 Deny-by-Default 模式，不存在通用固定基线。它使用行为模型或用户提供的 AppArmor/Seccomp Profile 作为 allowlist，再叠加对应自定义规则：

- AppArmor：加载 APM 或自定义 AppArmor Profile，并可追加 AppArmor Raw Rules。
- Seccomp：加载 APM 或自定义 Seccomp Profile；默认动作在阻断模式为 `ERRNO`，`allowViolations=true` 时为 `LOG`，并可追加 syscall Raw Rules。
- BPF：v0.9.2 尚不支持 DefenseInDepth。

BehaviorModeling 与 DefenseInDepth 在 v0.9.2 中属于实验能力，仅支持 AppArmor 与 Seccomp。诊断此模式时，应优先核对 APM/Profile 来源、模式完成状态和最终默认动作，不能套用 EnhanceProtect 的内置规则或 RuntimeDefault 基线解释。
