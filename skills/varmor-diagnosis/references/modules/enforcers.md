# Enforcer 能力与故障判读

跨 enforcer 的匹配链、VP/VCP 重叠、规则冲突和统一结论分类见 `troubleshooting/enforcer-conflicts.md`。EnhanceProtect 内置规则的实际实施范围按 Enforcer 分别见 `modules/built-in-rules-apparmor.md`、`modules/built-in-rules-bpf.md`、`modules/built-in-rules-seccomp.md`；各策略模式的默认 Profile 见 `modules/policy-mode-profiles.md`。本文件侧重各 enforcer 的能力边界与执行信号；诊断时先确认实际 Pod 使用的 enforcer，再用对应章节解释事件。

## 1. 能力边界

| Enforcer | 主要控制层 | 典型对象 | 关键前提 | 常见运行时信号 |
|---|---|---|---|---|
| AppArmor | Linux LSM | 文件、执行、能力、部分网络/挂载/ptrace | AppArmor LSM、Profile 语法和加载能力 | `EACCES`、`Permission denied`、AppArmor audit/DENIED |
| BPF | BPF LSM/相关内核 hook | 文件、进程、能力、网络、挂载等细粒度规则 | 内核 BPF/BTF/BPF LSM、架构和资源 | `EPERM`、BPF audit、load/attach/map 错误 |
| Seccomp | syscall filter | 系统调用及参数 | Kubernetes/runtime Seccomp 支持、Profile 文件可见 | `SIGSYS`、`Bad system call`、`EPERM` |
| NetworkProxy | Pod 内 Envoy sidecar | L4 TCP、SNI/域名、L7 HTTP/HTTPS、TLS MITM | Webhook 注入、Secret/证书、流量重定向、sidecar Ready | 连接拒绝、TLS 错误、HTTP 规则未命中、Proxy audit |

它们可以组合，但执行顺序和相互作用重要：BPF 内核级网络规则可能先于 NetworkProxy；NetworkProxy 只处理已重定向到 sidecar 的流量；NetworkProxy 不能替代 CNI NetworkPolicy。

## 2. Profile 落地链

- AppArmor：agent 将 Profile 载入节点内核；Kubernetes 版本较新时可能通过 SecurityContext 的 `appArmorProfile`，较老版本可能使用兼容 annotation。
- BPF：agent 将 Profile/程序装载并挂到相应 hook；Pod 侧通常能看到 vArmor BPF Profile 引用 annotation。
- Seccomp：agent 将 JSON Profile 放在 kubelet/runtime 可读位置，Pod 通过 `seccompProfile` 引用；已运行容器不会因文件更新自动重新加载。
- NetworkProxy：Webhook 注入 Profile 引用、initContainer、Envoy sidecar、配置/证书 volumes 和必要的 CA 环境；initContainer 负责重定向，sidecar 负责策略执行。

诊断必须同时比较：策略期望、Pod 实际引用、节点实际 Profile、运行时处置。

## 3. 模式与审计

EnhanceProtect 内置规则中，`allowViolations` 与 `auditViolations` 是正交开关：

- `false/false`：通常阻断但不产生日志；
- `false/true`：阻断并记录 `DENIED`（AppArmor/BPF）；
- `true/true`：放行并记录 `AUDIT`；
- `true/false`：放行且不记录。

Seccomp 有特殊限制：观察模式通常需要两个字段同时为 true，事件通常表现为 `AUDIT|ALLOWED`；不能照搬 AppArmor/BPF 的 `DENIED` 语义。

DefenseInDepth 的 allowlist 违规通常默认阻断并记录 `DENIED`；允许违规时记录 `ALLOWED`。NetworkProxy 自定义规则由 qualifier 与 `defaultAction` 决定，不应套用 `allowViolations`。

审计事件通常包含 `enforcer`、`action`、`profileName`、时间以及 `event`。关联时优先用 Pod UID、节点、Profile、namespace/name 和时间窗口；短进程可能缺少完整容器归属，NetworkProxy 通常只有 Pod 级身份。

## 4. AppArmor

重点核对：节点是否启用 AppArmor LSM；Profile 是否存在且语法有效；agent 是否报告加载失败；Kubernetes 版本对应的引用方式；Pod 是否被显式 `Unconfined`；Profile 名称是否和策略 status/AP 一致。

常见根因：Profile 语法或自定义规则错误、节点 LSM 未启用、securityfs/相关挂载不可用、加载器版本不兼容、Profile 冲突或 Pod 引用旧 Profile。

## 5. Seccomp

重点核对：容器最终 `seccompProfile` 类型和 localhostProfile；节点文件是否位于 kubelet 实际读取范围；runtime 是否支持；进程退出是否为 SIGSYS；策略更新后目标 Workload 是否重建。

`EPERM` 不是 Seccomp 专属，必须结合 syscall、审计事件和 Profile。`SIGSYS/Bad system call` 更有指向性，但仍需核对是否为其他 syscall sandbox。

## 6. BPF

重点核对：内核版本/架构、BPF LSM、BTF、BPF filesystem 与 map/program 资源、agent load/attach 结果、每节点容器数量和规则规模。

若节点反复 NotReady、发生 kernel BUG/Oops/Call Trace，且时间与 BPF Profile 加载一致，应优先按节点内核/驱动风险处理，不要只把它当作业务容器 CrashLoop。不同版本的 BPF 支持和已知内核问题可能变化；历史固定阈值只可作为线索，不能跨版本直接下结论。

## 7. NetworkProxy

分层判断：

1. **注入层**：Pod 是否有 proxy annotation、initContainer、sidecar、volumes；
2. **启动层**：initContainer 是否完成、sidecar readiness、配置 Secret/证书是否存在；
3. **转发层**：流量是否被重定向到 proxy，ProxyUID/端口是否冲突；
4. **规则层**：L4 IP/CIDR/端口、SNI/host、L7 path/method 和 `defaultAction`；
5. **HTTPS 层**：未配置 TLS MITM 时，HTTPS 的 path/method 规则不会生效，通常只有 SNI/host 可判断；
6. **绕过层**：NET_ADMIN、ProxyUID、proxyAdminPort、Pod CIDR 管理端口和其他网络隔离是否允许绕过。

不要假设 deny 跨层次优先于 allow；依据实际版本支持的 qualifier、规则优先级、匹配层次和 `defaultAction` 判断最终处置。NetworkProxy 事件由 sidecar 产生，通常不能仅靠事件定位到具体 container。

## 8. 建议方向（仅建议）

先确认实际 enforcer 和最终 Pod 配置，再决定是调整规则、修复节点能力还是处理业务兼容性。观察模式、AlwaysAllow、重建 Workload、切换 enforcer 或升级内核都应说明安全影响和验证条件，不直接执行。
