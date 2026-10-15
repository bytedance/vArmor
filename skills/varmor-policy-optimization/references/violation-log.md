# 违规日志 violations.log

## 1. 位置与轮转

- AppArmor、BPF、Seccomp 的节点日志位于宿主机
  **`/var/log/varmor/violations.log`**。官方 agent 将宿主机 `/var/log` 以 hostPath 挂到容器
  同路径，因此经 agent 读取的是同一底层文件，不存在“先写容器层再同步到宿主机”。
- 已有授权的节点只读传输通道时可直接复制宿主文件；否则默认经 agent hostPath 视图使用
  `kubectl cp/exec`。不要为此新建特权调试 Pod 或扩大节点权限。
- 轮转为单文件 10MB、保留 3 份备份（lumberjack）。默认备份名为
  `violations-<timestamp>.log`；采集也兼容 `.log.gz` 和旧式 `violations.log.*`。
- 新任务在观察期由 [增量采集器](incremental-collection.md) 定期读新增字节，及时保留轮转前的数据，
  到期自动生成预处理结果。旧任务快照回退在分析前一次性导出活动文件和备份。两种路径均不把
  完整日志输出到模型上下文。

### 按需判断 NetworkProxy

**仅当当前策略 enforcer 包含 NetworkProxy 时执行本段，否则跳过：**

1. NetworkProxy 从 `v0.10.0` 提供；统一写入 agent `violations.log` 的 ALS 链路从 `v0.10.3`
   提供。版本低于 `v0.10.3` 或未知时，不基于该日志自动优化 NetworkProxy。
2. `v0.10.3+` 且为 runc：事件写入上述宿主机日志，走普通 agent 采集。
3. micro-VM：`v0.10.4+` 改由 `varmor-network-proxy` sidecar 内置 sink 写容器层日志；更早版本
   没有该采集路径。当前流程均不具备跨 Pod/容器生命周期的完整证据，只允许只读分析，不删除
   NetworkProxy 规则。

## 2. Envelope（外层字段）

每条日志可能包含：

```text
level            日志级别
time             采集时间
eventTimestamp   事件发生时间（epoch 秒，时间窗以此为准）
nodeName         节点名
podUID / podName / podNamespace   Pod 身份
containerID / containerName / image   容器身份
pid / mntNsID    进程 / mount namespace
enforcer         AppArmor | BPF | Seccomp | NetworkProxy
action           最终处置（见下）
profileName      产生事件的 Profile
policyKind / policyName / policyNamespace   归属策略身份
event            enforcer 专属事件对象
```

### 策略身份

`v0.10.1/v0.10.2` 的常见 Envelope 只有 `profileName`；`v0.10.3+` 增加
`policyKind/policyName/policyNamespace`。过滤时始终精确匹配当前策略的 `status.profileName`，
存在 policy identity 时再做附加校验。`collect_violations.py --explain` 会分别统计
`profileMismatch`、`policyIdentityMismatch` 和 `missingIdentity`，避免把零匹配误判为无违规。

## 3. action 词汇

| action | 含义 |
|---|---|
| `DENIED` | 被阻断并记录 |
| `AUDIT` | 观察期放行并记录（AppArmor/BPF） |
| `AUDIT\|ALLOWED` | Seccomp 观察期组合值 |
| `ALLOWED` | 放行（如 DefenseInDepth allowViolations） |

## 4. event：各 enforcer 专属结构

### AppArmor（大而全，按 operation 区分领域）

关键字段：`operation`、`profile`、`name`/`name2`（路径）、`deniedMask`/`requestedMask`、
`fsuid`/`ouid`、`comm`、`capability`（`operation=capable` 时的 `name`），以及 mount
（`srcName`/`fsType`/`flags`）、ptrace（`peer`/`peerProfile`）、network
（`netFamily`/`netSockType`/`netProtocol`/`netForeignAddr`/`netForeignPort`）、dbus、signal 等。

判读要点：

- 文件事件里 `name` 是路径；`operation=capable` 时 `name` 才是 capability，二者不能互推。
- 目录聚合时会保留 `accesses`/`requestedMasks`/`deniedMasks` 的组合关系。

### BPF（已类型转换，六类逻辑事件）

`operation` 取值即事件类型：`Capability`、`File`、`Bprm`、`Network`、`Ptrace`、`Mount`。

- Capability：`capability`；File：`path` + `permissions`；Bprm：`path`（执行）。
- Network：`type=socket`（`socket.domain/type/protocol`）或 `type=connect`
  （`address.ip/port`）；Ptrace：`external` + `permission`；Mount：`path`/`type`/`flags`。

### Seccomp

只保留 `syscall`（另有 auditID/epoch/subj/pid/comm/exe 等审计字段）。事件不含 syscall 参数。
Seccomp 原始日志不进入模型，由确定性脚本处理。

### NetworkProxy（来自 Envoy ALS）

字段：`layer`（L4/L7）、`dstAddress`、`sni`、`authority`、`method`、`path`，以及聚合时会剔除
的 `filterChain`/`responseCode`/`reason`/`durationMs`。

- `dstAddress` 是 Original Destination 恢复后的真实目标 `IP:port`，不是固定代理监听地址。
- L4 是 TCP 连接，L7 是 HTTP 请求；未启用 TLS MITM 时，HTTPS 的 path/method 不可见。
- `sni` 与 `authority` 相互独立（后者是 HTTP Host），差异可用于识别域前置。

## 5. 预处理约定

- 剔除时间/PID/审计序号/耗时等不影响规则判断的波动字段，保留 enforcer、操作、路径、权限、
  网络目标、syscall、capability。
- 无效日志必须计数：存在无效日志时，分析结果不具备自动删除资格，不能静默跳过。
- 动态路径做确定性归一（`:pid`/`:pod-uid`/`:sa-rev`/`:snapshot`/`:range`）。这些占位符只是
  聚合记号，**不是 AppArmor/BPF 通配符，绝不能写回策略规则**。

## 6. 数据处置

- 原始日志和派生产物存入本轮专用目录；每批落盘后显式收敛为目录 `0700`、文件 `0600`，不依赖
  跨 shell 持久的 `umask`。
- 日志可能包含业务文件路径、进程、镜像、网络 IP/端口、HTTP authority/path 等敏感元数据；
  报告只引用支持结论所需的最小字段，并对业务标识脱敏。
- 不额外读取 Secret 内容或 Annotation 具体值；报告不得输出 HostPath 物理路径或完整资源 JSON。
- 本轮审核和回滚需求结束后，按用户或组织策略清理原始日志；未获确认不主动删除。
