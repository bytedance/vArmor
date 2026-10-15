# 运行时违规日志与证据边界

## 来源与版本

官方 agent 的 AppArmor/BPF/Seccomp 统一事件通常写入宿主机 `/var/log/varmor/violations.log`，
经已有 agent 的 hostPath 可见；实际容器路径需结合 volumes/volumeMounts 确认。官方实现使用
lumberjack 轮转（单文件 10MB、3 个备份），常见备份名为 `violations-<timestamp>.log`，
也可能看到压缩文件或旧式命名；实际版本与日志配置优先。agent stdout 主要用于组件运行错误，
不能默认它包含完整违规事件。APM 用于 BehaviorModeling，不是普通审计存储。

NetworkProxy 的统一 agent 日志 ALS 链路从 v0.10.3 提供；runc 部署通常走节点日志。
micro-VM 的 v0.10.4+ 部署可由代理 sidecar 内置 sink 写容器日志，早期版本和自定义部署需
确认来源。只读诊断可分析现有片段，但日志可能因轮转、Pod 重建或版本差异缺失，不能因未找到
事件就排除该 enforcer。不要求达到策略自动优化的全节点采集或删除资格门槛。

## 关联字段

外层常见字段包括 `eventTimestamp`（事件发生时间，epoch 秒）、`time`（采集时间）、
`nodeName`、`profileName`、`enforcer`、`action`、`podUID/podName/podNamespace`、
`containerID/containerName`、`pid/mntNsID` 与 enforcer 专属 `event`。
v0.10.3+ 可包含 `policyKind/policyName/policyNamespace`，更早版本可能只有 profileName。
字段缺失不补造；用现有身份、节点、Profile、时间和操作信息说明关联强度。

| action | 解释 |
|---|---|
| DENIED | 被拒绝并记录 |
| AUDIT | 观察放行并记录（AppArmor/BPF） |
| AUDIT\|ALLOWED | Seccomp 观察期组合值 |
| ALLOWED | 放行 |

AppArmor 按 operation 区分文件、capability、mount、ptrace、network 等语义，不能把 `name`
一律当作文件路径。BPF 的 operation 与对应事件字段一起判读。Seccomp 事件可能只有 syscall
而没有参数；NetworkProxy 的 dstAddress 是原始目标，SNI/authority/path 的可见性取决于层次
与 TLS 配置。完整规则语义见各 enforcer/内置规则参考。

## 结论强度

事件证明的拒绝动作与业务故障之间，还需时间、运行身份和具体操作的关联。短生命周期进程可能
缺少 Pod/container 字段；可由 containerID、节点、进程/命名空间信息与该时间的对象映射补强。
Pod 名重用时优先 UID；Profile 同时保护多个 Pod 时仅匹配 Profile 不能定位某个 Pod。

无匹配记录只表示所读片段未命中。说明查询时间、文件/轮转范围、身份筛选、无效行与未覆盖部分，
不要写成“没有拒绝”。聚合/路径归一可用于搜索，但判定业务原因时应核对必要的原始事件。
