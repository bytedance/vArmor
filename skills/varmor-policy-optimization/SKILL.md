---
name: varmor-policy-optimization
license: Apache-2.0
description: Validate and optimize vArmor EnhanceProtect policies. Use for policy review, creation, observation, or convergence. Explain the workflow first when the user is exploring it. Not for DefenseInDepth.
---

# vArmor 增强策略自动优化

协助用户校验或创建观察模式 `EnhanceProtect` 策略，并根据违规日志逐步收敛到最贴近业务的策略。
只处理 EnhanceProtect；不处理 DefenseInDepth 的优化。

## 两个异步阶段

本 Skill 提供两个可独立进入的阶段，不要求在一次调用中线性完成：

| 阶段 | 能力 | 操作手册 |
|---|---|---|
| 一、建立观察任务 | 校验或组装策略，下发成功后为每个策略和窗口建立任务记录 | [playbooks/author-policy.md](playbooks/author-policy.md) |
| 二、收敛观察任务 | 从任务记录恢复范围，分析日志并汇报归因，经用户决定后生成候选并确认更新 | [playbooks/optimize-policy.md](playbooks/optimize-policy.md) |

一次调用可以处理多份策略或多个任务记录；每个任务的策略身份、窗口、证据、产物和确认独立。
首次介绍到这里即可询问用户想了解、建立观察任务还是收敛已有任务，进入阶段后再展开该阶段细节。

处理策略时优先使用用户提供的 YAML。用户准备下发时，可以建议检查 context 与 vArmor 状态、
已有策略、目标工作负载、Enforcer 能力和滚动影响，并让用户选择需要核验的项目；已知事实可记录
为 `user-provided`，不重复探测。预检用于发现兼容性与生效风险，不替用户选择 Enforcer、规则或
滚动开关。

命令、产物和失败关闭条件留到相应执行步骤说明。真正变更 CRD 前仍按统一确认完成 context、
脚本校验、server dry-run、diff、哈希和最终确认。

执行约定与变更边界统一见 [playbooks/README.md](playbooks/README.md)。建立观察任务时，建议根据
测试业务量和行为覆盖与用户商定观察周期；对可主动压测的测试业务，可先建议约两小时，再由智能体
结合违规速率、发布/定时任务和日志轮转情况调整，最终由用户确认。通常建议执行 3～5 个观察周期，
但以业务覆盖和违规收敛情况为准，不把次数作为硬门限。

策略生效并确认观察窗口后，为每个策略保存独立任务记录，即完成优化任务的建立。任务记录是后续
恢复入口，不是阶段中间产物；定时任务、提醒或用户手动触发都只需引用其路径。新任务默认在
观察期启动本地增量采集器，定期保存日志，到期自动过滤、归一化和聚合成 `pre.json`，不需模型
逐轮取日志。采集器不调用模型；后续触发再完成语义归因。先把归因情况交给用户，再根据用户决定生成候选策略，最终更新 CRD 还需
再次确认。每次优化依赖
**固定时间戳闭区间 + 起点策略快照 + 当前策略**；快照是本地可审核 JSON，不依赖隐藏状态。

vArmor 将违规事件以 JSON 行写入 `/var/log/varmor/violations.log`。当前官方实现使用 lumberjack，
单文件上限 10MB、保留 3 个备份。agent 经 hostPath 直接写宿主文件；只有策略启用
NetworkProxy 时，才按版本和 runtime 检查额外日志分支。详细边界见
[references/violation-log.md](references/violation-log.md)。
启动、资源限制和连续性证据见 [references/incremental-collection.md](references/incremental-collection.md)。

## 产物、命令与两层职责

- **阶段一区分两个步骤**：仅在用户明确要求创建策略后，填写（组装）才允许模型按**用户确认的
  信息**组装 CRD；校验阶段模型**不得擅自修复**，只能由脚本做固定规范化或回到用户确认。
- **保留最小可审核产物**：策略草稿/规范化策略/快照、逐节点日志、`pre.json`、归因与用户决定、
  candidate、guard diff 和分析报告落盘。同一证据不重复保存为资源 dump、merged log、过滤结果
  或退出码文件。用户确认后从已审核的同一策略文件下发。
- **下发前预检是建议模块**：在最终确认策略前，向用户列出 context/vArmor 状态、已有策略与
  Profile、目标工作负载、Enforcer/agent 能力和滚动影响等可选检查；只执行用户确认的项目。
  用户只想了解流程或本地检查策略时，保持在当前任务范围内。
- **确定性层（scripts/）**：结构类型校验、内置规则表、enforcer 兼容、规则原子化、Seccomp
  计划、删除落地、仅删除 diff。脚本只承担可精确判断、会影响最终变更的问题，不用模型生成的
  多层“证明文件”模拟可信执行器。本地脚本不是完整 CRD Schema，`--dry-run=server` 才是
  Schema 权威。
- `disable-cap-all`、`disable-cap-all-except-net-bind-service` 与 `disable-cap-privileged`
  允许出现在草稿中，但必须由 `validate_policy.py` 展开；展开后的 normalized YAML 才进入审核
  和下发，模型不手工展开。
- **模型层**：理解用户提供的策略与 RawRules，以及把聚合事件**确定归因**到当前原子规则。
  除用户明确进入的阶段一组装步骤外，模型不补全、不改写或直接下发 YAML。

| 脚本 | 作用 |
|---|---|
| scripts/validate_policy.py | 校验 + 规范化（观察开关、聚合能力规则原子化）；stdout 为纯 YAML |
| scripts/monitor_violations.py | 只读增量采集、字节预算、到期确认读和既有预处理；run/status/close；claim/release 与授权 force-release |
| scripts/collect_violations.py | 时间窗 + profileName/可选 policy identity 过滤；由 preprocess 复用 |
| scripts/preprocess_aggregate.py | 从多节点日志一步生成 manifest、过滤计数、聚合与来源资格；`catalog` 生成规则目录 |
| scripts/build_agent_inventory.py | 从文件或混合 Kubernetes List stdin 重建 agent 调度与 Ready 完整性 |
| scripts/seccomp_plan.py | syscall→完整规则原子的计划；每个内置规则/自定义 syscall 组须显式 remove/keep |
| scripts/finalize_node_log.py | 全部传输成功后，本地校验/解压并原子发布一份节点日志 |
| scripts/validate_attribution.py | 归因边界校验：eventId/精确 catalog/enforcer；不替代模型的语义判断 |
| scripts/build_manifest.py | preprocess 内部复用：校验窗口、起止 inventory、节点并集与 retention |
| scripts/apply_removals.py | 从 attribution 决策派生坐标，重建 catalog 并确定性移除规则 |
| scripts/guard_removal.py | 重算 candidate 删除 diff，并校验 replace 后的线上 spec |
| scripts/hash_policy.py | 策略指纹及观察起点快照，检测 YAML 修改、对象重建和观察期间 spec 漂移 |

按当前阶段和实际输入调用脚本，不为凑齐固定流水线而运行无关步骤。阶段一通常只需要策略校验与
指纹绑定；阶段二才需要日志处理和删除门禁。

规则合法集合与兼容元数据由 scripts/data/builtin-rules-catalog.json 维护。
`catalogProvenance` 只表示取材来源，不是精确版本门限。官方 `v0.10.1`～`v0.10.5`
的内置规则实现已验证一致，比对日期、路径与 SHA-256 记录在 catalog 的
`builtInRuleCompatibility.verificationEvidence`；`v0.10.0` 仅缺少 `copy-fail-mitigation`。
其他/未知版本只对策略实际使用的内置规则标记兼容性未知，不把整份策略笼统判为不兼容。
NetworkProxy 使用独立的功能与日志版本门控，见
[references/violation-log.md](references/violation-log.md)。

## 变更边界（统一确认）

- 违规日志、节点、业务资源只读；唯一变更对象是 **VP/VCP CRD**（及确认后随之发生的工作负载
  滚动/重启）。
- 任何下发 / 更新前：脚本校验有效 → RawRules 检查通过 → 明确展示可选预检状态及证据来源 →
  `--dry-run=server` 通过 → 提供完整本地 YAML 路径与哈希，并在对话展示脱敏摘要 + 结构化
  diff → 用户明确确认**目标集群与变更**。未确认不执行；不替用户删除/重建业务 Pod。新建用
  `kubectl create` 防覆盖，已存在同名对象则停下走阶段二。
- **观察语义**：进入观察模式的是内置规则与基线（只记录不拦截）；**自定义 RawRules 动作保持原
  语义**，deny / 阻断型 Seccomp action / NetworkProxy defaultAction=deny 仍会真实拦截，需
  单独向用户确认。
- 失败关闭：依赖/连接问题、策略不存在、非 EnhanceProtect、日志不完整、归因不确定、schema
  失败、diff 含非删除变更、用户未确认时，一律不变更。

## 按需读取的参考（不默认全量加载）

- [references/optimization-loop.md](references/optimization-loop.md)：收敛回路与证据边界
- [references/enhance-protect-semantics.md](references/enhance-protect-semantics.md)：规则类别、观察模式、隐式基线
- [references/builtin-rules-semantics.md](references/builtin-rules-semantics.md)：每条内置规则的用途与误伤风险（检查用户已有规则时必读，不凭名字猜）
- [references/raw-rules-syntax.md](references/raw-rules-syntax.md)：四类 RawRules 结构
- [references/violation-log.md](references/violation-log.md)：violations.log 位置/轮转/Envelope/event
- [references/policy-crd-lifecycle.md](references/policy-crd-lifecycle.md)：可变性与 Kubernetes 生效边界
- [vArmor 官方文档索引](https://www.varmor.org/zh-cn/llms.txt)：仅当本地 references 无法解释
  额外背景知识时按需查阅；该索引随官方文档更新。官方文档用于补充背景，不能替代当前集群事实、
  server dry-run 或本 skill 的确定性门禁。

产物模板：[templates/optimization-analysis.md](templates/optimization-analysis.md)、
[templates/attribution.json](templates/attribution.json)、
[templates/observation-task.json](templates/observation-task.json)。

## 关键证据纪律

- 时间窗以任务记录中的 `eventTimestamp` epoch 闭区间为准。首次正式采集前，用户可以明确提前
  结束观察；更新任务中的实际 `end` 并保留原计划时间后，该窗口再固定，不从日志反推范围。
  运行中的增量任务通过 close 请求和采集器确认提前结束，开始最终归因后不再修改窗口。
- 默认增量采集必须在 start 前完成初始化、end 后完成末次读取，文件游标与日志事务提交；
  每节点间隔一个扫描周期做两次排空确认读，无法恢复的缺口阻断删除。短暂读取问题只在检查点
  连续并追平后恢复资格；采集器中断恢复同样逐节点验证中断前检查点，不能用新游标补证。
  身份/拓扑变化、无法恢复的中断仍阻断。旧任务的快照回退仍要求每节点复制在 `window.end` 后开始。
  `pre.json.collectionManifest` 区分两种模式，不用预处理时间代替读取时间，并要求 agent inventory 连续。
- 阶段二必须拒绝未展开的 capability 聚合规则和非观察模式开关；起点快照缺失、
  `start < capturedAt` 或 UID/generation/spec 哈希不一致时只允许只读分析，不允许生成或下发
  删除候选。
- agent 完整性以 DaemonSet 的 desired 调度数和全部 owned Pod 为准；起止 inventory 的 NotReady、
  terminating、未调度、缺失或未采集均阻断删除。增量窗内同 UID 的短暂 NotReady 仅在 Ready
  恢复且文件检查点连续、游标追平后解除疑点；真实身份/拓扑变化仍阻断。
  节点扩缩容或 DaemonSet desired/current 数变化会阻断整策略删除，协商窗口时说明这一后果。
- 仅当策略包含 NetworkProxy 时检查其日志版本/runtime 分支；`<v0.10.3`、版本未知或 micro-VM
  均令 `networkProxyEvidenceEligible=false`；归因、删除器和最终 guard 都拒绝 NetworkProxy 删除。
- 只能删除当前策略已存在的原子规则；不动 mode/target/enforcer/privileged/audit/allow/
  defaultAction。
- 归因基于“实际原子规则 + 实际 enforcer + 充分事件字段”；不凭名字相似、频率或主观风险；
  证据不足保持未匹配。
- 归因完成后先展示完整汇总，询问用户“删除/保留/继续观察”，再把决定写回 attribution；删除
  坐标只由脚本派生，不另存 removals。删除范围确定后再运行 Seccomp apply、生成 candidate 和
  guard diff。分析报告必须按模板落盘并与 candidate 一起审核。
- `privileged=false` 时存在无法靠删规则消除的隐式基线，需单列给用户做结构性决策。
- 下发/更新后检查实际加载结果；AppArmor/BPF 与 Seccomp 的生效方式不同，Seccomp/注入变化
  需新容器，不能假定更新规则会自动滚动工作负载。
- 定时、提醒和手动触发都先读取同一任务记录；自动触发可采集与归因，归因汇报后由用户选择删除
  范围，候选生成后仍须最终确认才能更新 CRD。
- 原始日志与派生产物放入本轮目录；不依赖跨 shell 的 `umask`，每批落盘后显式收敛目录 `0700`、
  文件 `0600`。报告只保留最小必要证据并脱敏，不输出 Secret、Annotation 值、HostPath 物理
  路径或完整资源 JSON。

## 环境依赖

- kubectl 已登录目标集群；Python 3 与 PyYAML（一次性：`pip3 install --user pyyaml`）。
- `monitor_violations.py run` 是脚本直接读集群的**唯一例外**：持续采集需要本地进程独立维护
  游标、截止时间和字节预算，不能依赖模型逐轮调用。它只按明确 context 和 agent 范围只读访问。
  其余脚本继续从文件或 stdin 读写，使确定性变换和集群操作解耦；策略写操作仍由执行者按
  playbook 完成。增量采集需可持续运行的本地进程。
