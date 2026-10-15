# Playbook 执行契约

本文件定义两个异步阶段共用的执行约定。阶段可在不同调用或会话中独立进入，也可在一次调用中
批量处理多个任务。详细领域知识见 `references/`。

## 1. 前置依赖

- 进入用户确认的集群预检、日志采集或变更步骤时，`kubectl` 可访问目标集群，并确认当前 context；
  仅介绍 Skill 或本地校验 YAML 时不运行 kubectl，不擅自切换 context。
- Python 3 + PyYAML（一次性安装：`pip3 install --user pyyaml`）。
- 脚本位于 `scripts/`；`monitor_violations.py run` 在已授权的 agent 范围只读访问集群，其他
  数据处理脚本从文件或 stdin 读取。所有 CRD 写操作仍由执行者按本契约完成。

## 2. 命令与产物原则

- 关键策略、逐节点日志、证据归约、归因决定、候选策略和 diff 必须落盘，供用户审核与后续复核。
  资源原始 dump、合并日志、过滤结果和退出码等可确定重建的表示不重复保留。用户确认后从已审核
  的同一策略文件下发，不临时拼接 YAML 或直接构造创建命令。
- 每个策略或任务使用独立运行目录；文件名前缀对应生成步骤，不能覆盖其他任务的策略和证据。
  任务记录位于持久任务目录，不属于阶段产物；它是可更新的状态索引，引用的快照、inventory 和
  各轮产物保持不可变。
- 根据命令结构选择 shell 保护。复杂管道或连续写入可使用 `set -euo pipefail`，敏感临时文件可
  使用 `umask 077`；也可以采用显式退出码检查、`&&`、受限目录或原子发布等同等可靠的方式。
  不为每条简单查询机械添加这些前缀，也不向用户逐项播报例行 shell 设置。无论采用哪种方式，
  命令失败都不能被后续 chmod 等成功命令掩盖。包含数组或 here-string 的采集块使用 Bash；
  简单命令不限定 shell。
- 新 shell 中从任务记录恢复 context、目录和固定窗口；审核过的哈希从确认记录恢复，不重新计算
  后当成原审核哈希。基线 RV 可从本地 current YAML 读取，不从实时集群重新赋值。
- 时间读取属于内部证据，不逐项向用户播报“当前时间已同步”。创建观察任务时确定固定窗口；
  增量采集由脚本记录实际读取起止和末次排空，不需模型逐轮取时。快照回退的阶段二触发时确认一次
  窗口已结束，整批节点采集只记录一次 `COLLECTION_STARTED_AT` 并复用。
  对话中只在商定窗口、窗口未到或时间证据异常时说明时间。

| 阶段 | 保留产物 |
|---|---|
| 一 | `1.1.3-draft.yaml`、`1.2.1-normalized.yaml`、`1.7-policy-snapshot.json`、`1.7-agent-inventory.json` |
| 二 | `2.1.1-current.yaml`、`2.1.2-agent-inventory.json`、`2.1.3-logs/*.log`、`2.1.4-pre.json`、`2.1.5-catalog.json`、`2.1.5-attribution.json`、`2.1.6-post-seccomp.yaml`、`2.1.6-candidate.yaml`、`2.1.6-guard-diff.json`、`2.1.6-analysis.md`、`2.1.8-post-replace.yaml` |

`2.1.6-seccomp-plan.json` 仅在存在 Seccomp 命中、保留或歧义决定时保留。
增量任务另保留 `collector.json`、`collector.sqlite`、`transfer-ledger.json` 和少量启动诊断；journal 是游标与原始记录的
事务存储，到期导出的节点日志供现有分析链使用。详见 [增量采集](../references/incremental-collection.md)。
任务记录建议放在 `<task-root>/varmor-policy-optimization/<cluster-context-safe>/`，并采用：

- VP：`vpol-<namespace>-<name>--<start>--<plannedEnd>.json`
- VCP：`vcpol-<name>--<start>--<plannedEnd>.json`

`<task-root>` 可由用户、工作区或执行环境决定；模型也可选择其他持久位置和等价命名，只需稳定
区分集群、策略与原计划窗口，并让后续入口能引用绝对路径。避免使用临时目录或某轮 `RUN_DIR`。
`<cluster-context-safe>` 可将 context 中文件名不安全的字符替换为 `_`。

文件名使用原计划窗口，后续提前结束不改名。任务记录始终保留，是跨会话恢复和所有触发方式的
统一入口；调度器、提醒和手动继续都只引用其绝对路径。状态按实际进展更新为 `observing`、
`collecting`（快照采集）、`collected`、`collection-failed`、`analyzing`（增量分析）、
`awaiting-decision`、`candidate-ready` 和 `completed`，未经过的状态无需补写。阶段二的领取由
monitor 的本地 claim/release 原子处理；中断遗留领取按增量参考中的授权 force-release 恢复，并留
analysisClaimHistory 审计记录，不由两个触发各自读改任务文件。进入 awaiting-decision 时移除
analysisClaim，后续状态的旧残留字段不参与领取判断。

- 集群发现与只读检查只在用户选择的预检项、已授权的观察期增量采集或阶段二快照采集中执行。模型根据现场输出选择
  kubectl 命令；示例命令是可靠起点，不要求在环境命名、label 或安装方式不同时机械照抄。
- 节点 agent 经 hostPath 直接写宿主机 `/var/log/varmor`。已有节点只读通道时可直接复制；
  否则默认经 agent hostPath 视图增量读取；快照回退一次性导出，不为此新建特权 Pod 或扩大节点权限。
- 只有策略包含 NetworkProxy 时才读取其版本/runtime 日志分支，详见
  [violation-log.md](../references/violation-log.md)；其他策略不加载这部分判断。
- 脚本仅用于复杂数据归约、确定性转换和写入边界校验。模型生成的 JSON/YAML 是可审核产物，不因
  文件格式、marker 或中间层数量而自动成为可信证据。
- 原始违规日志包含业务路径、进程、镜像和网络目标等敏感元数据。运行目录用
  `install -d -m 700 "$RUN_DIR"` 创建；每批文件落盘后及向用户展示前都执行
  `find "$RUN_DIR" -type d -exec chmod 700 {} +` 和
  `find "$RUN_DIR" -type f -exec chmod 600 {} +`。若选择使用 `umask`，只把它视为当前 shell 的
  附加保护，不替代显式权限收敛。不要把原始日志、完整 URL、HostPath 或资源 JSON 直接贴入
  对话或报告。
- **本地文件与对话展示分开**：本地保留实际将下发的完整 CRD YAML，供用户通过文件路径审核；
  对话只展示对象身份、策略哈希、规则摘要和结构化 diff。任何对话内 YAML/JSON 视图都必须移除
  `managedFields`、`status` 并遮蔽 Annotation 值；完整本地文件不得因此被改写或替换。
- 原始日志保留到本轮分析、用户审核和必要回滚完成为止。随后按用户或组织留存要求处理；未取得
  用户确认不主动删除。需要清理时只删除本轮运行目录，保留用户要求的脱敏报告和策略文件。
  例外仅限本轮临时复制目录：完整节点日志成功发布后，可清理其重复副本；失败时保留排障材料，
  不生成正式节点日志。

## 3. 变更边界（统一确认，不分风险层级）

本 skill 对违规日志、节点、业务资源都是**只读**。唯一会改变的是**当前 VP/VCP CRD**：

- 阶段一：下发一个新的 VP/VCP。
- 阶段二：更新现有 VP/VCP 的规则（可能因此触发工作负载滚动更新 / 重启）。

任何变更（含由此带来的工作负载重启）执行前必须满足：

1. 用确定性脚本完成校验，且结果有效。
2. `kubectl ... --dry-run=server` 通过。
3. 向用户提供**完整本地 CRD 文件路径 + 内容哈希**，并在对话中展示脱敏策略摘要与结构化 diff
   （删除来源、内容、enforcer、关联证据、未匹配与歧义事件）。
4. 用户明确确认**目标集群 + 变更内容**后才执行。

未经确认绝不 apply；不替用户删除/重建业务 Pod（target 为 Pod 或开关关闭时只提示需重建）。

阶段二在归因完成后先展示匹配、未匹配、歧义、隐式基线和放宽影响，并询问用户希望删除、保留
还是继续观察。删除范围确定后再生成 post-Seccomp、candidate 和 guard diff；候选生成后仍按
上述 1～4 执行最终确认。

## 4. 证据记录格式

每个关键结论都应能回溯，记录以下字段（在分析报告中体现）：

```text
target policy    kind / namespace / name（VCP 的 namespace 为空）
window           start / end（用户给的固定闭区间；记录原始时间戳）
rule identity    source + rule(+context.targets)
enforcer         事件实际 enforcer
evidence         事件字段与规则限制如何对应
match            确定关联（可多条）；unmatched；ambiguous
```

纪律：

- 时间窗以任务记录中的 `eventTimestamp` epoch 为准；首次正式采集前可按用户明确要求提前结束，
  保留 `plannedEnd` 并更新实际 `end`。快照采集开始后不再修改；运行中的增量任务通过 close 请求
  和采集器确认提前结束，最终归因开始后范围固定。不从日志内容反推范围。
- 只移除当前策略已存在的原子规则；不动模式/target/enforcer/控制开关。
- 证据不足保持 unmatched；不因频率、规则名相似或主观风险归因。
- 存在无效日志 / 日志不完整 / Seccomp 歧义时，按各 playbook 处理并显式告知，不静默删除。

## 5. 失败关闭

以下情况停止且不变更：依赖缺失、连接失败、策略不存在、策略非 EnhanceProtect、阶段二策略未
原子化或未显式开启观察开关、窗口起点早于快照、快照复制早于窗口终点、增量初始化晚于起点或末次
读取不完整、观察期间策略或 agent
拓扑漂移、起点/终点 agent NotReady 或缺失、预期采集节点集合不一致、日志或 retention 证据不完整、归因
不确定、schema 校验失败、diff 含非删除变更、dry-run 失败、线上 spec 与 candidate 不一致、用户未确认。NetworkProxy 证据
不合格时单独禁止该来源的规则删除。错误按
DEPENDENCY / CONNECT / NOT_FOUND / SCHEMA / VALIDATION / NOT_CONFIRMED 归类表达，不把查询失败
或空结果误读成"无此行为"。
