# 观察期增量采集

新建观察任务默认使用 `scripts/monitor_violations.py`。模型只发现一次 agent 范围、确认日志
挂载和现有只读授权、启动采集器并检查就绪；循环取日志和到期预处理交给本地进程。
本轮只改采集，不改变归因、删除决定、candidate 或 CRD 更新流程。

## 输入与启动

输入仍是现有任务记录：context、策略身份、固定闭区间、起点策略快照和起点 agent inventory。
先核对 agent namespace、DaemonSet、容器及日志目录；范围需与起点 inventory 一致。采集器
只对该范围做策略 GET、agent DaemonSet/Pod LIST、Pod 身份 GET 和既有 agent 中的只读 exec，
不创建资源、不写远端文件。已有授权覆盖这些动作时不用重复询问。

与用户协商窗口时，为初始化保留时间，将 `start` 安排在采集器完成首轮读取之后。
在 start 前初始化时，只对既有完整行建立 EOF 游标，避免下载整份旧历史；未完成的尾行仍保留
重读起点。初始化后出现的新文件从头读取。事件窗口过滤仍依赖实际节点的 eventTimestamp，
不能用本地读取时间修正节点时钟或补造事件时间。
不得因启动慢而擅自延后/缩短原窗口。新启动已经到 start 时，在任何集群读取前拒绝。
所有节点的 EOF 基线必须在 start 前完成；串行初始化跨过 start 或尚有未完成尾行时立即停止，
不把后续节点切成全量历史下载。保留已初始化的材料，需要完整证据时重新商定下一窗口或快照回退。
空日志可以通过在 start 前建立文件游标、
持续扫描、end 后完成末次读取证明覆盖，不再要求伪造一条早于 start 的违规事件。

使用执行环境提供的持久后台进程能力；没有时可用以下 Unix 示例。脚本和任务路径都用绝对路径，
示例变量由模型发现并填好，不要求用户学习 CLI。原始日志不输出到终端；startup.log 仅保留启动
错误，状态与缺口写入 collector.json：

```bash
install -d -m 700 "$RUN_DIR" || exit 1
(umask 077
 nohup python3 "$SKILL_DIR/scripts/monitor_violations.py" run \
   --task "$TASK_FILE" --output "$RUN_DIR" \
   --agent-namespace "$AGENT_NS" --daemonset "$AGENT_DS" \
   --container "$AGENT_CONTAINER" --log-directory "$AGENT_LOG_DIR" \
   --interval 30 --max-read-mb 4 --max-local-mb 512 --max-transfer-mb-per-minute 16 \
   --request-timeout 30 --final-read-seconds 60 \
   --network-proxy-evidence <not-applicable|eligible|ineligible> \
   --authorized-agent-read \
   > "$RUN_DIR/collector-startup.log" 2>&1 &)
```

仅对原已确认的空 selector 策略追加 `--allow-empty-selector`。
NetworkProxy 仍按 [violation-log.md](violation-log.md) 判断来源资格，不扩大到 micro-VM sidecar。
远端需要 `sh/stat -L -c/tail/head`，有 gzip 备份时还需 `gzip/wc`；枚举和读取都拒绝日志文件
符号链接，不将其当成空文件跳过。日志目录及其挂载路径仍以发现阶段核对的可信目录为前提。
工具不可用时失败并保留证据，
不自动安装或改为全量无限读取。镜像中工具支持情况可先用小范围只读检查。

日志目录必须存在、可读且可遍历；目录内日志文件尚未创建允许作为空状态。vArmor v0.10.5
[auditor 初始化](https://github.com/bytedance/vArmor/blob/v0.10.5/internal/auditor/auditor.go#L175-L183)
创建目录和 logger，并未预创建 violations.log；
[lumberjack](https://github.com/natefinch/lumberjack/blob/v2.2.1/lumberjack.go#L44-L51)
在首次 Write 时创建日志。不存在的目录、无权枚举和不完整传输不能当成空日志；之前见过的活动
文件身份消失且未在保留备份中找到，仍记为缺口。

启动后读取一次本地状态：

```bash
python3 "$SKILL_DIR/scripts/monitor_violations.py" status --output "$RUN_DIR"
```

`readyForWindow=true` 同时检查运行阶段、进程、目录租约、近期 heartbeat 和窗口尚未结束。
还需检查每个节点 `coveredFrom < start`，才能告知本轮采集具备完整起点。初始化中的进程不能
当作已就绪。用户随后运行业务；不把日志正文贴入上下文。用户返回时再检查当前状态，不用旧
ready/heartbeat 推断进程仍存活。本地进程能否跨会话、休眠和工具退出存活取决于宿主环境。

## 周期与到期动作

- 默认每 30 秒枚举日志并读取增量；有 backlog 时最多缩短到 5 秒。每轮轮换节点起点，避免
  高流量节点长期独占预算。只读已有文件，保留轮转前已保存的内容。
- 每轮新增日志处理默认最多 4 MiB，由本任务的全部集群节点共享，跨节点递减、下一轮才重置；
  节点越多，单节点可获得的份额可能越小，不承诺平均分配。另有全部节点共享的持久化
  **16 MiB/滚动 60 秒 audit exec stdout** 预算，
  包含清单、指纹、协议头、重读和失败传输的保守预留。进程重启不清空账本；额度不足等待，
  不放宽限额。Pod/策略 API 和 kubectl/TLS 协议开销不在字节额度内，这不是硬网络/CPU 配额。
  每轮远端读操作受超时约束，本地数据默认达到 512 MiB 时停止；
  阈值检查和最终导出可产生额外开销，不是硬磁盘配额。已约定限额时不自行增大。
- 事件窗口始终按 `eventTimestamp` 的 `[start,end]` 过滤。到 end 后自动进入最多 60 秒的末次
  读取/排空和身份校验，再自动调用现有 `collect_violations` 与 `preprocess_aggregate`。
  每节点要求 end 后两次排空读，第二次开始不早于第一次完成后一个扫描周期，才允许 finalize。
  默认 60 秒预算包含这个间隔、末次读和身份校验；预算须大于扫描周期，不能因耗尽而省略确认。
  末次读取只补齐同一固定事件窗口，不延长业务观察区间。排空超时或尾部仍不完整则无删除资格。
  两次确认降低晚写入漏采风险，不证明无限延迟的队列或落盘前事件全部到达。
- 输出沿用 `2.1.1-current.yaml`、`2.1.2-agent-inventory.json`、`2.1.3-logs/*.log` 和
  `2.1.4-pre.json`；阶段二直接使用，不再次取远端日志或重跑同一预处理。
- 采集器不调用模型。到期自动完成的是采集、过滤、归一化和聚合；语义归因仍由后续调用完成。
  通知/唤醒不是采集器的职责。需要跨会话通知时，按宿主能力安排只读状态任务；无能力时告知
  用户可以通过任务路径回来继续，不声称已安排通知。

## 去重、连续性与失败

`collector.sqlite` 在事务内同时保存完整日志行与文件游标。身份是节点、device/inode、文件
generation 和字节位置；不会因正文相同就丢弃真实重复事件。最终行为归一化/聚合继续使用
原有脚本，而不是重新实现规则归因。原始行只存在本地受限文件中。

普通 rename 轮转保持游标；已排空的备份消失不算缺口。gzip 接替同名备份时，只有解压内容在
原字节边界的首部/尾部指纹一致才复用游标。半行不提交、不推进游标，下轮重读。
每个活跃/变化文件用一次 exec 批量返回首部指纹、旧字节边界和增量，模型不编排这些读取。
已排空、身份和 stat 大小/mtime/ctime 未变的 logger 备份只检查元数据，gzip 不重复解压。
这是文件级批处理，尚未引入整节点一次 exec；每节点仍有一次清单 exec 和读前/读后 Pod GET，
API 元数据成本要按节点规模评估。inventory LIST 与 exec 不在同一时刻；读前 GET 缩小同名 Pod
被替换后误读的时段，读后 GET 在日志事务提交前再核对 UID，因此暂保留这两次检查。

未读数据对应的文件消失、活动文件身份消失、截断/指纹变化、真实拓扑/UID/终止状态变化、
未排空均保持阻断。单次读取失败记为 suspected 并继续，连续三次失败停止。
同 UID 的短暂 NotReady 可以继续取证；起点和终点 inventory 仍须完整 Ready。
疑点绑定发生时已有的活动文件 identity/generation/offset 检查点；仅当这些原检查点仍在、
首部/边界指纹连续、游标追平、agent Ready 恢复时，suspected 才写入 resolvedAt/recoveryBasis，
保留历史但恢复删除资格。一次命令成功、文件已丢失、身份变化或没有可核对的原检查点都不能算
恢复；事后新建游标不能补造检查点。硬缺口即使带 resolvedAt 仍被采集器和预处理阻断。
文件指纹不能检测所有原地改写；文件连续性也不能证明
内核/ALS 在落盘前未丢事件，因此不保证完全无损。高流量下应缩短扫描周期或使用已有日志后端，
不能靠提高频率的建议掩盖本轮缺口。

同一任务和运行目录各有进程锁，避免双采集。进程异常退出后可在原 end 之前用**同一命令**恢复，
保留游标、参数和预算账本；对每个原节点记录 collector-interrupted 疑点。只有策略快照、节点/
agent 身份仍一致，且每节点中断前的原检查点均验证连续并排空，才能解除全部中断疑点。
空目录没有原活动文件检查点、任一节点验证失败或恢复发生在 end 之后，均不能恢复删除资格；
重启成功本身不算恢复。已过期、已完成或已失败的任务不重新
开启采集。失败时尽量生成带缺口的 pre.json；不能生成时保留 journal 和错误类别供本地排查。
任何缺口、无效日志、快照漂移或来源不合格都继续阻断相关删除，不把“未采到”解释成“无违规”。

本方案保持整个策略的节点覆盖门禁：节点增删、agent 替换以及 DaemonSet desired/current 数变化
都会阻断本窗口的整策略删除，已有节点的证据仍可只读分析。规则删除作用于策略覆盖的所有节点，
新增节点缺少 start 前基线，不能仅忽略它后继续删规则。协商窗口时明确这一后果；需要删除资格的
窗口应覆盖稳定的 agent 拓扑，扩缩容后重新建立下一窗口，不将旧窗口缺口改成合格。

## 阶段二任务领取

采集器完成后把任务设为 `collected`；失败设为 `collection-failed`，并记录 collector 的 lastTrigger。
每次新的阶段二触发先执行本地 `claim --task ABS_TASK`，脚本生成并返回唯一 owner，只在返回
`claimed=true` 后继续。它用任务锁和持久 claim 原子地写入 analyzing（增量）或 collecting（快照），
另一个触发返回 already-claimed，附 existingOwner/claimedAt。保存本次返回的 owner 供自身 release
或确属同一调用的恢复；该恢复可显式传 `--owner`，新的定时唤醒不能复制别人的 owner 冒充恢复。
不要求不同会话重建同一 owner。进入 awaiting-decision 后不重新分析，更新该状态时顺手移除
analysisClaim；旧记录如有残留，在后续状态下忽略，不能据此重入或释放任务。
自己的分析失败可用 `release --task ... --owner ...` 归还未完成任务，其他 owner 不得解除。

持久领取没有自动 TTL，避免长时间分析被另一调用并发接管。分析中断遗留领取时，先确认旧分析
调用已停止，向用户说明任务、旧 owner、领取时间和残留产物，取得对解除该领取的明确授权后执行：

```bash
python3 "$SKILL_DIR/scripts/monitor_violations.py" force-release --task "$TASK_FILE" \
  --expected-owner <核对过的旧owner> --reason "用户授权：旧分析会话已中断，释放领取以恢复分析" \
  --authorized-analysis-reset
```

该标志与 `--authorized-agent-read` 一样，只声明已有授权，不验证用户身份或外部审批，也不授予
新的系统权限；执行者仍须按文档先取得授权，不能由脚本自行推断。命令在任务锁内再次核对
expected-owner 和未完成状态，恢复领取前状态并把 owner、时间、原因写入 analysisClaimHistory，
保留中间产物。
随后由新调用重新 claim，复核已有输入和产物。旧 owner 的 attribution 无论是否可解析，均按
未完成材料处理：忽略旧 `outputs.attributionFile` 引用，从已核验的 current/pre 重新执行 2.1.5，
重建、校验并汇报归因后再更新引用，不因文件存在而跳过归因，也不沿用其中未完成的决定。
force-release 不证明旧归因或用户删除决定有效，不重启已失败采集器，也不改变证据资格。
领取只防重复执行；用户审核与最终确认照旧。

## 用户提前结束

用户明确要求提前分析时，不终止进程后重抓旧日志。向同一采集器提交结束请求：

```bash
python3 "$SKILL_DIR/scripts/monitor_violations.py" close --output "$RUN_DIR" \
  --reason "用户确认业务操作完成，要求提前结束观察"
```

请求只使用已到时间。采集器在下一安全点更新 task.window.end，保留 plannedEnd 和任务路径，
写入 `endReason=user-closed-early` 与 `closeAppliedAt`，然后进行末次读取和预处理。
提交成功不等于已应用；检查 status 中的确认后才按新 end 继续。开始最终归因后窗口不再修改。
本次不支持自动延长窗口，不能直接编辑 collector.json 或修改运行限额。

## 旧任务与快照回退

未启动采集器、窗口已经结束或没有持久运行环境时，仍使用阶段二原有的快照路径。它保留
“每节点复制在 end 后开始、全部文件成功复制、最早保留事件不晚于 start”的证据约束。
不能通过窗口结束后的快照补造连续采集证据；回退不能清除已有缺口或保证找回已被覆盖的日志。
