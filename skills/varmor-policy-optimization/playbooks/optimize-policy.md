# 阶段二：收敛观察任务

本阶段从任务记录恢复上下文，完成“采集 → 归因汇报 → 用户决定 → 候选 → 确认更新”。它可以在
阶段一之后异步触发，也可以在新的调用或会话中独立进入。

输入是一份或多份任务记录的绝对路径。一次调用可处理多个任务，也可为单个任务读取多个节点日志；
每个任务单独恢复策略身份、context、窗口和起点证据，使用独立运行目录并分别汇报。定时任务、
提醒和用户手动操作只是不同入口，不依赖对话记忆。自动触发可采集、分析并形成归因汇总；删除范围
尚未确定时停在 2.1.5，不能代填用户决定或自动更新 CRD。

命令按 [执行契约](README.md) 选择合适的失败检查与文件权限保护，并恢复本轮变量；未通过的命令
不因后续 chmod 成功而视为成功。

## 2.1 单任务路径

### 2.1.0 读取任务并确定有效窗口

先读取任务记录，核对 `status`、`clusterContext`、策略身份、`window`、快照路径和起点 inventory。
正常到期、定时触发和手动触发都走同一路径。

**先分辨采集模式**：`outputs.collectorDirectory` 非空时，按
[增量采集](../references/incremental-collection.md) 用 `monitor_violations.py status` 读取本地状态。
运行中继续观察，末次读取中等待脚本完成；不重复 exec/cp。`phase=finished` 且 pre.json 窗口与任务
一致时复用该目录和既有 current/inventory/pre；缺口或 `collectionComplete=false` 只允许只读分析。
采集失败时说明错误类别和已有证据，不把快照回退当成清除缺口的办法。

如果用户在首次正式采集前明确表示业务操作已完成并要求提前进行，可将这条消息视为提前结束窗口
的确认：读取一次当前 epoch（或使用用户明确给出的已到时间），保持 `plannedEnd` 不变，把
`window.end` 更新为该时间，设置 `endReason=user-closed-early` 并更新 `updatedAt`。有效 `end`
需满足不早于 `start`，更新完成后再开始采集；不要另行建议一个未来的短窗口。

上述直接更新适用于尚未启动采集器的快照任务；运行中的增量任务通过 `monitor_violations.py close`
提交同一用户要求，确认 `closeAppliedAt` 和任务实际 end 后继续，不直接编辑状态文件或终止进程。

到期或提前结束处理完成后再领取任务。增量任务须等待采集器结束，状态为 collected/collection-failed，
采集器已写入 lastTrigger；快照任务仍从 observing 开始，要求实际 end 已到。
执行 `monitor_violations.py claim --task <任务绝对路径>`，脚本生成并返回本次 owner，只在
claimed=true 后继续并保存 owner；already-claimed 或等待用户决定时结束重复触发。确属同一调用的
恢复可显式传原 owner，新的定时唤醒不复制旧 owner。遗留领取按增量参考中的授权 force-release
流程解除，不手改 JSON，也不自动按年龄接管。领取会原子地写入 analyzing（增量）或 collecting（快照）；自身失败
可用 release 归还未完成任务，不覆盖其他调用的领取。失败采集的 pre.json 只做只读分析，不因
领取成功获得删除资格；缺少 pre.json 时先报告采集失败，不进入归因。

force-release 后重新领取时，忽略旧 `outputs.attributionFile`，从核验过的 current/pre 重新执行
2.1.5，重建并校验归因，完成汇报后再更新引用。旧文件即使存在且可解析，也不能用来跳过归因
或沿用未完成的用户决定。

一旦正式采集开始，快照任务的本轮有效 `end` 即固定，不再修改。增量任务在进入最终归因后范围固定。
若先前已有早于有效 `end` 的探索性快照导出，
它不能作为本轮正式采集产物，仍需在有效 `end` 之后重新采集。任务状态用于避免定时与手动入口
重复执行：快照路径由 claim 写 `lastTrigger` 并进入 `collecting`；增量路径由采集器完成日志阶段，
claim 后进入 analyzing，不再次采集。已经进入后续状态的任务不重复采集。
提前手动触发时，如有外部定时任务则按能力取消；无法取消时，后续触发读取状态后直接结束。

### 2.1.1 固定范围并校验基线

窗口统一使用任务记录中的 epoch 秒并以 `eventTimestamp` 为准；用户给 ISO8601 时只转换一次并
保留原值。核对有效 `end` 已到、context 与任务记录完全一致，确认实际 agent/manager 版本，并按
2.2 选择适用分支。快照回退每轮使用全新目录，并把路径写入任务的 `outputs.latestRunDirectory`；
增量路径使用采集器已创建的独立目录。

**增量路径**：对采集器的 `2.1.1-current.yaml` 再做本地 `validate_policy --require-observation
--require-atomic-capabilities` 和 `hash_policy verify-snapshot --window-start` 校验，并从该文件恢复
RV。核对 collector/pre/task 的窗口、节点及来源资格一致后，直接进入 2.1.5；不执行下方的
远端导出，也不执行 2.1.2～2.1.4。不覆盖采集器已保存的证据。最终 replace 前仍核对线上 RV。
空 selector 只沿用阶段一已确认的 opt-in。当前 RV 已因 status 变化而过期时，按正常审核流程重新
绑定基线，不拿新远端 RV 直接替换已审核值。

**下面的 2.1.1～2.1.4 命令是旧任务的快照回退**；新任务启动与自动预处理见增量采集参考。

```bash
EXPECTED_CTX="<当前任务记录中的 clusterContext>"
CTX="$(kubectl config current-context)" || exit 1
test -n "$CTX" || exit 1
test "$CTX" = "$EXPECTED_CTX" || exit 1
kubectl --context "$CTX" cluster-info || exit 1
RUN_DIR="<当前任务本轮的独立运行目录>"
install -d -m 700 "$RUN_DIR" || exit 1

kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
  -o yaml > "$RUN_DIR/2.1.1-current.yaml" || exit 1
chmod 600 "$RUN_DIR/2.1.1-current.yaml" || exit 1

python3 scripts/validate_policy.py --file "$RUN_DIR/2.1.1-current.yaml" \
  --require-atomic-capabilities --require-observation \
  --quiet-notices > /dev/null || exit 1

RV="$(python3 scripts/hash_policy.py verify-snapshot \
  --file "$RUN_DIR/2.1.1-current.yaml" \
  --snapshot <起点策略快照绝对路径> \
  --window-start <start> --resource-version-only)" || exit 1
test -n "$RV" || exit 1
```

校验必须证明：

- 当前对象仍是同一 UID、generation、`status.profileName` 和 spec 哈希；
- `start >= policySnapshot.capturedAt`；
- capability 聚合规则已展开；
- `auditViolations=true` 且 `allowViolations=true`；
- 只处理 `EnhanceProtect`，不修改 target、mode、enforcer 或控制开关。

`resourceVersion` 仅因 status 变化不阻断，但 `$RV` 绑定本轮基线，最终 apply 前再比较一次。
快照校验结果不单独落盘，结论写入 `2.1.6-analysis.md`。
RV 是本地 current 的版本；换 shell 时从该文件恢复，禁止用新的远端 RV 覆盖基线值。

### 2.1.2 生成期末 inventory

先按阶段一的方法确认 agent DaemonSet、namespace 和容器名。使用混合 Kubernetes List 的标准
输入直接生成 inventory，不保存 DaemonSet/PodList 原始 dump：

```bash
(set -o pipefail
 kubectl --context "$CTX" get daemonset,pods -n "$AGENT_NS" -o json \
   | python3 scripts/build_agent_inventory.py \
       --cluster-snapshot - \
       --daemonset-name "$AGENT_DS" \
       --daemonset-namespace "$AGENT_NS" \
   > "$RUN_DIR/2.1.2-agent-inventory.json") || exit 1
chmod 600 "$RUN_DIR/2.1.2-agent-inventory.json" || exit 1
```

起止 inventory 会核对 DaemonSet UID/generation/desired/current/ready、全部 owned Pod、节点、
Pod UID、Ready 和 terminating 状态。节点增删、Pod 替换或任一端不完整都阻断删除。

### 2.1.3 按批次逐节点导出日志

仅快照回退使用本节；默认增量任务的节点读取由脚本负责。

核对实际 hostPath 映射后，对起止节点并集串行采集。不按 Ready 筛掉节点。
使用已有节点只读通道，或已经获授权的 agent exec/cp；按会话授权设置 `L4_AUTHORIZED=yes`，
未获授权不进入特权容器。不能在容器中反复 grep/cat，`kubectl cp` 也不展开通配符。
开始遍历节点前读取一次当前 epoch 作为整批采集起点并确认窗口已结束，后续节点复用该值，不重复
取时。每个节点的枚举、保存精确路径、复制和发布在同一次 Bash 调用中完成：

```bash
test "$L4_AUTHORIZED" = yes || exit 1
WINDOW_END=<end>
COLLECTION_STARTED_AT="$(date +%s)" || exit 1
test "$COLLECTION_STARTED_AT" -ge "$WINDOW_END" || exit 1
# 在同一次 Bash 调用中遍历节点；以下节点段复用同一个 COLLECTION_STARTED_AT。
REMOTE_OUTPUT="$(
  [ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec \
    -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
    sh -c 'test -r /var/log/varmor/violations.log &&
      find /var/log/varmor -maxdepth 1 -type f \
        \( -name "violations.log" -o -name "violations-*.log" \
           -o -name "violations-*.log.gz" -o -name "violations.log.*" \) -print'
)" || exit 1
test -n "$REMOTE_OUTPUT" || exit 1
REMOTE_FILES=()
while IFS= read -r remote; do
  test -n "$remote" && REMOTE_FILES+=("$remote")
done <<< "$REMOTE_OUTPUT"
printf '%s\n' "${REMOTE_FILES[@]}" \
  | grep -Fx '/var/log/varmor/violations.log' >/dev/null || exit 1
STAGING="$(mktemp -d "$RUN_DIR/.copy-XXXXXX")" || exit 1
LOG_ARGS=()
for remote in "${REMOTE_FILES[@]}"; do
  local_file="$STAGING/${remote##*/}"
  kubectl --context "$CTX" cp "$AGENT_NS/$AGENT_POD:$remote" \
    "$local_file" -c "$AGENT_CONTAINER" || exit 1
  # kubectl cp may preserve the remote mtime; record local copy completion.
  touch "$local_file" || exit 1
  LOG_ARGS+=(--file "$local_file")
done
python3 scripts/finalize_node_log.py "${LOG_ARGS[@]}" \
  --output "$RUN_DIR/2.1.3-logs/$NODE.log" \
  --window-end "$WINDOW_END" --started-at "$COLLECTION_STARTED_AT" || exit 1
rm -r -- "$STAGING"
```

脚本只处理本地副本，要求采集起点不早于 `window.end`、每个文件完成时间不早于采集起点，
验证 JSON/时间戳、解压并保留内容，成功后原子发布 0600 节点日志并携带采集起点；拒绝覆盖旧文件。
失败时保留临时材料，不产生正式日志。不保存退出码文件或永久 `raw/` 目录。

每批落盘后执行：

```bash
find "$RUN_DIR" -type d -exec chmod 700 {} + || exit 1
find "$RUN_DIR" -type f -exec chmod 600 {} + || exit 1
```

### 2.1.4 一步生成 `pre.json`

`preprocess` 在内存中完成 manifest、逐节点日志合并、固定窗口/profileName/可选 policy identity
过滤、清洗和聚合，不再生成 `manifest.json`、`merged.log` 或 `collected.json`：

```bash
python3 scripts/preprocess_aggregate.py preprocess \
  --start-agent-inventory <起点-agent-inventory-绝对路径> \
  --end-agent-inventory "$RUN_DIR/2.1.2-agent-inventory.json" \
  --window-start <start> --window-end <end> \
  --node <n1> --log "$RUN_DIR/2.1.3-logs/<n1>.log" \
  --node <n2> --log "$RUN_DIR/2.1.3-logs/<n2>.log" \
  --policy "$RUN_DIR/2.1.1-current.yaml" \
  --network-proxy-evidence <not-applicable|eligible|ineligible> \
  > "$RUN_DIR/2.1.4-pre.json" || exit 1
chmod 600 "$RUN_DIR/2.1.4-pre.json" || exit 1
```

过滤身份直接从 current 的 kind/namespace/name/status.profileName 派生，避免复制参数时用错策略。
`2.1.4-pre.json` 是后续唯一采集输入，内嵌：

- `collectionManifest`：窗口、起止拓扑、逐节点 earliest/latest、read 与 retention 依据；
- `collectionCounts`：matched、窗口外、identity mismatch、parse error 等过滤计数；
- `collectionComplete`、`retentionCovered`、`seccompSyscalls`、`aggregatedEvents`。

manifest 以节点日志携带的采集起点计算 `collectionStartedAt/collectedAt`，另记
`manifestBuiltAt`；所有节点都必须
在 end 之后采集，不能用 preprocess 的运行时间代替。只有 `collectionComplete=true` 才能进入
候选生成。所有节点均须有不晚于 start 的保留事件；
空日志或最早事件晚于 start 时 retention 为 unknown。`matched=0` 时先按
`profileMismatch/policyIdentityMismatch/missingIdentity` 诊断，不能直接解释为无违规。
日志 Envelope 见 [violation-log.md](../references/violation-log.md)。

### 2.1.5 形成并汇报归因

先生成非 Seccomp 归因目录：

```bash
python3 scripts/preprocess_aggregate.py catalog \
  --file "$RUN_DIR/2.1.1-current.yaml" \
  > "$RUN_DIR/2.1.5-catalog.json" || exit 1
```

同时运行 Seccomp 计划但先只看 stdout，不落盘。首次输出只列 pending 候选，不产生删除：

```bash
python3 scripts/seccomp_plan.py \
  --policy "$RUN_DIR/2.1.1-current.yaml" \
  --pre "$RUN_DIR/2.1.4-pre.json" || exit 1
```

模型以 `2.1.4-pre.json.aggregatedEvents` 和 `2.1.5-catalog.json.ruleCatalog` 为输入，按
[attribution.json](../templates/attribution.json) 写
`$RUN_DIR/2.1.5-attribution.json`（纯数组，不增加外层包装对象）：

- 初次归因只写 `eventId`、`summary` 和 `matches`，不替用户填写 `decision`；
- 只在事件字段、规则限制和 enforcer 均确定匹配时加入 match；
- 一个事件可匹配多条规则；必须检查全部候选，不能找到第一条就停止；
- RawRule 必须逐字复制 catalog 坐标；targets 需要完整可执行路径/Profile 证据；
- 同一 capability 原子对应多条业务语义规则时，事件只能证明其直接语义；证据不足保持未匹配；
- `networkProxyEvidenceEligible=false` 时 NetworkProxy matches 必须为空。
- 当前策略 `privileged=false` 时，规则目录仍只包含显式原子；另读
  [隐式基线语义](../references/enhance-protect-semantics.md#3-隐式基线重要盲区)，检查
  `matches: []` 的事件是否可确定归于 RuntimeDefault。确定时只写入分析报告“基线来源”，
  不伪造 catalog match、不生成删除坐标；证据不足继续标为 unmatched。

先校验事件 ID、精确坐标和 enforcer，不保存 stdout：

```bash
python3 scripts/validate_attribution.py \
  --pre "$RUN_DIR/2.1.4-pre.json" \
  --catalog "$RUN_DIR/2.1.5-catalog.json" \
  --attribution "$RUN_DIR/2.1.5-attribution.json" > /dev/null || exit 1
```

attribution 必须覆盖 `aggregatedEvents` 中全部 eventId，且每个只出现一次；没有确定关联也要写
`matches: []`，不能省略事件。

#### 归因汇报

完成归因校验后，整理并向用户展示：

- 本轮窗口、采集完整性、节点与 retention 结论；
- 按业务语义分组的匹配事件、规则坐标、Enforcer 和“为何匹配”；
- 一个事件命中多条规则、Seccomp 歧义及删除后会放宽什么；
- unmatched、证据不足、隐式基线来源和建议继续观察的项目；
- Seccomp pending 候选，以及当前尚未生成 candidate、尚未修改集群。

归因成立只说明规则被业务触发，不等于用户同意移除。汇报后询问用户希望删除、保留还是继续
观察；同时把任务状态更新为 `awaiting-decision`，记录 `outputs.attributionFile` 并移除
`analysisClaim`。旧任务后续状态若残留此字段则忽略，不视为分析领取。在用户给出
删除范围前停留在本节，不生成 post-Seccomp、candidate 或 guard diff。

用户理解归因后，再把 Seccomp pending 候选和所有已成立 matches 按业务影响分组，请用户逐项或
逐组决定：

- Seccomp：每条内置规则显式删除/保留；每个自定义 syscall 原子组显式删除/保留；
  有歧义时另行确认是否接受扩大允许范围；
- 每个非 Seccomp match：`remove`、`keep` 或 `observe`。

用户确认后，将非 Seccomp 决定写回每个 match 的 `decision` 字段，并用
`--require-decisions` 再次运行上述校验。同一规则坐标出现在多个事件中时决定必须一致。
`2.1.5-attribution.json` 同时承担归因证据和用户决定记录，不再生成 `removal-decision.json`
或 `removals.json`。存在确认删除项时进入 2.1.6；全部保留或继续观察时，记录结论并将当前任务
设为 `completed`，需要继续时再按 2.1.8 建立下一任务。

### 2.1.6 生成候选并执行严格 guard

根据用户决定生成 post-Seccomp 基线。所有候选都需要显式决定；漏传一个参数时
`decisionsComplete=false`，apply 和 guard 均失败。存在 Seccomp 命中、保留或歧义决定时保存
最终计划为 `2.1.6-seccomp-plan.json`；无上述情况时只生成 post-Seccomp YAML：

```bash
python3 scripts/seccomp_plan.py \
  --policy "$RUN_DIR/2.1.1-current.yaml" --pre "$RUN_DIR/2.1.4-pre.json" \
  [--remove-seccomp-rule <rule> ...] [--keep-seccomp-rule <rule> ...] \
  [--remove-seccomp-syscall <syscall> ...] [--keep-seccomp-syscall <syscall> ...] \
  [--allow-ambiguous] \
  > "$RUN_DIR/2.1.6-seccomp-plan.json" || exit 1  # 存在命中/保留/歧义决定时

python3 scripts/seccomp_plan.py \
  --policy "$RUN_DIR/2.1.1-current.yaml" --pre "$RUN_DIR/2.1.4-pre.json" \
  --apply [--remove-seccomp-rule <rule> ...] [--keep-seccomp-rule <rule> ...] \
  [--remove-seccomp-syscall <syscall> ...] [--keep-seccomp-syscall <syscall> ...] \
  [--allow-ambiguous] \
  > "$RUN_DIR/2.1.6-post-seccomp.yaml" || exit 1
```

`SCMP_ACT_ALLOW/LOG` 只进入忽略清单，不得作为删除候选。`customRemovals` 必须保留完整 RawRule
原子。`unmatchedSyscalls` 不产生决定。自定义规则按 syscall 整组决定，不支持组内部分选择；
内置规则独立使用 rule 参数决定。保留某个候选不代表其他候选已被证实，原本多规则命中的 syscall
只要仍有删除，仍需 `--allow-ambiguous`。

候选和 guard 都直接从 attribution 中的 decision 派生坐标：

```bash
python3 scripts/apply_removals.py \
  --baseline "$RUN_DIR/2.1.6-post-seccomp.yaml" \
  --pre "$RUN_DIR/2.1.4-pre.json" \
  --attribution "$RUN_DIR/2.1.5-attribution.json" \
  > "$RUN_DIR/2.1.6-candidate.yaml" || exit 1

python3 scripts/guard_removal.py \
  --baseline "$RUN_DIR/2.1.1-current.yaml" \
  --candidate "$RUN_DIR/2.1.6-candidate.yaml" \
  --pre "$RUN_DIR/2.1.4-pre.json" \
  --attribution "$RUN_DIR/2.1.5-attribution.json" \
  [--remove-seccomp-rule <rule> ...] [--keep-seccomp-rule <rule> ...] \
  [--remove-seccomp-syscall <syscall> ...] [--keep-seccomp-syscall <syscall> ...] \
  [--allow-ambiguous] \
  > "$RUN_DIR/2.1.6-guard-diff.json" || exit 1
```

guard 从原始 current + pre 重算 Seccomp 和非 Seccomp 删除，要求 candidate 与预期完整相等，
并拒绝任何新增、改写、控制字段变化或未批准删除。模型不得手工编辑 YAML。

按 [optimization-analysis.md](../templates/optimization-analysis.md) 写
`$RUN_DIR/2.1.6-analysis.md`，覆盖快照/拓扑/retention、归因、用户决定、未匹配、Seccomp 计划和
guard diff。最后收敛权限并计算 candidate 哈希：

```bash
find "$RUN_DIR" -type d -exec chmod 700 {} + || exit 1
find "$RUN_DIR" -type f -exec chmod 600 {} + || exit 1
CANDIDATE_SHA256="$(python3 scripts/hash_policy.py fingerprint \
  --file "$RUN_DIR/2.1.6-candidate.yaml" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')" || exit 1
```

将该哈希原样写入 analysis 的审核记录；新增 shell 从已审核记录恢复 `CANDIDATE_SHA256`。
同时把任务状态更新为 `candidate-ready`，记录 `outputs.candidateFile`。

### 2.1.7 dry-run、最终确认与 replace

先执行 server dry-run。候选用完整对象语义表达删除，因此阶段二使用 `replace`；这里不重复 hash
或 resourceVersion 校验，因为 dry-run 不产生变更：

```bash
kubectl --context "$CTX" replace \
  -f "$RUN_DIR/2.1.6-candidate.yaml" --dry-run=server || exit 1
```

向用户提供 candidate 与 analysis 的本地路径、`CANDIDATE_SHA256`、脱敏摘要、guard diff、目标
context 和生效边界。用户第二次明确确认目标集群与最终变更后：

```bash
RV="$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["metadata"]["resourceVersion"])' \
  "$RUN_DIR/2.1.1-current.yaml")" || exit 1
CURRENT_RV="$(kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
  -o jsonpath='{.metadata.resourceVersion}')" || exit 1
test -n "$RV" && test "$CURRENT_RV" = "$RV" \
  && python3 scripts/hash_policy.py verify \
       --file "$RUN_DIR/2.1.6-candidate.yaml" --hash "$CANDIDATE_SHA256" \
  && kubectl --context "$CTX" replace -f "$RUN_DIR/2.1.6-candidate.yaml"
```

该命令同时防止确认等待期间的远端策略漂移、本地 candidate 误改和拿错文件。kubectl 的
resourceVersion 冲突仍作为最后一道并发保护。

### 2.1.8 验证与下一窗口

先读取更新后的对象并校验线上 `spec` 与 candidate 一致：

```bash
kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
  -o yaml > "$RUN_DIR/2.1.8-post-replace.yaml" || exit 1
python3 scripts/guard_removal.py --verify-live \
  --candidate "$RUN_DIR/2.1.6-candidate.yaml" \
  --live "$RUN_DIR/2.1.8-post-replace.yaml" > /dev/null || exit 1
```

再按阶段一 1.6 检查 VP/VCP 与 ArmorProfile 的加载计数及失败 conditions。AppArmor/BPF 以实际
Profile 加载结果为准；Seccomp/注入变化需要新容器。`updateExistingWorkloads=true` 主要作用于
策略创建/删除，不能假定更新规则会自动滚动。需要重建时由用户执行或单独授权，不能直接开始
下一观察窗口。依据见 [生命周期与生效边界](../references/policy-crd-lifecycle.md)。

更新和必要的新 Pod 实际生效后，在下一轮新目录按阶段一 1.7 创建快照、起点 inventory 和任务，
再协商下一固定窗口。只读报告或无删除项时也按报告模板落盘，未执行的 diff/更新步骤明确标 N/A。
通常建议 3～5 个周期，但按业务覆盖与违规收敛判断，不把次数设为硬门限。

## 2.2 分支与例外

| 条件 | 动作 |
|---|---|
| 缺少起点策略快照 | 只读分析；不得生成 candidate。为当前策略创建新快照后重新开始窗口 |
| 起点 inventory 缺失 | 无法证明节点覆盖；不得删除，重新开始窗口 |
| 增量采集已完成且 pre.json 完整 | 复用本地输入，跳过快照采集和重复预处理 |
| 增量初始化晚于 start | 立即拒绝新启动；多节点初始化跨过 start 则停止，不全量拉历史 |
| 无法恢复的日志缺口、中断或末次未确认排空 | 只读分析；不得删除，保留证据并协商下一窗口 |
| 单次读取失败、同 UID 瞬时 NotReady 或 end 前采集器重启 | 核对疑点发生前的原检查点和身份；全部节点连续追平才恢复资格，保留恢复历史 |
| 未启动采集器且窗口已结束 | 使用原快照回退，不补造增量连续性 |
| 空 selector | 仅对阶段一已单独确认的策略传 `--allow-empty-selector` |
| v0.10.0 | 仅当实际使用 `copy-fail-mitigation` 时判不兼容 |
| v0.10.1～v0.10.5 | 依据 catalog `verificationEvidence` 已验证实现一致，不做 patch 版本 mismatch |
| 其他/未知版本 | 只对实际使用的内置规则标记兼容性 unknown，需人工核验 |
| 不含 NetworkProxy | 传 `--network-proxy-evidence not-applicable`，不加载其版本分支 |
| NetworkProxy `<v0.10.3` 或版本未知 | 传 `ineligible`，仅该来源禁止删除 |
| NetworkProxy `v0.10.3+` + runc 节点日志 | 证据链完整时传 `eligible` |
| NetworkProxy + micro-VM | 传 `ineligible`，只读分析 |
| `kubectl cp`/tar 不可用 | 使用 2.2.1 单次流式导出；本地校验后发布，失败不产生正式日志 |
| Seccomp 多规则命中 | 默认阻断；用户确认扩大允许范围后才传 `--allow-ambiguous` |
| Seccomp 候选存在 | 每条内置规则和每个自定义 syscall 组均显式 remove/keep，三处参数完全一致 |
| 没有任何确认删除项 | 不生成或 apply candidate；记录分析并进入下一观察窗口 |

兼容导出仍必须读取全部已枚举轮转文件，每个文件只读一次；任何文件不可读、解压失败或流中断都
失败关闭。退出码由当前命令直接判断，不另存 `<node>.exit`。

### 2.2.1 无 tar 时的导出

仅在复制尚未开始且已确认 tar 不可用时选择此路径；复制途中失败不得改走此路径重读同批日志。
本分支复用 2.1.3 在节点遍历前确定的 `WINDOW_END` 和 `COLLECTION_STARTED_AT`，并在同一次 Bash
调用内重新枚举并立即读取，stdout 只写本地：

```bash
test "$L4_AUTHORIZED" = yes || exit 1
test "$COLLECTION_STARTED_AT" -ge "$WINDOW_END" || exit 1
REMOTE_OUTPUT="$(
  [ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec \
    -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
    sh -c 'test -r /var/log/varmor/violations.log &&
      find /var/log/varmor -maxdepth 1 -type f \
        \( -name "violations.log" -o -name "violations-*.log" \
           -o -name "violations-*.log.gz" -o -name "violations.log.*" \) -print'
)" || exit 1
test -n "$REMOTE_OUTPUT" || exit 1
REMOTE_FILES=()
while IFS= read -r remote; do
  test -n "$remote" && REMOTE_FILES+=("$remote")
done <<< "$REMOTE_OUTPUT"
printf '%s\n' "${REMOTE_FILES[@]}" \
  | grep -Fx '/var/log/varmor/violations.log' >/dev/null || exit 1
STAGING="$(mktemp -d "$RUN_DIR/.stream-XXXXXX")" || exit 1
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec \
  -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'set -eu
    test "$#" -gt 0
    for f do
      test -r "$f"
      case "$f" in *.gz) gzip -cd "$f";; *) cat "$f";; esac
      printf "\n"
    done' sh "${REMOTE_FILES[@]}" > "$STAGING/violations.log" || exit 1
python3 scripts/finalize_node_log.py --file "$STAGING/violations.log" \
  --output "$RUN_DIR/2.1.3-logs/$NODE.log" \
  --window-end "$WINDOW_END" --started-at "$COLLECTION_STARTED_AT" || exit 1
rm -r -- "$STAGING"
```

## 2.3 失败关闭清单

出现以下任一情况时停止且不更新 CRD：

- context/依赖/连接异常，策略不存在或不是 EnhanceProtect；
- 聚合 capability 未展开，观察开关未显式开启；
- 快照缺失或窗口早于快照，UID/generation/profileName/spec 漂移；
- 起止 agent inventory 不完整，节点增删、Pod UID 替换、NotReady 或 terminating；
- 预期节点日志缺失、读取/解压/JSON 解析失败，窗口未结束或 retention 无法证明；
  增量初始化晚于 start、无法恢复的文件缺口或中断、末次读取未确认排空；
- NetworkProxy 证据不合格却请求删除其规则；
- attribution 事件、坐标、enforcer 或 decision 不合法，同一坐标决定冲突；
- Seccomp 歧义未确认，或 keep/allow 参数在 plan、apply、guard 间不一致；
- guard 发现非删除变更或 candidate 与重算结果不完全一致；
- server dry-run 失败，线上 spec 与 candidate 不一致，最终 resourceVersion/hash 不一致，或用户未确认。
