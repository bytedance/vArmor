# 阶段一：建立观察任务

本阶段接收策略、完成校验与下发，并建立可供后续异步恢复的任务记录。一次调用可处理一份或多份
策略；每份策略使用独立运行目录和任务记录，不混用校验结果、哈希或确认。

策略处理分两个步骤：

- **填写（组装）阶段**：允许模型根据**用户已确认**的信息组装完整 CRD。
- **校验阶段**：模型**不得擅自修复**；只能由脚本执行固定规范化，或回到用户重新确认信息。

## 1.0 进入条件

- 用户先了解 Skill 时，简要说明“接收/组装 → 本地校验 → 可选预检 → dry-run → 确认下发”；
  等用户准备处理策略后再展开命令步骤。
- 用户提供 YAML 并要求检查时，先按 1.1.1 保存工作副本，再从 1.2 开始本地校验；不补规则、
  不重选 Enforcer。
- 用户希望创建策略但未提供 YAML 时，进入 1.1，依据用户给出的字段和规则组装。

策略内容优先来自用户。模型负责解释字段、发现缺失或冲突、执行规范化校验并提出修正建议。
预检用于验证策略设定，不延伸为设计一整套规则；集群支持某 Enforcer 只证明它可能可用，不代表
应该选择它。

命令按 [执行契约](README.md) 选择合适的失败检查与文件权限保护；恢复本轮变量，不依赖上一次
shell 状态。

## 1.1 填写 / 组装

### 1.1.1 接收策略输入

优先请用户提供现有 YAML 或本地文件路径。拿到策略后先复述对象身份、target、Enforcer、控制
开关和规则来源，确认理解一致；此时不查询集群、不替用户扩充规则。阶段一统一在受限运行目录中
处理副本，不改写用户原文件：

```bash
RUN_DIR="<当前策略的独立运行目录>"
install -d -m 700 "$RUN_DIR" || exit 1
SOURCE_POLICY="<用户提供的本地 YAML 路径>"
install -m 600 -- "$SOURCE_POLICY" "$RUN_DIR/1.1.3-draft.yaml" || exit 1
```

用户直接提供 YAML 内容时，将原文写入同一 `1.1.3-draft.yaml`。如果需要从零组装，则在 1.1.3
生成该文件，无需执行上述复制命令。

### 1.1.2 收集组装信息

仅对明确要求从零创建策略的用户逐项收集；不重新询问用户已经明确的内容：

1. 策略类型：VarmorPolicy 还是 VarmorClusterPolicy。
2. `metadata.name`；VP 还需 namespace。
3. `target.kind`（Deployment/StatefulSet/DaemonSet/Pod）。
4. 目标定位：`target.name` 或 `target.selector`（二选一）。
5. `target.containers`（可空=全部业务容器）。
6. `policy.enforcer`（由用户选择；支持性探测不能替用户选择）。
7. 期望启用的内置/自定义规则（由用户提供；没有明确规则时停下询问，不自动补充规则）。
8. **`updateExistingWorkloads`（必须显式确认）**：为 true 且 manager 启用了更新工作负载能力时，
   创建策略会触发现有 Deployment/StatefulSet/DaemonSet 的滚动更新；必须说明并确认影响。
9. **`privileged`（必须显式确认，默认 false）**：决定 RuntimeDefault/AlwaysAllow 基线，
   且为 true 时 vArmor 不生成 Seccomp Profile。
10. **仅当选了全量匹配（空 selector）时**：作为高风险项单独确认；1.2.1 需带
    `--allow-empty-selector`，并在展示实际命中清单后进行第二次确认。

### 1.1.3 组装 CRD

依据用户确认信息，参照
[templates/observation-policy-skeleton.yaml](../templates/observation-policy-skeleton.yaml)
组装完整 CRD。只填用户确认的内容，不替用户臆测规则。组装产物必须写入
`$RUN_DIR/1.1.3-draft.yaml`，后续
校验、展示与下发都基于文件进行，不使用临时拼接的命令直接创建策略。

`spec.target` 创建后不可变，组装时务必让用户核对目标。

## 1.2 确定性校验（模型不得擅自修复）

### 1.2.1 脚本校验 + 固定规范化

```bash
python3 scripts/validate_policy.py \
  --file "$RUN_DIR/1.1.3-draft.yaml" > "$RUN_DIR/1.2.1-normalized.yaml" || exit 1
chmod 600 "$RUN_DIR/1.1.3-draft.yaml" "$RUN_DIR/1.2.1-normalized.yaml" || exit 1
POLICY_SHA256="$(python3 scripts/hash_policy.py fingerprint \
  --file "$RUN_DIR/1.2.1-normalized.yaml" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')" || exit 1
```

- stdout 重定向得纯 YAML；adjustments / notices 在终端（stderr）读取并转达用户。
- 校验不通过：把**全部**错误一次性交回用户，或回到 1.1.2 重新确认；模型不自行改规则内容。
- 脚本只校验优化约束与明显结构错误，**不是完整 CRD Schema**；目标集群的 `--dry-run=server`
  才是 Schema 权威，不能仅因脚本 valid=true 就宣称策略完全合格。
- 自动规范化（均有 adjustment 说明）：补 `auditViolations/allowViolations=true`；把
  `disable-cap-all/-privileged/-except-net-bind-service` 展开为原子 `disable-cap-[CAP]`
  （保留 NET_BIND_SERVICE 豁免）。
- 聚合 capability 规则的展开只能由 `validate_policy.py` 按 catalog 执行，模型不得手工列举。
  展开后的 `1.2.1-normalized.yaml` 才是用户审核、指纹绑定和实际下发的策略。

### 1.2.2 RawRules 结构化模型校验（有阻断效力）

模型对 `1.2.1-normalized.yaml` 中的 RawRules 执行检查（三类内置规则已由脚本确定性校验，不再
重复）：

- **必读**：[references/raw-rules-syntax.md](../references/raw-rules-syntax.md)。
- 若策略不含任何 RawRules，记录 `result=true`、`reason=not applicable` 后直接继续，不做空转分析。
- **检查清单**：
  - appArmorRawRules：规则文本/逗号结尾/glob，targets 路径，deny/audit 语义；
  - bpfRawRules：files/processes/network/ptrace/mounts 的字段层级、qualifier、pattern 约束；
  - syscallRawRules：names 为 syscall、action 合法、args 结构；
  - networkProxyRawRules：egress 结构、qualifier；
  - 各 RawRules 是否存在对应的 enforcer。
- **结果**：在用户审核摘要中记录 `result` 与具体问题/已检查项，不额外生成模型自证 JSON。
  CRD 结构以 server dry-run 为准；RawRules 内部文本语法、动作和业务影响仍需本步检查，
  server dry-run 不会编译 AppArmor 等 Profile。
- **内容指纹**：沿用 1.2.1 生成的 `POLICY_SHA256`，无 RawRules 时也必须保留并展示。
- **阻断**：任何未检查、格式异常、证据不足、`result=false` 均**不得进入 dry-run / 下发**。
- **绑定**：阶段内不为 dry-run 重复校验指纹；真正 create 前统一 verify。若文件在此之前发生
  修改，旧结论失效，重新执行 1.2.1 和 1.2.2。

## 1.3 下发前预检

完成本地策略校验后，如果用户准备继续下发，在最终确认策略前主动说明 dry-run 无法覆盖的风险，
并建议以下预检：

| 预检项 | 目的 |
|---|---|
| context 与 vArmor 状态 | 确认目标集群、CRD、manager/agent 和实际版本 |
| 已有策略与 Profile | 检查同名 VP/VCP、目标上已有策略、ArmorProfile 状态及潜在冲突 |
| target 与容器 | 确认工作负载、selector、容器名、Annotation 和实际命中范围 |
| Enforcer 能力 | 核验用户策略所选 AppArmor/BPF/Seccomp/NetworkProxy 是否可用 |
| 生效与滚动影响 | 核验 `updateExistingWorkloads`、现有 Pod 和可能的滚动/重建影响 |

询问用户要执行“全部、指定项目或跳过”，按用户选择运行相应查询。用户已提供并确认的事实
记录为 `user-provided`，无需重复查询；跳过项记为 `not-checked`。预检结果用于指出不兼容、冲突
和风险，不据此改写策略内容。真正下发前仍需完成 context 确认、脚本校验、server dry-run、
diff/哈希和最终确认。

执行任何已选择的集群预检前固定 context，后续 kubectl 都显式携带：

```bash
CTX="$(kubectl config current-context)" || exit 1
test -n "$CTX" || exit 1
kubectl --context "$CTX" cluster-info || exit 1
```

仅在实际使用的规则存在兼容性疑问且用户选择版本检查时，查询 manager/agent 镜像；catalog
provenance 不是精确版本门限，NetworkProxy 使用独立版本边界。

按对象类型选择正确的查询方式，分支要点（不穷举每条命令）：

- **VP（namespace 作用域）**：查询带 `-n <ns>`。
- **VCP（cluster 作用域）**：跨 namespace 查询用 `-A`；不带 `-n` 只会落到当前 namespace，并非全集群。
- **控制器（Deploy/STS/DaemonSet）**：读 PodTemplate 的 `.spec.template.spec.containers[*].name`。
- **Pod（无 template）**：读 `.spec.containers[*].name`，不是 `.spec.template...`。

```bash
# vArmor 自身可用：CRD 已安装
kubectl --context "$CTX" get crd -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep varmor

# 选择“context 与 vArmor 状态”时：只列组件身份、镜像和 Ready，不导出完整资源
kubectl --context "$CTX" get deploy,ds -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.readyReplicas,IMAGE:.spec.template.spec.containers[*].image'

# 选择“已有策略与 Profile”时：只列身份、模式和状态，再对相关对象做精确查询
kubectl --context "$CTX" get vpol -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,MODE:.spec.policy.mode,PHASE:.status.phase,PROFILE:.status.profileName'
kubectl --context "$CTX" get vcpol \
  -o custom-columns='NAME:.metadata.name,MODE:.spec.policy.mode,PHASE:.status.phase,PROFILE:.status.profileName'

# 目标对象（控制器）。作用域二选一，勿照抄 -n：
#   VP:  -n <ns>      VCP: -A
kubectl --context "$CTX" get <deploy|sts|ds> <target> -n <ns> \
  -o jsonpath='{.spec.template.spec.containers[*].name}{"\n"}'
# VCP 按 name：namespaced GET 无法跨 ns，须用列表 + field-selector（输出含 ns/name）
kubectl --context "$CTX" get <deploy|sts|ds> -A \
  --field-selector metadata.name=<target> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}'
# Pod 按 name。VP 可直接 GET；VCP 必须跨 namespace 列表查询，不能把 NAME 与 -A 混用
kubectl --context "$CTX" get pod <target> -n <ns> \
  -o jsonpath='{.spec.containers[*].name}{"\n"}'
kubectl --context "$CTX" get pods -A --field-selector metadata.name=<target> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'

# PodTemplate Annotation 只列键名，不输出值（VP: -n / VCP: -A）
kubectl --context "$CTX" get <workload> [-n <ns>|-A] \
  -o go-template='{{range $k,$v := .spec.template.metadata.annotations}}{{$k}}{{"\n"}}{{end}}'
```

发现相关 Annotation 键后，将完整工作负载 YAML 只写入权限 `0700` 的本地运行目录，并在本地完成
`unconfined` 等值判断；对话中只报告布尔结论和相关键名，不输出 Annotation 值或完整资源 JSON。
selector 匹配需要的 label 值同样只在本地处理，对话仅展示命中对象身份和数量。

同时读取目标容器的实际 SecurityContext。控制器查看
`.spec.template.spec.{securityContext,containers[*].securityContext}`，Pod 查看
`.spec.{securityContext,containers[*].securityContext}`。将声明与策略做静态冲突检查：

- `capabilities.add` 中的能力与 `disable-cap-*` 对照。例如显式添加 `SYS_ADMIN`，同时选择
  `disable-cap-sys-admin`，应在最终确认时单列。
- `runAsUser: 0` 只说明以 root 身份运行，不能单独证明某项 capability 必需。
- 静态冲突是风险提示，不自动删除规则，也不在观察模式下一律阻断。说明两种收敛方向：移除工作
  负载不必要的 capability 后保留规则；或由后续运行时证据证明业务确有需要，再移除对应规则。
- 对 `privileged: true`、现有 Seccomp/AppArmor 配置以及 unconfined 覆盖单独说明影响。

按实际 Pod 所在节点定位 vArmor agent。不要猜 label，也不要把仅按 `nodeName` 得到的多个 Pod 名
直接传给 `kubectl exec`：

```bash
# 先发现 agent DaemonSet。上游 Helm 默认 component label 为 varmor-agent，但名称可配置。
kubectl --context "$CTX" get ds -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,CONTAINERS:.spec.template.spec.containers[*].name,IMAGE:.spec.template.spec.containers[*].image'

# 确认 AGENT_NS/AGENT_DS 后，在目标节点列出 Pod 及 owner。
# 不把 DaemonSet LabelSelector 手工转换成 -l，以免遗漏 matchExpressions。
kubectl --context "$CTX" get pods -n "$AGENT_NS" \
  --field-selector spec.nodeName=<node> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].kind}{"/"}{.metadata.ownerReferences[0].name}{"\t"}{.status.containerStatuses[*].ready}{"\n"}{end}'
```

`kubectl` JSONPath 支持 `?()` 等值过滤，但不支持正则过滤；无论使用 JSONPath、label selector
还是 field selector，都必须输出分隔符。从结果中只接受 owner 精确等于
`DaemonSet/$AGENT_DS` 的 Pod，并验证最终恰好得到一个 Ready agent。再从 DaemonSet 读取实际
容器名，后续 `exec` 显式使用 `-c "$AGENT_CONTAINER"`。

分别探测各能力。每项命令自行转成 `supported`、`unsupported` 或 `unknown`，不得因一个路径不可读
让其他能力的证据一起失败：

进入特权 agent 前，根据已有会话授权设置 `L4_AUTHORIZED=yes`；未获授权使用已有节点只读通道，
或记录能力 unknown。不能因环境变量为空就跳过后宣称探测成功。

```bash
# AppArmor：Y=supported，N=unsupported，文件不可读=unknown
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'printf "apparmor="; if [ -r /sys/module/apparmor/parameters/enabled ]; then cat /sys/module/apparmor/parameters/enabled; else echo unknown; fi'

# BPF LSM：能读取且包含 bpf=supported；能读取但不含=unsupported；不可读=unknown
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'printf "lsm="; if [ -r /sys/kernel/security/lsm ]; then cat /sys/kernel/security/lsm; else echo unknown; fi'

# Seccomp：actions_avail 可读是较强的内核支持证据；不可读时再查看当前进程状态作为降级证据
[ "$L4_AUTHORIZED" = "yes" ] && kubectl --context "$CTX" exec -n "$AGENT_NS" "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c 'if [ -r /proc/sys/kernel/seccomp/actions_avail ]; then printf "actions_avail="; cat /proc/sys/kernel/seccomp/actions_avail; else printf "actions_avail=unknown\n"; fi; awk '\''/^Seccomp:|^Seccomp_filters:/{print}'\'' /proc/self/status 2>/dev/null || true'
```

节点 enforcer 能力判读：

- AppArmor：`parameters/enabled` 须为 `Y`（仅目录存在不等于启用）。
- BPF：`/sys/kernel/security/lsm` 须包含 `bpf`，并确认 agent 已启用 BPF enforcer（不能只看内核版本）。
- Seccomp：`actions_avail` 可读并列出 action，说明内核提供 Seccomp filter；`/proc/self/status`
  的 `Seccomp` 值只表示当前 agent 进程是否处于 Seccomp 模式，值为 `0` 不能解释为内核不支持。
- 任一探测为 `unknown` 时如实展示；不要把查询失败解释为 `unsupported`，也不要覆盖其他已取得的
  AppArmor/BPF 证据。
- 探测结果仅用于检查用户所选 Enforcer 是否可用，不得反向替用户选择 Enforcer 或扩充规则集合。

逐项核对：

- name 或 selector 命中目标对象（**零命中要明确告知**）；`containers` 名称在 PodTemplate/Pod 中真实存在。
- 目标无 `unconfined` 注解覆盖；需要时确认 vArmor 生效标签。
- 承载节点上的 agent Ready，且节点按上述证据支持声明的 enforcer。

作为**观察模式**策略，零命中/不确定时以**警告 + 用户确认**决定是否继续（不一律阻断）；
但若会导致“策略看似下发、实际不保护任何容器”，必须先讲清后果，不能当作已就绪。

## 1.4 防覆盖检查（新建语义）

先确认同名对象是否存在（VP 带 `--context "$CTX" -n <ns>`；VCP 不带 namespace）：

```bash
kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>]
```

- **不存在（真新建）**：使用 `kubectl create`，避免 `apply` 覆盖。
- **已存在**：停止；这属于阶段二（更新）场景，请用户明确选择走更新流程，不在此覆盖。

## 1.5 dry-run、展示、确认与创建

若预检已固定 `$CTX`，从确认记录恢复同一个值，不用新的 current context 替换；用户跳过预检时，
在这里读取并确认目标 context。server dry-run 不产生变更，直接使用已校验的规范化文件，不重复
做 hash verify：

```bash
if [ -z "${CTX:-}" ]; then
  CTX="$(kubectl config current-context)" || exit 1
fi
test -n "$CTX" || exit 1
kubectl --context "$CTX" cluster-info || exit 1
kubectl --context "$CTX" create \
  -f "$RUN_DIR/1.2.1-normalized.yaml" --dry-run=server || exit 1
```

向用户展示：

- 完整 `1.2.1-normalized.yaml` 的本地文件路径与 `POLICY_SHA256`；对话中只展示脱敏策略摘要，不输出
  Annotation 值、`managedFields` 或 `status`；
- **结构化 diff / 变更摘要**（新建：说明将创建的对象与规则清单、生效范围）；
- adjustments、notices、RawRules 检查结果、预检结论；
- 预检证据来源（cluster-verified / user-provided / not-checked）；
- 将创建到的集群（`$CTX`）/ namespace / name。

**观察模式措辞**：进入观察模式的是**内置规则与基线**（只记录不拦截）；**自定义 RawRules 的动作
保持原语义**——其中 `deny`、阻断型 Seccomp action（除 `ALLOW/LOG` 外，含 ERRNO/KILL*/TRAP/
TRACE/NOTIFY）、NetworkProxy defaultAction=deny 仍会真实拦截。对这类阻断型 RawRules 必须向用户
单独点明并确认。

用户明确确认目标集群与内容后，在唯一真正变更点校验 hash 并创建：

```bash
python3 scripts/hash_policy.py verify \
  --file "$RUN_DIR/1.2.1-normalized.yaml" --hash "$POLICY_SHA256" \
  && kubectl --context "$CTX" create -f "$RUN_DIR/1.2.1-normalized.yaml"
```

## 1.6 校验下发结果（VP/VCP 分别处理）

1. 先读取策略回写的身份与 `status.profileName`（VP 带 `-n`，VCP 不带）：
   ```bash
   kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] \
     -o jsonpath='{.status.profileName}{"\n"}{.status.phase}{"\n"}{.status.conditions}'
   ```
2. 按 `profileName` 在**精确 namespace** 查同名 ArmorProfile（不要用 `-A | grep` 以免误匹配）：
   - VP：位于策略 namespace。
   - VCP：策略无 namespace，ArmorProfile 位于 **vArmor 系统 namespace**。
   ```bash
   kubectl --context "$CTX" get armorprofile <profileName> -n <ap-namespace> \
     -o jsonpath='{.status.desiredNumberLoaded}{"/"}{.status.currentNumberLoaded}{"\n"}{.status.conditions}'
   ```
3. **自行轮询**（不要用 `kubectl wait --for=condition=Ready`：全部成功时 ArmorProfile 可能没有
   Ready condition，wait 会必然超时）。成功标准同时满足：
   - `desiredNumberLoaded > 0`
   - `currentNumberLoaded == desiredNumberLoaded`
   - 没有失败节点的 condition
   - `0/0` 视为未知/未实际加载，不算成功。
4. 告知生效边界：控制面创建成功 ≠ 现有 Pod 已被保护；target 为 Pod 或未开
   `updateExistingWorkloads` 时需用户手动重建；Seccomp/注入变化需新 Pod。
5. 引导下一步：让业务充分运行（启动/发布/扩缩容/定时任务），再进入阶段二读取违规日志收敛。

## 1.7 建立任务记录

策略实际加载且需要的新 Pod 就绪后，先从 API Server 读取实际对象并创建观察起点快照。脚本在
快照中写入本地 epoch `capturedAt`；观察窗口 `start` 必须取不早于该值的时间：

```bash
(set -o pipefail
 kubectl --context "$CTX" get <vpol|vcpol> <name> [-n <ns>] -o yaml \
   | python3 scripts/hash_policy.py snapshot \
   > "$RUN_DIR/1.7-policy-snapshot.json") || exit 1

(set -o pipefail
 kubectl --context "$CTX" get daemonset,pods -n "$AGENT_NS" -o json \
   | python3 scripts/build_agent_inventory.py \
       --cluster-snapshot - \
       --daemonset-name "$AGENT_DS" \
       --daemonset-namespace "$AGENT_NS" \
   > "$RUN_DIR/1.7-agent-inventory.json") || exit 1
find "$RUN_DIR" -type d -exec chmod 700 {} + || exit 1
find "$RUN_DIR" -type f -exec chmod 600 {} + || exit 1
```

快照记录 `capturedAt`、kind/namespace/name、UID、generation、resourceVersion、
`status.profileName` 与 spec 哈希。resourceVersion 可能仅因 status 回写变化；阶段二会记录其
变化，但以 UID、generation 和 spec 哈希判断观察期间是否发生影响归因的策略漂移，并强制校验
`start >= policySnapshot.capturedAt`。起点 agent inventory 同时记录 DaemonSet 身份、调度计数、
全部 owned Pod/节点/UID 和自身 `capturedAt`；`start` 也必须不早于该时间。然后与用户商定固定
结束时间 `end`。任务记录中的 `start/end` 统一保存 epoch 秒；若用户使用 ISO8601 展示，保留
原值但只做一次带时区转换：

- 周期过短可能覆盖不到启动、发布、扩缩容、故障切换和低频定时任务。
- 周期过长可能遇到 violations.log 轮转覆盖，也会增加单次分析量。
- 对能够主动触发主要行为的测试业务，可先建议约两小时；业务量低、存在低频任务时适当延长，
  违规速率高或接近日志轮转容量时适当缩短。智能体可结合现场证据给出具体建议，最终由用户确认。
- 通常建议完成 3～5 个观察周期，但当代表性行为已覆盖且近期周期没有新的确定删除项时可以提前
  结束；覆盖不足时也可继续更多周期。

确认起点 inventory 完整、`start` 不早于两份证据的 `capturedAt`，并与用户确认窗口后，按
[任务模板](../templates/observation-task.json) 保存任务记录。推荐约定：

- VP：`vpol-<namespace>-<name>--<start>--<plannedEnd>.json`
- VCP：`vcpol-<name>--<start>--<plannedEnd>.json`

```bash
TASKS_DIR="<task-root>/varmor-policy-optimization/<cluster-context-safe>"
install -d -m 700 "$TASKS_DIR" || exit 1
TASK_FILE="$TASKS_DIR/<task-id>.json"
```

具体位置和命名可结合执行环境调整；保持任务路径持久、`taskId` 稳定，并能区分集群、策略和原
计划窗口即可。若采用上述命名，`taskId` 与文件名主体一致；后续提前结束只更新内容，不改文件名
或路径。同一任务 ID 已存在时读取现有记录，不覆盖创建新任务。任务目录建议 `0700`，任务记录
建议 `0600`。

任务初始 `plannedEnd` 和 `end` 相同，状态为 `observing`，并引用当前策略运行目录中的快照与起点
inventory 绝对路径。任务记录成功落盘即表示本轮优化任务已建立；将其完整路径告知用户。批量处理
时为每个策略和窗口分别建立记录。

新任务默认按 [观察期增量采集](../references/incremental-collection.md) 启动本地采集器。
协商 start 时为初始化留出时间；保持已确认的窗口，脚本在 start 前就绪后再让用户运行约定业务。
同时说明节点扩缩容、agent 替换或 DaemonSet desired/current 数变化会阻断本窗口的整策略删除，
已有证据仍可只读分析；需要完整删除资格时，在拓扑稳定后另建窗口。
采集器范围和限额应简要说明，已有授权覆盖 agent 只读访问时不重复审批。它将运行目录写入任务的
`outputs.collectorDirectory`，每 30 秒读新增日志，到 end 自动生成 `outputs.preFile`，不需要模型
逐节点取日志、等待定时触发后才抓全量历史。无法持续运行本地进程时，明确使用旧快照回退及其
轮转覆盖限制。collector 必须在 start 前完成全部节点初始化；新启动已到 start 或初始化跨过
start 时立即停止，重新协商窗口或明确走快照回退，不宣称有完整观察证据。

任务记录是可更新的状态索引，引用的快照与 inventory 是不可改写的起点证据。后续定时任务、
提醒或用户手动触发都读取同一任务记录：

- 支持一次性定时任务时，可让它在 `end` 后携带任务记录路径触发阶段二，先确认采集器已完成
  末次读取和自动预处理，再读取 pre.json 归因，不开启第二份采集；
- 只能提醒时，提醒内容携带任务记录路径；
- 均不支持时，用户随时可以用任务记录路径手动继续。

触发方式写入 `trigger`，只是入口元数据，不影响任务是否成立。增量采集到期只自动生成预处理输入；自动触发适合读取它并生成归因
汇总；向用户说明归因结果并取得删除范围决定后，再生成候选策略，且不自动 apply。
