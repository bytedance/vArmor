# 策略链路查询（Policy）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
沿对象链验证策略编译环节：VP/VCP → status.profileName → 同名 AP → 节点条件。确认策略是否被 manager 接受、AP 是否生成、节点是否已处理。

## 适用场景
- 策略 READY=False / PHASE=Error/Failed
- 策略 Ready=True 但无目标防护
- AP 不存在或长期 Pending
- AP 部分节点未加载

## 前置依赖
- 已知策略类型：VP（namespace-scoped）或 VCP（cluster-scoped）
- 已知策略名、策略 namespace（仅 VP 需要）和待验证目标的 namespace
- 从概览中获取的 profileName（如有）

以下命令统一通过策略类型选择 scope；`TARGET_NAMESPACE` 始终表示当前待验证 Workload/Pod 的 namespace，不能与 VP 自身的 namespace 隐式混用。

```bash
POLICY_KIND=vp                  # 仅允许 vp 或 vcp
POLICY_NAME=<policy-name>
POLICY_NAMESPACE=<policy-namespace>  # VCP 时忽略
TARGET_NAMESPACE=<target-namespace>

case "$POLICY_KIND" in
  vp)
    POLICY_RESOURCE="varmorpolicies.crd.varmor.org"
    POLICY_NS_FLAG="-n $POLICY_NAMESPACE"
    ;;
  vcp)
    POLICY_RESOURCE="varmorclusterpolicies.crd.varmor.org"
    POLICY_NS_FLAG=""
    ;;
  *) echo "ERROR: POLICY_KIND must be vp or vcp"; return 1 2>/dev/null || exit 1 ;;
esac

policy_get() {
  kubectl $POLICY_NS_FLAG get "$POLICY_RESOURCE" "$POLICY_NAME" "$@"
}

policy_describe() {
  kubectl $POLICY_NS_FLAG describe "$POLICY_RESOURCE" "$POLICY_NAME"
}
```

---

## 1. VP/VCP 策略本体

### 1.1 策略状态摘要

```bash
policy_get -o jsonpath='KIND={.kind}\tNAME={.metadata.name}\tREADY={.status.ready}\tPHASE={.status.phase}\tGEN={.metadata.generation}{"\n"}PROFILE={.status.profileName}{"\n"}'
```

**重点关注字段：**
| 字段 | 判读 |
|---|---|
| `READY=true` | 所需 Agents 已处理 Profile，**不代表 Pod 已注入或已运行** |
| `READY=false` | 查看 conditions 和 phase 找原因 |
| `PHASE=Error/Failed` | 策略编译失败 |
| `PHASE=Pending` | 结合创建/更新时间、conditions 与 reconcile 日志区分正常等待和持续失败 |

当前公开 API 的 VP/VCP status 不包含 `observedGeneration`，不能用 generation 对比证明 manager 是否已处理最新 spec。应结合 `metadata.generation`、conditions 的更新时间、phase/profileName 变化、事件和 manager reconcile 日志判断。

### 1.2 Conditions 详情

```bash
policy_get -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

**Condition 类型与含义：**
| Condition Type | True 含义 | False 原因排查方向 |
|---|---|---|
| `Created` | AP 已创建 | manager reconcile 失败、CRD 问题、RBAC |
| `Updated` | AP 已同步到最新版本 | 策略更新后 AP 未更新 |
| `Ready` | 所需 Agent 已响应 | 节点未加载，查看 AP node conditions |

### 1.3 策略 spec 验证

```bash
# target 配置（精确查看匹配条件）
policy_get -o jsonpath='TARGET_KIND={.spec.target.kind}{"\n"}NAME={.spec.target.name}{"\n"}SELECTOR={.spec.target.selector}{"\n"}CONTAINERS={.spec.target.containers}{"\n"}'

# policy 模式与 enforcer
policy_get -o jsonpath='ENFORCER={.spec.policy.enforcer}{"\n"}MODE={.spec.policy.mode}{"\n"}'

# 是否有 unconfined 标注或绕过设置（在目标上）
# 注意：unconfined 在目标 Workload/Pod 上，不在策略上
```

**target 验证清单：**
1. `kind` 是否为 Deployment/StatefulSet/DaemonSet/Pod 之一
2. `name` 和 `selector` 是否互斥且有一个存在
3. `selector` 格式是否合法（Kubernetes label selector 语法）
4. VP 的 namespace 是否与目标 Workload 一致
5. 是否有 VCP 可能覆盖同 namespace 的 VP（VCP 可能覆盖、合并或优先，需以实际版本语义确认）
6. 目标 Workload/Pod 是否带有 `<webhook-object-label>` 标签（默认匹配标签，以实际部署配置为准）

### 1.4 策略事件

```bash
# describe 会按 VP/VCP 的实际 scope 查询，避免把 cluster-scoped VCP 强行放入 namespace
policy_describe | grep -A30 "Events:"

# 结构化事件查询可保留更完整的排序结果；VCP 的关联事件可能出现在不同 namespace，因此跨 namespace 查询
POLICY_UID=$(policy_get -o jsonpath='{.metadata.uid}') ||
  { echo "POLICY_QUERY_FAILED: cannot read policy UID"; return 1 2>/dev/null || exit 1; }
case "$POLICY_KIND" in
  vp)
    EVENT_KIND=VarmorPolicy
    EVENT_SCOPE_FLAG="-n $POLICY_NAMESPACE"
    ;;
  vcp)
    EVENT_KIND=VarmorClusterPolicy
    EVENT_SCOPE_FLAG="-A"
    ;;
esac
kubectl $EVENT_SCOPE_FLAG get events \
  --field-selector "involvedObject.uid=$POLICY_UID,involvedObject.kind=$EVENT_KIND,involvedObject.name=$POLICY_NAME" \
  --sort-by='.lastTimestamp' ||
  echo "EVENTS_QUERY_FAILED: inspect RBAC, API connectivity, and event availability"
```

Kubernetes Event 保留时间有限，且 vArmor 版本不一定为每次 reconcile 生成 Event。查询为空不能证明策略没有报错，仍应以 conditions、phase、profileName 变化和 manager 日志为主证据。

---

## 2. ArmorProfile（AP）执行对象

### 2.1 AP 是否存在且状态正确

从策略 status.profileName 确认 AP 名称。官方实现中，VP 的 AP 通常在策略（业务）namespace，
VCP 的 AP 通常在 vArmor 组件 namespace；优先沿该关系定向查询，已有结果直接复用。
实际 namespace 不清时，可按名称跨 namespace 查询摘要，再结合策略身份与对象关系确认：

```bash
kubectl --context <context> get armorprofiles.crd.varmor.org -A \
  --field-selector 'metadata.name=<profile-name>' \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid'
```

这是列表查询，不使用 `get … -A <name>`。多条同名结果不能盲选首项；无权限或查询失败时保留
发现缺口，不把结果解释为 AP 不存在。scope 不清时可使用 API discovery 或定向查询 CRD；
scope 只说明是否需要 namespace，不能代替 namespace 的发现。

```bash
# Namespaced AP 使用已确认 namespace；Cluster-scoped 不传 -n。
kubectl -n <confirmed-ap-namespace> get armorprofiles.crd.varmor.org <profile-name> -o json
```

一次读取可本地提取加载计数、conditions 与策略关联，后续示例的 AP_NS_FLAG、PROFILE_NAME
由模型使用同一对象事实填写。NotFound、Forbidden 和连接失败分开表达。

**判读规则：**
- AP 不存在 → manager 未创建或已删除残留策略
- `DESIRED=0` → 当前期望响应的 agent 数为零；结合 agent 覆盖、reconcile 与 target/注入证据判断，不能仅由该值推出 target 未匹配
- `CURRENT < DESIRED` → 部分节点未加载，记录差异节点
- `CURRENT = DESIRED` 但 READY=false → 可能有节点加载失败，检查 conditions

### 2.2 AP 节点条件（失败节点定位）

```bash
# 列出所有失败节点条件（使用已确认的 AP scope）
kubectl $AP_NS_FLAG get armorprofiles.crd.varmor.org "$PROFILE_NAME" -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.nodeName}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}' | grep -v True
# 或更精确地查找 status=False 的条件
kubectl $AP_NS_FLAG get armorprofiles.crd.varmor.org "$PROFILE_NAME" -o json | python3 -c "
import sys, json
ap = json.load(sys.stdin)
for c in ap.get('status', {}).get('conditions', []):
    if c.get('status') != 'True':
        print(f\"NODE={c.get('nodeName','N/A')}\tTYPE={c.get('type')}\tSTATUS={c.get('status')}\tREASON={c.get('reason','')}\tMSG={c.get('message','')}\")
"
```

**失败条件常见原因：**
| Reason | 排查方向 |
|---|---|
| `AppArmorLoadFailed` | 节点 AppArmor LSM、Profile 语法、securityfs 挂载 |
| `BPFLoadFailed` | 内核版本/架构、BTF、BPF LSM、map/program 资源 |
| `SeccompWriteFailed` | kubelet 路径权限、Profile 内容、runtime 支持 |
| `ProfileProcessFailed` | agent 处理错误，查 agent 日志 |

### 2.3 AP 与策略版本一致性

```bash
# 检查 AP 的 label 是否关联到正确的策略 generation（使用已确认的 AP scope）
kubectl $AP_NS_FLAG get armorprofiles.crd.varmor.org "$PROFILE_NAME" -o jsonpath='{.metadata.labels}'
# 对比策略的 .metadata.generation 和 AP 创建时间
```

---

## 3. 匹配验证（target 是否命中目标）

优先按已有策略与目标对象确认实际匹配；复杂 selector 可使用下方脚本或等价 API 查询。先按 `target.kind` 限定唯一资源类型，再区分 `target.name` 与 `target.selector`。selector 是标准 `metav1.LabelSelector`，可能包含 `matchLabels`（多组 key=value）和 `matchExpressions`（集合操作：In/NotIn/Exists/DoesNotExist），不能假设为单一 key=value。

```bash
# 从 Skill 根目录执行。脚本只读取一个策略，并在明确指定的 TARGET_NAMESPACE 中
# 按 target.kind/name 或完整 LabelSelector 计算实际命中对象，不继续查询 AP、Pod 或节点。
if [ "$POLICY_KIND" = "vp" ]; then
  python3 scripts/match-policy-target.py \
    --kind vp \
    --name "$POLICY_NAME" \
    --namespace "$POLICY_NAMESPACE"
else
  python3 scripts/match-policy-target.py \
    --kind vcp \
    --name "$POLICY_NAME" \
    --target-namespace "$TARGET_NAMESPACE"
fi
```

脚本的 `POLICY` 和 `TARGET` 行保留策略身份、container 范围及原始匹配条件；`CANDIDATE` 行说明 API 侧候选是否通过完整 selector，并用 `failed` 标明未通过的条件；`MATCH` 行列出最终命中对象；`SUMMARY` 同时保留候选数、命中数与未命中数。`ERROR` 表示查询、结构或 selector 解析失败，不能解释为零命中。脚本不会检查 Webhook 匹配标签、unconfined 或 VP/VCP 重叠，这些仍需按下列检查点分别验证。

**关键检查点：**
1. target.kind/name/selector 是否真的命中了对应类型的目标
2. 目标 Workload/Pod 是否有 vArmor 匹配标签
3. 目标 container 是否在 `spec.target.containers` 范围内（空=全部 containers）
4. 是否存在 `<unconfined-annotation>` 等显式绕过 annotation
5. VCP 与 VP 的重叠处理是否符合实际版本语义

---

## 4. 已配置内置规则冲突分析

策略为 `EnhanceProtect` 且需要解释规则冲突、加载失败或业务行为受影响时，先对照实际规则与对应 enforcer 语义；复杂冲突元数据可借助脚本。脚本读取一个现有 VP/VCP 中已经配置的 built-in rules，不新增、删除或推荐规则，也不输出策略模板。

读取策略元数据属于 L0；读取相关 APM 行为样本按 L1 评估范围与敏感数据。不会触发新的行为采集；脚本仅输出命中维度、计数和执行文件 basename，文件完整路径始终脱敏。

```bash
# 在线读取一个 VP；VCP 使用 --kind vcp --name <name>，不传 --namespace
python3 scripts/analyze-built-in-rules.py \
  --kind vp \
  --namespace "$POLICY_NAMESPACE" \
  --name "$POLICY_NAME" \
  --features "mount-sth,require-sa" \
  --capabilities "sys_admin" \
  --apm-name <apm-name> \
  --apm-namespace <apm-namespace>

# 离线分析必须使用 kubectl -o json 导出的 JSON；APM 可省略
python3 scripts/analyze-built-in-rules.py \
  --policy-file <policy.json> \
  --apm-file <apm.json> \
  --features "" \
  --capabilities ""
```

`--features` 和 `--capabilities` 未传表示上下文未知，传空字符串表示已明确没有对应项。不要根据镜像名称猜测 feature/capability。APM 是有限时间行为样本，不是完整许可清单；脚本只输出命中的维度、计数和执行文件 basename，文件路径始终脱敏。

状态解释：

| 状态 | 含义 |
|---|---|
| `CONFLICT_DECLARED` | 显式 feature/capability 与 catalog 的冲突元数据相交 |
| `CONFLICT_OBSERVED` | 给定 APM 样本命中 capability/syscall/execution/file 冲突 |
| `NO_CONFLICT_OBSERVED` | 给定 APM 样本未命中；仅限样本，不能证明不存在冲突 |
| `APM_DATA_UNAVAILABLE` | 规则包含行为冲突条件，但没有 APM，不能伪装成无冲突 |
| `APPLICABILITY_NOT_ESTABLISHED` | 显式上下文不足以满足该规则的适用条件 |
| `UNSUPPORTED_BY_ENFORCER` | 策略 enforcer 与 advisor catalog 声明的规则 enforcer 无交集 |
| `UNASSESSED` | 规则不在 advisor catalog，或必要上下文/元数据不足 |
| `SUPPORTED` | 在给定证据范围内未建立冲突，且无需更多行为证据 |

`CONCLUSION status=REVIEW_REQUIRED` 或 `INTERPRETATION rule_layer=NOT_EXCLUDED` 表示规则层尚未排除，不能写成“问题不在规则层”或“规则配置无冲突”。内置 catalog 固定来源和 commit 记录在 `scripts/built-in-rule-conflicts.json`。运行时实现可能支持 catalog 尚未收录的新规则；这类规则必须输出 `UNASSESSED`，不能自行补造冲突条件。`CONCLUSION status=NO_CONFLICT_ESTABLISHED` 也只表示所给证据未建立冲突，不是策略安全性或业务兼容性的保证。

---

## 可选汇总要点
策略链路检查可汇总：
1. 策略基本状态：READY/PHASE/GEN 一致性
2. Conditions 异常项（reason + message）
3. AP 存在性与 DESIRED/CURRENT 差异
4. 失败节点列表和失败原因
5. target kind/name/selector 的实际匹配验证结果
6. 已配置规则的冲突状态（适用时）及证据边界
7. 明确断点在「匹配/编译/AP生成/节点响应」的哪一环
8. 下一步方向
