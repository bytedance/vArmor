# BehaviorModeling 专项检查（Behavior Modeling）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
排查行为建模场景的链路问题：采集 → 归一化 → 上报 → 汇总 → 持久化。建模只描述观察到的行为，不证明行为完整，也不自动等于安全许可清单。

## 适用场景
- 策略 mode=BehaviorModeling 但无数据
- 建模一直未完成
- APM（ArmorProfileModel）不存在或无数据
- 完成建模后切换模式失败
- classifier 异常

## 前置依赖
- 已知策略类型（VP/VCP）、策略名、VP 的 namespace，以及 vArmor 组件 namespace
- 已知建模 duration 和开始时间
- 目标 Workload 已在运行且产生行为

APM 与 `status.profileName` 同名，并沿已发现 AP 的 namespace 定位；VP 通常在策略 namespace，
VCP 通常在 vArmor 组件 namespace。未知时先按 policy.md 第 2.1 节定位 AP，再查询同 namespace
的 APM。下方 scope 示例可按已有结果调整，CRD scope 不单独证明对象所在 namespace。

使用 BPF enforcer 建模时，进入目标业务容器执行命令可能引入额外行为样本，优先 API 与已有
日志；必要 exec 应说明对样本的影响，不把诊断产生的行为当作原有业务行为。

```bash
POLICY_KIND=vp                  # 仅允许 vp 或 vcp
POLICY_NAME=<policy-name>
POLICY_NAMESPACE=<policy-namespace>  # VCP 时忽略
VARMOR_NAMESPACE=<varmor-namespace>

case "$POLICY_KIND" in
  vp)
    POLICY_RESOURCE="varmorpolicies.crd.varmor.org"
    POLICY_NS_FLAG="-n $POLICY_NAMESPACE"
    APM_NAMESPACE="$POLICY_NAMESPACE"
    ;;
  vcp)
    POLICY_RESOURCE="varmorclusterpolicies.crd.varmor.org"
    POLICY_NS_FLAG=""
    APM_NAMESPACE="$VARMOR_NAMESPACE"
    ;;
  *)
    echo "ERROR: POLICY_KIND must be vp or vcp"
    return 1 2>/dev/null || exit 1
    ;;
esac

policy_get() {
  kubectl $POLICY_NS_FLAG get "$POLICY_RESOURCE" "$POLICY_NAME" "$@"
}
```

---

## 1. 建模前置条件检查

### 1.1 containerd 与 BTF

从已确认目标 Pod 的 nodeName 检查相关节点 runtime；多节点问题先选择异常节点，按证据扩展。
BTF 等节点能力按 [node.md](node.md) 定向验证。优先 AP/agent 日志中的采集错误；必要时检查
一个已知 BTF 文件，不为建模故障进行完整节点体检。

```bash
kubectl get node <target-node> -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}{"\n"}'
```

从相关 DaemonSet owner、节点和容器确认 agent；未 Ready 不阻止状态/日志取证。
后续示例的 NODE_NAME、AGENT_POD 和容器由模型根据已有事实填写。

### 1.2 classifier 部署

```bash
# classifier 是否部署
CLASSIFIER_DS=$(kubectl -n "$VARMOR_NAMESPACE" get ds <classifier-daemonset-name> -o name 2>&1)
if [ $? -eq 0 ]; then
  echo "$CLASSIFIER_DS"
  # classifier 节点覆盖
  kubectl -n "$VARMOR_NAMESPACE" get ds <classifier-daemonset-name> -o jsonpath='DESIRED={.status.desiredNumberScheduled}\tREADY={.status.numberReady}{"\n"}'
  # 目标节点是否有 classifier
  kubectl -n "$VARMOR_NAMESPACE" get pods -l <classifier-pod-selector> --field-selector spec.nodeName="$NODE_NAME" -o wide
else
  printf '%s\n' "$CLASSIFIER_DS"
  echo "CLASSIFIER_QUERY_FAILED: inspect the kubectl error; distinguish NotFound from permission or connectivity failures"
fi
```

在当前部署实现中，如果 BehaviorModeling 依赖 classifier，则 classifier 缺失会导致建模链路不完整；应以实际版本架构、配置和日志确认 classifier 是否为必需组件。

### 1.3 审计来源配置

```bash
# 检查 agent 配置中审计/行为采集是否启用
# 查看相关 agent 的启动参数；可读取必要的非敏感开关值，凭据与端点按需脱敏
kubectl -n "$VARMOR_NAMESPACE" get ds <agent-daemonset-name> -o go-template='{{range .spec.template.spec.containers}}{{$name := .name}}{{range .args}}{{$name}}{{"\t"}}{{.}}{{"\n"}}{{end}}{{end}}' |
  grep -iE 'audit|behavior|model|bpf' |
  sed -E 's/(--[^=[:space:]]+)=.*$/\1=<redacted>/'
# 查看 agent ConfigMap 是否存在及键名（仅列键名，不输出 data 内容，ConfigMap 可能含内部端点/证书/凭据）
kubectl -n "$VARMOR_NAMESPACE" get cm -l <agent-pod-selector> -o go-template='{{range .items}}{{.metadata.name}}{{":"}}{{"\n"}}{{range $k,$v := .data}}  {{$k}}{{"\n"}}{{end}}{{end}}'
# 如需检查特定配置项，确认键名后定向查询：
# kubectl -n "$VARMOR_NAMESPACE" get cm <confirmed-cm-name> -o jsonpath='{.data.<confirmed-config-key>}'
```

---

## 2. 策略建模状态

```bash
# 建模策略状态
policy_get -o jsonpath='KIND={.kind}\tREADY={.status.ready}\tPHASE={.status.phase}{"\n"}DURATION={.spec.policy.modelingOptions.duration}{"\n"}PROFILE={.status.profileName}{"\n"}'

# conditions
policy_get -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

**建模阶段（phase）含义：**
| Phase | 含义 |
|---|---|
| `Pending` | 等待建模开始或条件不满足 |
| `Modeling` | 正在采集中 |
| `Completed` | 建模完成，APM 已生成 |
| `Error/Failed` | 建模失败 |

---

## 3. APM（ArmorProfileModel）检查

```bash
# APM 与策略 status.profileName 同名
APM_NAME=$(policy_get -o jsonpath='{.status.profileName}') ||
  { echo "POLICY_QUERY_FAILED: cannot read status.profileName"; return 1 2>/dev/null || exit 1; }
if [ -z "$APM_NAME" ]; then
  echo "PROFILE_NAME_EMPTY: policy has not reported status.profileName; stop APM queries"
  return 1 2>/dev/null || exit 1
fi
echo "APM namespace/name: $APM_NAMESPACE/$APM_NAME"

APM_JSON=$(kubectl -n "$APM_NAMESPACE" get armorprofilemodels.crd.varmor.org "$APM_NAME" -o json) ||
  { echo "APM_QUERY_FAILED: inspect the kubectl error and verify the namespace against the actual object"; return 1 2>/dev/null || exit 1; }
printf '%s' "$APM_JSON" | python3 -c "
import json, sys
apm = json.load(sys.stdin)
status = apm.get('status') or {}
print(f\"DESIRED={status.get('desiredNumber','')}\tCOMPLETED={status.get('completedNumber','')}\tREADY={status.get('ready','')}\")
print(f\"STORAGE_TYPE={apm.get('storageType','')}\")
for condition in status.get('conditions') or []:
    print(
        f\"NODE={condition.get('nodeName','')}\tTYPE={condition.get('type','')}\t\"
        f\"STATUS={condition.get('status','')}\tREASON={condition.get('reason','')}\t\"
        f\"MESSAGE={condition.get('message','')}\tLAST={condition.get('lastTransitionTime','')}\"
    )
"
```

**APM 存储类型注意：**
- `storageType` 是 APM 顶层字段；建模数据位于顶层 `data` 下
- APM 数据量过大时可能使用本地存储（`storageType=LocalDisk`）而非完整保存在 CRD 中
- 此时查询 `armorprofilemodels.crd.varmor.org` 可能看不到完整模型，需结合 manager 存储配置与日志判断

---

## 4. 建模三段链路排查

建模无数据时，按以下三段分别验证：

### 4.1 第一段：采集能力（节点侧）

```bash
# 目标节点 agent 日志中的采集错误
kubectl -n "$VARMOR_NAMESPACE" logs "$AGENT_POD" -c <agent-container> --since=<duration> --tail=300 | grep -iE 'modeling|audit|collect|bpf|behavior|error|failed'

# 日志不足时再按 node.md 检查已定位的 BPF 对象；不默认枚举全部程序。

# 目标 Pod 确实在产生行为（应用在运行）
kubectl -n <namespace> get pod <target-pod> -o jsonpath='PHASE={.status.phase}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}READY={.ready}{"\t"}RESTARTS={.restartCount}{"\n"}{end}'
# 如果目标 Pod 没有启动或一直崩溃，自然无行为可采集
```

**采集层问题：**
- BTF 不可用 → BPF 采集程序无法加载
- agent 未启用行为采集模式 → 检查配置
- 目标 Workload 未运行/无流量 → 无行为数据
- containerd 版本/配置问题 → 进程身份关联失败

### 4.2 第二段：归一化与上报（classifier）

结合目标节点与 classifier DaemonSet owner 确认相关实例，检查该容器 Ready、重启、
lastState 和资源。异常实例或升级中的旧实例可按故障时间取证，不要求唯一 Ready 才读取日志。

```bash
kubectl -n "$VARMOR_NAMESPACE" logs <classifier-pod> -c <classifier-container> --since=<duration> --tail=300
# 怀疑 OOM 时结合 lastState、resources 和事件；metrics 可用时按需 top 单个 Pod。
```

**上报层问题：**
- classifier 未覆盖目标节点 → 该节点行为数据丢失
- classifier OOM → 数据量大导致归一化失败
- classifier 到 manager 的网络不通 → 上报失败
- RBAC/权限不足 → classifier 无法上报数据

### 4.3 第三段：汇总与持久化（manager）

reconcile/汇总问题优先 manager Leader，身份按 component.md 发现。无法解析 Leader 时
可从少量相关实例的有限日志寻找证据，不要求用户手动确认后才能继续。

```bash
kubectl -n "$VARMOR_NAMESPACE" logs <manager-pod> -c <manager-container> --since=<duration> --tail=300
```

storageType=LocalDisk 且日志指向持久化失败时，确认存储挂载与目标文件再检查，优先文件元数据和
定向可读性检查；不扫描整个存储目录。必要访问按统一授权约定，不把普通容器身份自动当 L4。

**汇总层问题：**
- manager OOM → 跨节点数据汇总内存不足
- 存储权限问题 → APM 无法持久化
- manager reconcile 错误 → APM 未创建或更新

---

## 5. 建模完成后验证

已有 APM_JSON 可直接复用；需要确认状态变化时才重新读取。

```bash
# 建模完成后 APM 是否包含数据
if [ -n "$APM_NAME" ]; then
  # 仅判断实际模型字段是否非空，不输出可能包含路径等敏感行为数据的原文
  APM_JSON=$(kubectl -n "$APM_NAMESPACE" get armorprofilemodels.crd.varmor.org "$APM_NAME" -o json) ||
    { echo "APM_QUERY_FAILED: cannot inspect model data"; return 1 2>/dev/null || exit 1; }
  printf '%s' "$APM_JSON" | python3 -c "
import sys, json
apm = json.load(sys.stdin)
data = apm.get('data') or {}
dynamic_result = data.get('dynamicResult')
profile = data.get('profile')
print(f'APM has dynamicResult content: {bool(dynamic_result)}')
print(f'APM has profile content: {bool(profile)}')
"
fi
```

**⚠️ 建模完成≠防护就绪：**
- 建模只描述「观察到的行为」，不证明行为完整
- 短时间建模可能遗漏周期性行为（定时任务、低频操作）
- 完成建模后需要确认模式切换（DefenseInDepth）是否成功
- 不建议未经人工审查直接将建模结果用于 Deny-by-Default 策略

---

## 6. 建模后模式切换检查

```bash
# 从 BehaviorModeling 切换到 DefenseInDepth 后
# 1. 策略 phase 是否变为 Protecting
policy_get -o jsonpath='PHASE={.status.phase}{"\t"}READY={.status.ready}{"\n"}'

# 2. 确认当前 Profile/AP 及其配置变化，不以名称变化作为切换成功的必要条件
policy_get -o jsonpath='{.status.profileName}{"\n"}'

# 3. AP 是否加载成功
AP_NAME=$(policy_get -o jsonpath='{.status.profileName}')
# ArmorProfile 的 namespace 按 policy.md 第 2.1 节定位：优先 VP/VCP 关系，未知时按名称跨 namespace 查摘要
kubectl -n <confirmed-ap-namespace> get armorprofiles.crd.varmor.org "$AP_NAME" -o jsonpath='DESIRED={.status.desiredNumberLoaded}\tCURRENT={.status.currentNumberLoaded}{"\n"}'

# 4. 新 Pod 是否获得新 Profile 注入（需要滚动更新）
```

---

## 可选汇总要点
BehaviorModeling 检查可汇总：
1. 前置条件满足情况（containerd/BTF/classifier/审计配置）
2. 策略 phase 和 modeling duration/开始时间
3. APM 存在性和完成节点数
4. storageType（判断数据可见性）
5. 三段链路中哪一段有问题（采集/上报/汇总）
6. 各组件（agent/classifier/manager）的错误日志摘要
7. 目标 Workload 是否确实在产生行为
8. 若已完成，APM 数据可见性、观察覆盖缺口与模式切换状态
9. 下一步方向
