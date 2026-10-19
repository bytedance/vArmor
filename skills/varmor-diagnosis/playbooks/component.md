# 组件健康检查（Component）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
判断 vArmor 控制面（manager）和数据面（agent/classifier）是否真正可用。注意：Running ≠ 功能健康。

## 适用场景
- 概览发现组件未就绪、重启或异常
- 策略不下发、AP 不生成
- Webhook 调用失败

---

## 1. manager 控制面

### 1.1 Pod 状态与重启原因

```bash
# 查看 manager Pod 列表（<manager-pod-selector> 是完整 label selector，如 app.kubernetes.io/name=varmor-manager，从实际 Deployment 获取）
kubectl -n <varmor-namespace> get pods -l <manager-pod-selector> -o wide

# 对异常 Pod 查看 lastState 和事件（替换 <pod-name>）
kubectl -n <varmor-namespace> describe pod <pod-name> | grep -A 20 "Last State\|Events:"

# 查看最近重启的退出码和原因
kubectl -n <varmor-namespace> get pods -l <manager-pod-selector> -o jsonpath='{range .items[*]}POD={.metadata.name}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}STATE={.state}{"\t"}LAST_STATE={.lastState}{"\n"}{end}{end}'
```

**重点关注字段：**
| 字段 | 含义 |
|---|---|
| `lastState.terminated.exitCode` | 退出码是方向线索；137 需结合 reason/事件确认 OOM，1/2 的含义以组件日志为准 |
| `lastState.terminated.reason` | OOMKilled/Error/Completed |
| `lastState.terminated.finishedAt` | 上次退出时间，判断是否频繁重启 |
| `conditions[?(@.type=="Ready")].status` | 是否真正 Ready |
| `containerStatuses[*].ready` | 容器就绪状态 |

**判读规则：**
- CrashLoopBackOff + exitCode=1 → 启动错误，优先查日志
- OOMKilled → 资源不足，检查 resources.limits 和行为建模数据量
- ImagePullBackOff → 镜像/仓库/网络问题
- Running 但 Ready=False → 结合启动时间、探针、事件和日志区分初始化与持续失败，按需短时复查

### 1.2 Leader Election

Lease 名称和 holderIdentity 格式以实际部署为准。已知 Lease 时直接查询；未知时可列出
组件 namespace 的 Lease 摘要，并结合 manager 配置、Pod 身份与日志确认。

```bash
kubectl -n <varmor-namespace> get leases -o custom-columns='NAME:.metadata.name,HOLDER:.spec.holderIdentity,RENEW:.spec.renewTime,DURATION:.spec.leaseDurationSeconds'
```

模型可根据 holderIdentity 与候选 Pod 的名称、UID、配置和日志判断，不要求特定字符串解析算法。
Leader 未确定时标记未知，仍可读取少量相关 manager 副本的有限日志；启动、Webhook 和异常退出
不必以 Leader 身份确认为前提。不能将未找到匹配 Lease 直接解释为无 Leader，应确认是否启用
选举、Lease 命名/作用域、读取权限和续租情况。超时结合实际选举配置与观察时间判断，不使用
固定 15/10 秒或等待时长作为通用结论。

### 1.3 RBAC 与权限

```bash
# 检查 manager ServiceAccount 和 RBAC
kubectl -n <varmor-namespace> get sa <manager-serviceaccount-name> -o yaml --ignore-not-found
kubectl get clusterrolebindings -o wide | grep <manager-serviceaccount-name>
kubectl get clusterroles | grep varmor
```

**判读规则：**
- RBAC 缺失 → manager 日志会出现 `forbidden` 或 `cannot list/watch` 错误

### 1.4 manager 日志

选择异常实例，或与目标策略/Admission 请求相关的实例；reconcile 问题优先 Leader。
无法唯一定位时允许在少量候选上按同一时间窗取证，标明实例，不盲选首项或要求用户手工设置变量。

```bash
kubectl -n <varmor-namespace> logs <manager-pod> -c <manager-container> --since=<duration> --tail=300
# 重启相关时读取 --previous；可对已获得片段本地筛选 error/failed/panic 或目标策略身份。
```

**重点关注日志关键词：**
| 关键词 | 含义 |
|---|---|
| `Reconciler error` | 策略 reconcile 失败 |
| `failed to create/update ArmorProfile` | AP 生成失败 |
| `webhook` + `certificate`/`tls`/`x509` | 证书问题 |
| `cannot list`/`forbidden` | RBAC 权限问题 |
| `leader election lost` | Leader 丢失，可能触发重选 |
| `out of memory`/`OOM` | 内存不足 |

---

## 2. agent 数据面

### 2.1 DaemonSet 覆盖

```bash
# 查看 agent DaemonSet 状态
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='DESIRED={.status.desiredNumberScheduled}\tREADY={.status.numberReady}\tAVAILABLE={.status.numberAvailable}\tUNAVAILABLE={.status.numberUnavailable}{"\n"}'

# 查看 Pod Ready、重启与调度情况；Running 不能代替 Ready
kubectl -n <varmor-namespace> get pods -l <agent-pod-selector> -o wide
```

### 2.2 节点未覆盖原因

```bash
# 查看 agent DaemonSet 的 tolerations、nodeSelector、affinity
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.tolerations}'
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.nodeSelector}'
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.affinity}'

# 查看目标节点上的事件（替换 <node-name>）
kubectl describe node <node-name> | grep -A10 "Events:"

# 查看无法调度的 agent Pod 事件
kubectl -n <varmor-namespace> get pods -l <agent-pod-selector> --field-selector=status.phase=Pending -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\t"}{.status.conditions[?(@.type=="PodScheduled")].message}{"\n"}{end}'
```

**常见未覆盖原因：**
- 节点有未容忍的污点（如 `node-role.kubernetes.io/master`、`node.kubernetes.io/not-ready`）
- nodeSelector/affinity 不匹配
- 节点资源不足
- hostPath 挂载失败（检查节点上对应目录是否存在）

### 2.3 agent 假活检查

Pod Running 但无法加载 Profile，这是最容易忽略的故障模式：

先把该节点 AP condition 与 agent 日志对应，再查看相关容器的安全上下文与挂载配置。
hostPath 和 volumeMount 要成对关联；泛词可以帮助定位候选卷，不能仅凭卷名判断内核可见性。

```bash
kubectl -n <varmor-namespace> get pod <agent-pod-on-node> -o jsonpath='{range .spec.volumes[*]}{.name}{"\t"}{.hostPath.path}{"\n"}{end}'
```

需要实际节点视图时，按 [node.md](node.md) 选用定向只读检查并复用结果；不要求统一的授权变量
或完整挂载体检。对话仅展示必要的脱敏路径信息。

### 2.4 agent 日志

```bash
# 查看特定节点已确认的 agent Pod 日志（Pod 名从 2.1/2.3 节的节点对应关系获取）
kubectl -n <varmor-namespace> logs <agent-pod-on-node> -c <agent-container> --since=<duration> --tail=200

# 过滤该节点 agent 的 Profile 加载失败日志，避免聚合所有节点
kubectl -n <varmor-namespace> logs <agent-pod-on-node> -c <agent-container> --since=<duration> --tail=500 | grep -iE 'failed|error|cannot load|profile|apparmor|bpf|seccomp'
```

**重点关注日志关键词：**
| 关键词 | 含义 |
|---|---|
| `failed to load apparmor profile` | AppArmor Profile 加载失败，可能是语法/LSM问题 |
| `failed to load bpf` / `invalid argument` | BPF 程序加载失败，可能是内核/BTF/架构不兼容 |
| `failed to write seccomp profile` | Seccomp Profile 写入失败，可能是路径/权限问题 |
| `failed to process ArmorProfile` | AP 处理失败 |
| `permission denied` / `operation not permitted` | 权限不足，检查挂载和特权配置 |

---

## 3. classifier（仅 BehaviorModeling 场景）

```bash
# 检查 classifier 是否部署
CLASSIFIER_DS=$(kubectl -n <varmor-namespace> get ds <classifier-daemonset-name> -o name 2>&1)
if [ $? -eq 0 ]; then
  echo "$CLASSIFIER_DS"
  # 若部署了，检查覆盖状态和有限日志
  kubectl -n <varmor-namespace> get ds <classifier-daemonset-name> -o jsonpath='DESIRED={.status.desiredNumberScheduled}\tREADY={.status.numberReady}{"\n"}'
  kubectl -n <varmor-namespace> logs -l <classifier-pod-selector> --tail=200
else
  printf '%s\n' "$CLASSIFIER_DS"
  echo "CLASSIFIER_QUERY_FAILED: inspect the kubectl error; NotFound is normal only for non-modeling mode"
fi
```

**判读规则：**
- 未启用 BehaviorModeling 时 classifier 不存在 → 正常
- 建模场景下 classifier 未就绪 → 建模数据可能缺失或不完整

---

## 可选汇总要点
组件检查可汇总：
1. manager：副本数、Leader 身份与状态、重启原因（如有）、关键错误日志摘要
2. agent：节点覆盖差异、未覆盖原因（如有）、目标节点 agent 是否假活
3. classifier：部署状态（仅建模场景）
4. 明确的下一步方向（如：控制面 OK → 进策略链路；agent 节点异常 → 进节点检查）
