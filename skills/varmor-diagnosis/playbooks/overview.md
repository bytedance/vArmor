# 概览查询（Overview）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
快速判断故障影响范围：全局、单节点、单策略、单工作负载还是单容器。建立诊断优先级，避免无目标收集全量数据。

## 适用场景
诊断初期，尚未明确故障范围时使用。症状入口不明确时，先跑此 playbook 缩小范围。

## 前置依赖
- 已知目标 namespace（可选，若跨 namespace 问题可省略）
- 已知 vArmor 安装 namespace（<varmor-namespace>，必须先根据实际部署对象、Webhook Service 引用或相关控制器对象发现，不使用固定默认值）

---

## 1. vArmor 组件总览

判断控制面和数据面是否整体可用。

```bash
# 查看已确认组件范围；共享 namespace 时补充组件 selector，不列无关业务 Pod
kubectl -n <varmor-namespace> get pods -l <varmor-component-selector> -o wide

# 查看各组件期望/就绪数量
kubectl -n <varmor-namespace> get deploy <manager-deploy-name> -o jsonpath='{.status.replicas}/{.status.readyReplicas}/{.status.availableReplicas}' && echo
kubectl -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.status.desiredNumberScheduled}/{.status.numberReady}/{.status.numberAvailable}' && echo
CLASSIFIER_STATUS=$(kubectl -n <varmor-namespace> get ds <classifier-daemonset-name> -o jsonpath='{.status.desiredNumberScheduled}/{.status.numberReady}/{.status.numberAvailable}' 2>&1)
if [ $? -eq 0 ]; then
  echo "$CLASSIFIER_STATUS"
else
  printf '%s\n' "$CLASSIFIER_STATUS"
  echo "CLASSIFIER_QUERY_FAILED: inspect the kubectl error and distinguish NotFound from permission or connectivity failures"
fi
```

**重点关注字段：**
| 字段 | 含义 |
|---|---|
| `STATUS` | Pod 阶段（Running/Pending/CrashLoopBackOff/ImagePullBackOff） |
| `RESTARTS` | 重启次数，>0 需结合 lastState 判断 |
| `AGE` | 存活时间，过短可能是刚启动或反复重启 |
| `NODE` | 所在节点，用于判断单节点故障 |
| `replicas/readyReplicas` | manager 期望/就绪副本数 |
| `desiredNumberScheduled/numberReady` | agent/classifier 期望/就绪节点数 |

**判读规则：**
- manager 0 Ready → 控制面全局故障，先查 [component.md](component.md) manager 部分
- agent numberReady < desiredNumberScheduled → 存在未覆盖节点，故障可能局限于未就绪节点
- classifier 未部署 → 仅当使用 BehaviorModeling 时才异常
- 所有组件 Ready ≠ 功能健康，仍需继续下游检查

---

## 2. 策略总览

目标 namespace 已知时优先该范围；仅在范围不明或有全局异常证据时使用下方跨 namespace 摘要，发现异常后转向具体策略。

```bash
# 查看所有 VarmorPolicy 摘要（非全量 yaml，仅关键状态字段）
kubectl get varmorpolicies.crd.varmor.org --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.ready,PHASE:.status.phase,PROFILE:.status.profileName,AGE:.metadata.creationTimestamp'

# 查看所有 VarmorClusterPolicy 摘要
kubectl get varmorclusterpolicies.crd.varmor.org -o custom-columns='NAME:.metadata.name,READY:.status.ready,PHASE:.status.phase,PROFILE:.status.profileName,AGE:.metadata.creationTimestamp'

# 查看所有 ArmorProfile 加载状态
kubectl get armorprofiles.crd.varmor.org --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,DESIRED:.status.desiredNumberLoaded,CURRENT:.status.currentNumberLoaded,READY:.status.ready,AGE:.metadata.creationTimestamp'
```

**重点关注字段：**
| 字段 | 含义 |
|---|---|
| `READY` | 策略/Profile 是否就绪（bool） |
| `PHASE` | 阶段（Pending/Protecting/Modeling/Completed/Error/Failed） |
| `DESIRED/CURRENT` | AP 期望/当前加载节点数，不一致说明部分节点未加载 |

**判读规则：**
- 所有策略 Pending/Error → 全局控制面问题，回到组件检查
- 单策略 READY=False → 该策略链路问题，进 [policy.md](policy.md)
- AP CURRENT < DESIRED → 部分节点未加载，记录差异节点名，进 [node.md](node.md)
- 所有策略 Ready，但目标 Pod 异常 → 问题在注入或运行时环节，继续下游

---

## 3. Webhook 总览

判断 Webhook 配置是否存在且端点可用。

```bash
# 查看 Mutating/Validating Webhook 配置是否存在
kubectl get mutatingwebhookconfigurations | grep varmor
kubectl get validatingwebhookconfigurations | grep varmor

# 查看 Webhook Service 是否存在且有 Endpoint
kubectl -n <varmor-namespace> get svc | grep webhook
kubectl -n <varmor-namespace> get endpoints | grep webhook
```

关键词未命中只是未发现候选；再按 Service 引用和实际部署确认，不能直接认定不存在。

**判读规则：**
- 已确认相关 Webhook 配置不存在 → 可能是安装问题或升级残留
- Service 存在但 Endpoints 为空 → manager Pod 未就绪或 Service selector 不匹配
- Webhook 配置和端点均正常 → 不能排除匹配标签/规则问题，需进 [webhook.md](webhook.md) 细查

---

## 4. 范围判断决策树

根据以上结果快速定位下一步：

| 观察到的现象 | 影响范围 | 下一步 |
|---|---|---|
| manager CrashLoop/0 Ready | 全局 | → [component.md](component.md) manager 部分 |
| 单/多节点 agent 未 Ready | 节点级 | → [node.md](node.md) |
| 所有策略 Pending/Error | 全局 | → [component.md](component.md) → [policy.md](policy.md) |
| 单策略 READY=False | 策略级 | → [policy.md](policy.md) |
| 策略 Ready，AP 完整，但目标 Pod Pending | Pod 级 | → [workload.md](workload.md) → [webhook.md](webhook.md) |
| 策略 Ready，Pod Running 但行为异常 | 运行时 | → [workload.md](workload.md) → [audit.md](audit.md) |
| 涉及出口网络/代理 | NetworkProxy | → [networkproxy.md](networkproxy.md) |
| 涉及行为建模无数据 | Modeling | → [behavior-modeling.md](behavior-modeling.md) |

---

## 可选汇总要点
按实际采集结果选择相关项：
1. 哪些组件 Ready、哪些不 Ready
2. 多少策略 Ready、多少异常
3. 异常 AP 的节点差异
4. Webhook 是否存在且有端点
5. 初步判定的影响范围和下一步方向

不要在概览阶段收集全量日志、全量事件或逐个 Pod 描述。
