# VP/VCP 生命周期与 Kubernetes 生效边界

## 1. 对象职责

| 对象 | 作用域 | 目标范围 |
|---|---|---|
| `VarmorPolicy`（VP） | namespace | 仅同 namespace 的 Workload |
| `VarmorClusterPolicy`（VCP） | cluster | 可跨 namespace 选择目标 |

对象链：

```text
VP / VCP --manager reconcile--> ArmorProfile --node agent load--> 底层 Profile
--admission injection--> Pod 运行时配置
```

VP/VCP 是用户声明，ArmorProfile 是内部执行对象，二者职责不同。

## 2. target 语义

- `kind`：`Deployment`、`StatefulSet`、`DaemonSet`、`Pod`。
- `name` 与 `selector` 用于确定 Workload，二者**互斥**（必须且只能设置一个）。
- `selector` 遵循 Kubernetes LabelSelector（matchLabels / matchExpressions）。
- `containers` 指定覆盖的业务容器；空列表通常表示全部业务容器（不含 init / ephemeral）。
- Workload/Pod 上的 `unconfined` 设置可能让目标绕过相应 Profile。
- VP 受自身 namespace 限制，VCP 可跨 namespace。二者可能同时命中同一目标，最终以 manager
  实际调谐结果、生成的 ArmorProfile 与 Pod 实际安全配置为准。

**可变性**：`spec.target` 创建后不可变；`spec.policy.enhanceProtect` 内的规则可反复修改。
本 skill 只修改 enhanceProtect 内的规则，不改 target。

## 3. ArmorProfile 状态

- `desiredNumberLoaded`：应处理该 Profile 的 agent 数。
- `currentNumberLoaded`：已处理的 agent 数。
- `conditions`：节点级加载结果、reason、message。
- VP/VCP 的 `status.profileName` 连接策略与 ArmorProfile。
- `ready=true` 表示控制面与节点处理达到相应条件，**不等于**所有现存 Pod 都已引用新 Profile。

## 4. 生效边界（关键）

- 安全配置通常在 **Pod 创建时**由 Admission Webhook 注入。
- 策略/ArmorProfile 更新后，**已运行的容器不会重新执行 admission，也不会自动重载 Seccomp**。
- Deployment / StatefulSet / DaemonSet 需要产生新 Pod 才能获得新的 PodSpec；裸 Pod 需要重新
  创建。
- `spec.updateExistingWorkloads=true` 时，vArmor 在策略创建/删除时对 Deploy/STS/DS 执行滚动
  更新，同时要求 manager 启用 `restartExistWorkloads`；该开关为 false 或 target 为 Pod 时
  不会自动更新，需要用户自行重建。单纯更新 EnhanceProtect 规则不保证触发滚动，
  不能仅凭这个开关就开始下一轮 Seccomp 观察。
- AppArmor/BPF Profile 可由 agent 更新；Seccomp 已加载的 filter 不能靠修改 Profile 文件替换，
  必须确认必要的新容器已经启动，再记录新观察起点。

核验依据：上游 `v0.10.5` 的
[policy_controller.go](https://github.com/bytedance/vArmor/blob/v0.10.5/internal/policy/policy_controller.go)
与 [clusterpolicy_controller.go](https://github.com/bytedance/vArmor/blob/v0.10.5/internal/policy/clusterpolicy_controller.go)
在 add/delete 路径调用工作负载更新，普通规则 update 路径更新 ArmorProfile。

因此下发或更新成功后，必须向用户说明：控制面对象更新成功 ≠ 现有 Pod 已获得新 Profile；
Seccomp 与注入相关变化通常需要新 Pod。

## 5. 变更安全

本 skill 唯一会修改的对象是 VP/VCP CRD。任何下发/更新（以及因此触发的工作负载重启）在执行
前都要：保留完整本地 YAML 并提供路径与哈希，在对话展示脱敏摘要和结构化 diff，通过 server
dry-run，并取得用户对目标集群与变更内容的明确确认。失败关闭：下发失败、策略不存在、观察期
策略漂移、日志不完整、归因不确定、schema 失败、diff 含非删除变更、用户未确认时，都不修改、
不下发。
