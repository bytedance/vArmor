# vArmor 架构与诊断地图

## 1. 系统定位

vArmor 是 Kubernetes Operator 风格的云原生容器加固系统。用户通过 VP/VCP 声明目标、enforcer、模式和规则；manager 将用户意图编译成 AP/Profile；agent 在节点加载执行；Webhook 负责在 Admission 阶段把 Profile 和代理相关设置注入目标工作负载。

它的安全边界是“工作负载级、节点内核/运行时级和应用出口级”的组合，不是硬件虚拟化容器。

## 2. 组件与责任

| 组件 | 角色 | 关键责任 | 典型影响范围 |
|---|---|---|---|
| `varmor-manager` | 控制面 Deployment | 监听 VP/VCP、校验与 reconcile、生成 AP/Profile、管理 Webhook、处理行为建模结果和 NetworkProxy 配置传播 | 集群级或策略级 |
| `varmor-agent` | 节点数据面 DaemonSet | 监听 AP，在节点准备 AppArmor/BPF/Seccomp 所需对象，向 AP status 回报加载结果，输出审计事件 | 单节点及其上的目标 Pod |
| `varmor-classifier` | 行为建模辅助组件 | 识别/归一化路径中的随机元素，辅助跨节点行为数据建模 | 仅 BehaviorModeling |
| Mutating Webhook | Admission 变更面 | 对匹配的 Workload/Pod 注入 Profile 引用和 NetworkProxy sidecar/initContainer | 新建/更新请求 |
| Validating Webhook | Admission 校验面 | 校验策略目标、模式、enforcer、NetworkProxy 配置和不可变字段 | VP/VCP 写入请求 |
| Kubernetes API/kubelet/runtime | 运行链路 | 保存 CRD、调度 Pod、读取 SecurityContext、加载 Localhost Profile | 集群/节点/Pod |
| Linux 内核/LSM/audit | 执行面 | 实际执行 AppArmor/BPF/Seccomp 约束和审计 | 节点/进程 |
| Envoy sidecar | NetworkProxy 数据面 | 透明接收出口流量并执行 L4/L7/SNI/HTTP/TLS MITM 规则 | Pod 出口 |

## 3. 端到端对象链

```text
VP / VCP
  └─ spec.target + spec.policy
       │ manager reconcile / validating webhook
       ▼
status.profileName + ArmorProfile
       │ agent per-node processing
       ▼
AppArmor / BPF / Seccomp profile + NetworkProxy Secret/config
       │ mutating webhook adds references and, for NetworkProxy, init/sidecar/volumes
       ▼
Pod admitted → scheduled → kubelet/runtime creates container
       │
       ▼
node enforcement + audit event → agent/manager status and user-visible behavior
```

## 3.1 Workload 生命周期与观察点

策略作用于 Workload 的 PodTemplate，但安全设置最终存在于具体 Pod。应按以下关系理解运行态对象：

```text
Deployment / StatefulSet / DaemonSet
  └─ PodTemplate
       └─ ReplicaSet 或控制器创建 Pod
            └─ Admission 注入后的最终 PodSpec
                 └─ 调度到节点 → kubelet/runtime 创建容器
```

- Deployment、StatefulSet、DaemonSet 的控制器只会按各自的更新语义创建或替换 Pod；策略更新成功不等于旧 Pod 已更新。
- PodTemplate 已有注入而实际 Pod 没有，通常指向滚动更新未发生、Pod 属于旧 ReplicaSet，或 Pod 并非由该模板创建。
- 实际 Pod 已注入而新 Pod 未注入，应比较两者创建时间、ownerReferences、模板 hash、Webhook 匹配范围和策略生效时刻。
- 裸 Pod 没有上层 Workload 控制器，策略更新、删除或 Webhook 恢复通常不会替它完成生命周期迁移。

因此，诊断“策略是否生效”至少要分别观察：策略对象、AP、Workload PodTemplate、实际 Pod、目标节点和运行时事件。

几个容易混淆的点：

- AP 是 vArmor 内部执行对象，不是用户的策略入口；AP status 的节点条件比 VP Ready 更接近落地故障。
- Workload 的 PodTemplate 与实际已运行 Pod 是两个观察点；模板没有注入，后续 Pod 通常不会受保护；模板已注入但旧 Pod 未重建，也可能仍未使用新设置。
- 新增 enforcer 的策略更新并不自动使已有 Workload 获得该 enforcer；必须核对实际 Pod 注入状态。
- Seccomp Profile 的变更需要 Workload 重启才会对已运行容器生效；其他更新也要按实际 enforcer 和 Pod 生命周期验证。

## 4. 影响面判断

- manager 无可用 Leader：策略 reconcile、Webhook 服务能力和集群范围控制面受影响。
- manager 非 Leader 副本短暂异常：通常由其他副本承接，不应直接判定全局故障。
- Webhook 配置缺失、Service 无 Endpoint、TLS/CA 不匹配或 selector 不匹配：可能导致策略写入失败，或目标 Workload 未注入。
- 单节点 agent 缺失/不健康：优先判定为节点局部故障；该节点上的 AP 可能不 Ready，目标 Pod 可能创建失败或无加固。
- classifier 异常：通常只影响 BehaviorModeling 数据采集。
- NetworkProxy sidecar/initContainer/Secret/证书链异常：可能表现为 Pod 创建失败、代理未 Ready、出口连接失败或 HTTPS L7 规则不生效。

## 5. 健康基线

1. manager 有稳定 Leader，reconcile 没有持续错误；
2. agent 覆盖应覆盖节点，并能处理 AP；
3. classifier 仅在启用行为建模时部署，且覆盖建模节点；
4. Mutating/Validating Webhook 配置、Service、Endpoint、证书和匹配范围一致；
5. VP/VCP 的 `status.ready`、`conditions`、`phase` 与目标阶段一致；
6. AP 的 `desiredNumberLoaded` 与 `currentNumberLoaded` 一致，失败节点条件为空；
7. 目标 Workload/Pod 的 selector、label、container 范围和显式绕过设置符合预期；
8. 节点 kernel、LSM、BTF、containerd、kubelet 和 Profile 存放/挂载能力满足所选 enforcer；
9. NetworkProxy 目标 Pod 的 sidecar、init、Secret、端口、UID、证书和代理状态一致。

## 6. 诊断优先级

1. Pod 是否存在、是否已调度；
2. Pod/Workload 是否带 vArmor 注入痕迹；
3. VP/VCP target 与 policy 是否匹配；
4. `profileName` 对应 AP 是否存在且节点加载数完整；
5. 目标节点 agent、内核/LSM/运行时是否健康；
6. 运行时拒绝事件是否与 enforcer、Profile、Pod UID、时间一致；
7. 若 NetworkProxy，额外验证 sidecar、init、Secret、证书和出口规则。
