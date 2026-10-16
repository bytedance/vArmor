# varmor-agent 节点数据面

## 职责

`varmor-agent` 以 DaemonSet 方式覆盖节点，监听 AP 并在本节点准备/加载 Profile，向 AP status 回报结果，同时参与违规审计和行为数据采集。它是判断“节点是否真正具备执行能力”的主要证据来源。

## DaemonSet 运行态设计

agent 的 DaemonSet 配置直接决定节点覆盖和内核可见性。重点关联 nodeSelector/affinity、tolerations、hostPath 或安全挂载、ServiceAccount/RBAC、资源限制、升级策略与目标节点状态：

- DaemonSet desired/current/ready 数量只能说明调度覆盖；具体节点仍需与 AP 的 node condition 和 Profile 加载结果对应。
- 未容忍系统节点污点、无法满足资源或亲和性条件，会形成“集群整体看似健康、单节点无法加固”的局部故障。
- hostPath、权限和内核接口挂载缺失，可能使 agent Pod Ready 但无法加载 Profile；这属于功能假活。
- agent 更新期间应区分旧 Pod 尚能执行的 Profile 与新节点尚未完成初始化的窗口，不能仅按 DaemonSet rollout 完成判断所有 AP 已恢复。

## 健康判定

按症状关联 agent 节点覆盖、Ready/重启/lastState、AP 加载计数与 node condition 和日志；涉及兼容或加载错误时再补充相关内核、LSM、BTF、runtime 能力，不要求每次完整体检。

Running 不是功能健康；“Pod Ready 但 AP 该节点未 Ready”应按假活处理。

## 典型故障

### 未覆盖节点

常见于 taint/toleration、nodeSelector、affinity、资源不足或 DaemonSet 更新未收敛。影响限于未覆盖节点，但该节点上的目标 Pod 可能成为唯一异常样本。

### 启动失败或反复重启

按证据区分 RBAC/watch 权限、镜像/配置、hostPath/安全挂载、内核/LSM 自检和资源不足。不要看到 CrashLoop 就直接归因 Profile 规则。

### Profile 加载失败

- AppArmor：语法、LSM、securityfs、加载器或 Profile 冲突；
- Seccomp：文件写入/路径、kubelet/runtime 可见性和 Profile 内容；
- BPF：内核/架构/BTF/BPF LSM、map/program 资源、load/attach；
- NetworkProxy：代理 Secret/配置由 manager 传播，节点侧关注挂载、运行时和 AP 状态。

### 节点级异常

如果节点 NotReady、重启或 kernel panic 同时影响多个 Pod，应把节点故障置于业务容器 Crash 之前诊断。BPF Profile 加载与内核错误在时间上相关时，先确认影响范围和证据，再提出隔离节点、升级内核或切换 enforcer 的建议。

## 诊断证据

关键关联键是节点名、AP 名、Profile 名、策略名、agent Pod、容器 ID、时间窗口和 AP node condition。节点侧 Profile 存在只能证明资源存在，不能单独证明 Pod 已使用；仍需核对 Pod SecurityContext/annotation 和运行时事件。

## 建议方向（仅建议）

优先确认覆盖、权限、资源、配置和节点兼容性，再处理 Profile 内容。涉及重启 agent、重建 Workload、切换 enforcer、放宽规则或升级内核时，说明影响、回滚和验证点，不直接执行。
