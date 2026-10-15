# varmor-manager 控制面

## 职责

`varmor-manager` 负责 VP/VCP 的 reconcile、策略校验和 AP 生成；提供 Mutating/Validating Webhook；在 BehaviorModeling 中接收并汇总行为数据；在 NetworkProxy 场景传播代理配置/Secret；通过 Leader Election 确定实际处理者。

## Deployment 运行态设计

manager 通常以 Deployment 运行。副本数、leader election、Service、WebhookConfiguration、RBAC、证书/配置挂载、readiness/liveness 和资源限制共同决定控制面是否真正可用：

- 多副本提高可用性，但同一时刻通常只有 Leader 负责实际 reconcile；非 Leader 副本 Running 不代表它正在处理策略。
- Service 与 Endpoint 承载 Admission 调用；Deployment Ready、Service 存在和 Webhook 可调用是三个不同层次。
- readiness 可能只反映进程或基础依赖，不能替代 VP/VCP 状态、AP 生成和 Webhook 注入证据；liveness 失败则可能造成选举抖动和 reconcile 中断。
- RBAC 决定 manager 能否 watch/update VP、VCP、AP、Webhook 相关对象；证书和配置挂载决定 Webhook、NetworkProxy 等功能能否启动。
- 资源限制会影响行为建模、APM 汇总和大规模策略 reconcile；OOM 后应同时检查是否有策略状态停滞或 Webhook 短暂不可用。

诊断时将 Deployment、Leader Lease、Service/Endpoint、WebhookConfiguration 和策略/AP 状态串起来；不要用单个 manager Pod 的 Running 或 Ready 代替整条控制面证据。

## 健康信号

- manager Pod Ready、重启次数、lastState、资源状态；
- Leader 的唯一性与 lease 续期是否连续；
- VP/VCP 的 conditions、phase、profileName 是否随事件变化；
- AP 是否生成、更新，status 是否回报节点结果；
- Webhook Service/Endpoint、证书和实际 failurePolicy；
- 行为建模时 manager 是否收到节点数据并能持久化 APM。

“Pod Running”或“有 Leader”只证明进程/选举层面正常，不证明 reconcile 和 Webhook 业务链正常。

## 典型故障

### CrashLoopBackOff / 启动失败

优先区分 CRD schema/版本、RBAC、配置与 enforcer 能力、镜像/资源、Kubernetes API 兼容性。把启动失败与具体策略拒绝分开判断。

### 无 Leader 或频繁切换

常见原因是 lease 不存在/不可更新、RBAC、API Server 抖动或 manager 自身异常。后果是 reconcile 无人稳定处理；匹配请求是否阻断取决于实际 Webhook `failurePolicy`。

### Running 但策略不下发

VP/VCP 长时间未更新、AP 未生成或未更新时，区分 API Server 限流/不可达、reconcile 队列积压、策略校验失败、目标链问题和 controller 业务错误。不要因为 manager 健康就跳过 Webhook、策略 status 和 AP。

### OOM 或资源不足

BehaviorModeling 的跨节点数据汇总、APM 生成和本地存储会显著改变资源需求；结合资源限制、数据规模和存储类型判断。

### Webhook 无 Endpoint

manager Service 存在但没有 Ready endpoint 时，API Server 无法稳定调用 Webhook。实际影响由 failurePolicy、匹配规则和请求类型决定；`Ignore` 可能表现为请求成功但没有注入。

## 诊断证据

优先形成 `策略事件/status → manager reconcile 证据 → AP 状态 → Webhook/Pod 注入` 的链路。Leader、RBAC、API Server 和证书是控制面基础依赖；不要把所有 manager 日志中的 warning 直接解释为业务故障。

## 建议方向（仅建议）

按“恢复可观测性和控制面稳定性 → 确认单策略链路 → 验证节点执行面”的顺序处理。涉及修改 RBAC、证书、Webhook、资源限制或重启 manager 时，只给出影响、前置条件、回滚和验证点，不直接操作。
