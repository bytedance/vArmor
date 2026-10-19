# Enforcer 匹配与规则冲突

## 诊断目标

不要只判断策略是否 Ready，而要闭合“声明了什么、匹配了什么、生成了什么、节点加载了什么、Pod 使用什么、最终由谁处置”。最早可证明的断点优先；后续异常可能只是连带现象。

## 六层匹配链

1. **策略声明**：确认 mode、enforcer、规则、target、container 范围及 `unconfined` 等选项。
2. **目标匹配**：确认 VP/VCP 的 namespace、kind、名称/selector、标签和优先级实际命中目标。
3. **策略编译**：确认规则和 enforcer 能力被转换为有效 AP；不支持的内核、模式专属字段或非法规则可能在此处失败。
4. **Admission 注入**：确认 Webhook 命中请求，并将所需 annotation、SecurityContext、sidecar 或引用写入最终 Pod/PodTemplate。
5. **节点加载**：确认目标节点的 agent 已加载对应 Profile，并满足 LSM、BPF、runtime、证书和资源等前提。
6. **运行时执行**：将实际行为与 Profile、enforcer、Pod UID、节点、时间和 action 对齐，判断放行、审计或拒绝。

任一层不成立，都不能用下一层的健康状态替代。例如 AP 存在不能证明 Pod 已注入，Pod 已注入也不能证明节点已加载。

## VP/VCP 重叠与最终归属

VP 与 VCP 可能同时命中同一 Workload。诊断时不要只按创建时间或对象名称推断优先级，应确认：

- 两类策略的 target、namespace 范围、selector 和优先级是否重叠；
- manager 最终选择或合并的策略归属，以及对应 AP/profileName；
- PodTemplate 和实际 Pod 中的最终 Profile、enforcer、模式和容器范围；
- 策略 generation、AP 版本、Pod 创建时间是否处于同一生效链路。

若声明层显示多个候选策略，而 AP 或 Pod 只体现一个最终结果，应以最终 AP 归属和 Pod 实际配置诊断；若不同观察点互相矛盾，结论应标为“规则冲突”或“证据不足”，而不是直接判定未生效。

## 多 enforcer 叠加

多个 enforcer 可以同时影响一个业务动作，但它们的控制层不同：

- AppArmor 与 BPF 可能同时约束文件、执行、能力、挂载或网络；
- Seccomp 约束 syscall，业务层的文件或网络错误可能只是底层 syscall 被拒绝后的表现；
- NetworkProxy 只处理已重定向到 sidecar 的流量，可能与 CNI NetworkPolicy、DNS、内核网络规则及应用自身校验叠加。

`EACCES`、`EPERM`、`Permission denied` 不能单独确定 enforcer；`SIGSYS`/`Bad system call` 更指向 Seccomp，但仍需结合 Profile、Pod、节点和时间证据。应先寻找最早、最具体且能解释现象的拒绝事件，再排除其他叠加层；不要因为同时存在多个 Profile 就把所有异常归因于 vArmor。

## Allow、Audit、Deny 语义

`allowViolations` 与 `auditViolations` 是正交配置，不能仅从“有无日志”推断是否放行：

- 不允许且不审计：可能阻断但没有对应审计记录；
- 不允许且审计：阻断并记录拒绝事件；
- 允许且审计：放行并记录允许/审计事件；
- 允许且不审计：放行且无对应审计事件。

Seccomp 的观察和事件语义不能简单套用 AppArmor/BPF 的 `DENIED`；应结合 syscall、信号、action 和 Profile 语义判断。NetworkProxy 自定义规则主要由 qualifier、优先级和 `defaultAction` 决定，不应直接套用 `allowViolations`。

## NetworkProxy 规则层次

按以下顺序定位，避免把规则未命中误判为代理故障：

1. **注入**：Pod 是否包含 proxy annotation、initContainer、sidecar、配置/证书 volume 及必要环境配置。
2. **启动**：initContainer 是否完成，sidecar 是否 ready，Secret、证书、配置和端口是否有效。
3. **转发**：目标流量是否经过重定向；端口、ProxyUID、管理端口和回环流量是否造成绕过或误转发。
4. **协议与匹配**：先区分 L4 IP/CIDR/端口，再判断 SNI/域名和 L7 HTTP host/path/method；不同层的规则不能互相替代。
5. **优先级与默认动作**：确认 qualifier、规则优先级、allow/deny 关系和 `defaultAction`；不要只凭规则文本顺序推断结果。
6. **HTTPS 可见性**：没有 TLS MITM 时通常只能依据连接、SNI 或 host 判断，不能期待按加密流量的 HTTP path/method 匹配。
7. **绕过与外部层**：核对允许绕过的身份、管理端口、Pod CIDR，以及 CNI NetworkPolicy、DNS、服务网格或应用代理的叠加影响。

sidecar Ready 只说明代理进程达到就绪条件，不代表所有流量都经过代理；L4 允许也不代表 L7 一定允许，反之亦然。

## 统一结论分类

报告应明确归入最贴近证据的一类：

- 未匹配
- 能力不支持
- 未编译
- 未注入
- 模板已注入但 Pod 未更新
- 未加载
- 已加载未触发
- 已触发且放行
- 已触发且拒绝
- 规则冲突
- 业务问题
- 证据不足
