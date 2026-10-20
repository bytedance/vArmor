---
name: varmor-diagnosis
license: Apache-2.0
description: Diagnose vArmor and Kubernetes security issues involving components, policies, Profiles, webhooks, node enforcers, BehaviorModeling, and NetworkProxy. Use when Pods are Pending, containers exit unexpectedly, policies fail to inject or take effect, policy status is abnormal, node Profiles fail to load, audit events need investigation, or vArmor components are unhealthy. Provide domain context, targeted read-only checks, and evidence interpretation.
---

# 自动诊断

模型基于 Kubernetes 诊断能力自主选择查询与排查路径，本 Skill 补充 vArmor 的对象关系、
生效语义和容易误判的证据边界。优先用小范围、低影响的动作回答当前问题。

- **references/**：知识层，解释架构、组件、CRD、规则语义与故障模式，按需读取。
- **playbooks/**：检查点、查询示例和判读建议；不是固定流程或命令白名单。
- **scripts/**：可选的复杂结构处理工具，不代替模型综合判读。
- **templates/**：正式诊断报告的组织参考。

统一命令成本、授权与证据约定见 `playbooks/README.md`。工具返回的事实是证据，知识库用于
解释；不凭经验补造状态、版本或日志。

## 适用范围

覆盖 vArmor 组件、VP/VCP/AP/APM、Admission Webhook、AppArmor/BPF/Seccomp/NetworkProxy、五种策略模式，以及 Pod Pending、Container Crash、策略未生效、审计事件和节点兼容性问题。

不负责生成策略、不负责策略管理、不负责替代通用 Kubernetes 故障处理，也不把 vArmor 当作虚拟机级隔离方案。即使工具具备写操作能力，本 Skill 也只输出建议、风险和验证点，不代用户修改策略、重启/删除资源、改变 Webhook、调整节点或切换防护模式。

## 核心心智模型

把一次防护拆成五个连续环节：

1. **目标发现**：VP/VCP 的 `spec.target` 是否匹配正确的 namespace、kind、name/label selector 和 container；目标是否满足 Webhook 匹配条件；是否被显式 `unconfined` 绕过。
2. **策略编译**：manager 是否接受策略、生成 Profile 和必要的 NetworkProxy 配置；VP/VCP status 是否反映正确阶段和原因。
3. **Admission 注入**：Webhook 是否在正确请求上注入 Profile 引用、NetworkProxy sidecar/initContainer、SecurityContext 或兼容 annotation。
4. **节点落地**：目标节点 agent 是否收到 AP，并按 enforcer 准备资源；AP 期望和实际加载数是否一致。
5. **运行时执行**：容器实际使用的 Profile 是否与策略一致，违规事件的 `enforcer`、`action`、身份和时间是否能与业务现象对应。

诊断时先判断故障位于哪一环，再沿前后相邻环节验证。`Policy Ready` 只说明 vArmor 观察到所需 Agents 已处理 Profile，不等同于每个业务 Pod 都被匹配、注入且按预期运行。

## 推荐诊断流程

1. 明确集群、namespace、Workload/Pod、container、节点、策略、开始时间和影响范围。
2. 范围不明时看概览，判断是全局、单节点、单策略还是单容器。
3. 建立对象链：`策略 → status.profileName → 同名 ArmorProfile → 目标 Workload/Pod → 目标节点 → agent/enforcer`。
4. 按证据补齐缺口：状态、事件、日志、节点内核/LSM/运行时和审计事件；避免无目标收集全量数据。
5. 区分“未匹配/能力不支持/未编译/未注入/模板已注入但Pod未更新/未加载/已加载但未触发/已触发且放行/已触发且拒绝/规则冲突/业务本身异常/证据不足”。
6. 输出问题、证据、根因、置信度、影响范围、建议和未排除项。

## 自主执行建议

- 已知 Pod、Workload、策略或节点时直接从该对象开始；目标模糊时先做有限摘要发现。
- 每步选择能验证当前假设的最小动作，复用已采集事实；先 API 状态/事件和有限日志，再按需
  做容器或节点视图的定向检查。不要为了完成手册、脚本或报告而增加采集。
- 集群操作前核实目标 context 并尽量显式绑定；已有明确集群与授权时不重复询问。只介绍流程
  或分析本地材料时不要求连接集群。不主动切换 context、安装依赖或扩大节点权限。
- 对象名、selector、container、profileName、路径和时间窗口由模型发现并向后传递；不让用户
  手动替换可发现参数，不执行未解析占位符。Python 只在选用脚本时需要，缺失时可用等价查询。
- 关键词搜索可用于发现候选，再由模型交叉确认归属。字段清单是提示，必要时可读取其他相关
  非敏感字段。脚本与原生命令按复杂度选择，不要求已有事实重新经过脚本。
- 找到可解释现象的断点后，补齐其原因或提出最小验证建议即可；查询失败、未匹配和未知分开
  表达。风险按具体命令、访问范围、开销和外部影响评估，已有授权范围内不逐命令询问。

## 参考文件路由

### 知识层（references/）：理解原理与故障模式

- 全局架构 → `references/architecture.md`
- VP/VCP/AP/APM 与状态 → `references/modules/policy-crd.md`
- manager → `references/modules/manager.md`
- agent → `references/modules/agent.md`
- 运行时违规来源、轮转与身份关联 → `references/modules/violation-log.md`
- classifier/建模 → `references/modules/classifier.md`
- enforcer → `references/modules/enforcers.md`
- Webhook/注入 → `references/modules/webhook.md`
- 各模式默认 Profile/基线（无自定义规则时是否仍有防护）→ `references/modules/policy-mode-profiles.md`
- EnhanceProtect 内置规则的实际实施范围（按 enforcer）→ `references/modules/built-in-rules-apparmor.md`、`references/modules/built-in-rules-bpf.md`、`references/modules/built-in-rules-seccomp.md`
- 症状路标 → `references/troubleshooting/` 下对应文件
- 跨 enforcer 冲突、VP/VCP 重叠、统一结论分类 → `references/troubleshooting/enforcer-conflicts.md`

知识按需读取，不一次加载全部：解释“某模式默认会保护什么”时读 `policy-mode-profiles.md`；分析某条 EnhanceProtect 内置规则是否可能导致异常时，先确认实际 enforcer，再读对应的规则实施文档。

本地参考不足时，从 [官方文档索引（main）](https://www.varmor.org/zh-cn/docs/main/llms.txt) 按需查阅相关页面作为补充；已发布版本优先查阅对应版本文档，不默认全量阅读，也不混用稳定版与 main 的语义。

### 操作层（playbooks/）：执行诊断查询

按症状选择；不要求按编号执行，最早可证明断点优先：

1. **概览** → `playbooks/overview.md`（诊断入口，快速判断影响范围）
2. **组件检查** → `playbooks/component.md`（manager/agent/classifier 健康）
3. **策略链路** → `playbooks/policy.md`（VP/VCP → AP → 节点条件）
4. **Webhook 验证** → `playbooks/webhook.md`（配置/端点/证书/匹配规则）
5. **Workload 验证** → `playbooks/workload.md`（PodTemplate vs 实际 Pod 注入对比）
6. **节点检查** → `playbooks/node.md`（内核/LSM/BTF/Profile 加载）
7. **审计事件** → `playbooks/audit.md`（运行时违规/审计事件关联）

统一操作契约、L0-L4 风险等级和证据记录格式 → `playbooks/README.md`

专项检查：
- NetworkProxy → `playbooks/networkproxy.md`（六层排查）
- 行为建模 → `playbooks/behavior-modeling.md`（三段链路）

### 脚本层（scripts/）：可选辅助结构处理

以下脚本可辅助处理复杂结构，按接口限定单个节点、策略或对象；简单查询与已有证据可直接由模型分析：

- enforcer 前置条件 → `scripts/check-enforcer-compatibility.py`（区分已证明、不满足和待证明条件）
- 策略 target 匹配 → `scripts/match-policy-target.py`（完整计算 name 或 LabelSelector 的实际命中对象）
- 已配置内置规则冲突 → `scripts/analyze-built-in-rules.py`（只分析现有 VP/VCP；可结合显式上下文和 APM 样本，不生成策略）
- 注入事实提取 → `scripts/inspect-injection.py`（提取单个 Pod/Workload 的字段白名单，不判断注入来源）

### 报告层（templates/）：组织最终输出

- 完整诊断报告 → `templates/diagnosis-report.md`

用户要求正式报告或问题较复杂时，参考该模板组织自包含的 Markdown；可按问题删减章节。
普通诊断用简洁的结论、关键证据、未确认项和下一步即可。根因未闭合时给出当前断点、未排除项
和下一探针，不为填表追加无关采集。

## 操作安全与证据解释规则

- `ready=false`、`Ready=False`、`CurrentNumberLoaded < DesiredNumberLoaded` 是异常信号，但要结合对象范围和时间判断是否仍在收敛。
- `restart_count>0` 不是根因，必须结合 lastState、事件和日志。
- `Policy Ready=True` 不代表 selector 有目标，也不代表 Pod 已完成注入。
- `AUDIT`、`ALLOWED`、`DENIED`、`AUDIT|ALLOWED` 表示最终处置，不要把审计事件一律解释为拦截。
- `EPERM/EACCES` 不能单独证明是 vArmor；`SIGSYS` 也要结合 Profile、时间和审计证据。
- 规则分析的 `REVIEW_REQUIRED`、`APM_DATA_UNAVAILABLE`、`UNASSESSED` 或 `APPLICABILITY_NOT_ESTABLISHED` 表示规则层尚未排除，不能据此写“问题不在规则层”。
- 短生命周期进程可能缺少 container/Pod 身份；NetworkProxy 事件通常是 Pod 粒度。
- 版本和字段可能变化；集群实际 CRD、状态和对应版本文档优先。

## 输出要求

输出范围与时间、结论及关键证据、置信度和必要的下一步。复杂问题解释相关防护环节的因果链；
正式报告引用证据编号，未知值写“未采集/未确认”。涉及放宽策略、重建工作负载、切换 enforcer
或升级内核时说明影响、前置条件、回滚与验证点，只提供建议。

## 边界提醒

- vArmor 不等价于 Kata 等硬件虚拟化隔离。
- NetworkPolicy 仍承担基础网络隔离；NetworkProxy 补充 L4/L7、SNI、TLS MITM、HTTP header mutation 和审计。
- NetworkProxy 场景重点关注 NET_ADMIN、ProxyUID、proxyAdminPort、Pod CIDR 管理端口和绕过路径。
- 当前诊断范围内的小范围只读查询由模型自主编排；定向读取已有 agent 的内核状态不因其
  privileged 身份自动变成高影响操作。主动请求、范围扩大或高成本取证按实际影响与授权处理。
  当前 Skill 不代用户执行集群/节点状态变更。
- 具体操作契约和统一证据格式以 `playbooks/README.md` 为准；不要依赖固定 namespace、Service、sidecar、annotation、端口或节点路径。
