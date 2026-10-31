---
sidebar_position: 6
---

# 故障排查

:::tip 优先尝试 varmor-diagnosis 技能

遇到策略或组件异常时，可以先使用 [**varmor-diagnosis**](../skills/diagnosis.md) 辅助定位原因。向 AI 助手描述异常现象、受影响的工作负载或节点、命名空间和大致发生时间。该技能通过只读排查关联配置、状态、事件和日志，区分已确认结论、可能原因与缺失证据。

例如：“使用 varmor-diagnosis，排查 shop 命名空间中 Deployment checkout 的策略为什么没有生效。约十分钟前更新过策略。请说明诊断依据、可能原因和恢复建议。”

安装与使用方法见[自动诊断指南](../skills/diagnosis.md)。也可以直接提供已有 YAML、事件和日志，无需连接集群。下文的检查步骤可用于补充调查和验证恢复结果。

:::

从受影响的工作负载、节点和时间范围开始，依次核对策略匹配、生成的 ArmorProfile、实际 Pod 配置、节点加载和运行时行为。组件 Ready 或策略报告成功，都不能单独证明预期操作已经受到保护。

## 按现象定位 {#find-the-failure-stage}

| 现象 | 优先检查 | 下一步 |
| --- | --- | --- |
| 策略未 Ready，或没有 ArmorProfile | 策略 Conditions、目标、模式、Enforcer 和 Manager 日志 | 区分匹配、校验与 Profile 生成失败 |
| ArmorProfile 在部分节点未加载 | ArmorProfile 节点 Conditions、对应 Agent 和节点能力 | [Profile 加载失败](#profile-loading-failures) |
| 策略 Ready，但行为不符合预期 | 实际 Pod 引用、创建时间、策略模式和关联审计事件 | [策略匹配与实际防护](#policy-matching-and-enforcement) |
| Pod 处于 Pending 或 ContainerCreating | 先检查调度、镜像、存储卷和运行时事件 | [工作负载启动失败与崩溃](#workload-startup-and-crashes) |
| 容器反复崩溃 | 退出码或信号、上次运行日志、Profile 和拒绝证据 | [工作负载启动失败与崩溃](#workload-startup-and-crashes) |
| vArmor 组件异常 | Pod Conditions、重启次数、上次终止原因和事件 | [组件与 API 连通性](#component-and-api-connectivity) |
| 磁盘或网络恢复后仍然失败 | 新产生的 Agent 日志和当前 Profile 状态 | [修复原因后重新协调](#retry-after-correcting-the-cause) |
| BPF 更新失败，重试却报告成功 | 应用规则的日志和实际防护效果，不能只看 CR 状态 | [BPF 应用失败](#bpf-application-failure) |
| NetworkProxy 注入、转发或 TLS 异常 | Init/Sidecar 状态、配置和实际请求 | [NetworkProxy 故障排查](enforcers/networkproxy/troubleshooting.md) |

## 收集可关联的必要证据 {#collect-evidence}

将以下示例名称替换为实际资源。`POLICY_NS` 是应用策略所在的命名空间，`VARMOR_NS` 是 vArmor 安装命名空间。如果使用 VarmorClusterPolicy，执行集群范围查询，替代 VarmorPolicy 查询。

```bash
POLICY_NS=default
POLICY_NAME=example-policy
VARMOR_NS=varmor

kubectl -n "$POLICY_NS" get varmorpolicy "$POLICY_NAME" -o yaml
kubectl get varmorclusterpolicy "$POLICY_NAME" -o yaml
kubectl get armorprofiles -A
kubectl -n "$VARMOR_NS" get pods -o wide
```

读取策略的 `status.profileName`，查找对应 ArmorProfile 并核对其 `ownerReferences`。命名空间策略的 ArmorProfile 位于策略命名空间，集群策略的 ArmorProfile 位于 vArmor 命名空间。不要猜测生成的名称，也不要认为所有匹配策略都被选中。

```bash
AP_NS=default
AP_NAME=replace-with-status-profileName
AGENT_POD=replace-with-agent-on-affected-node
MANAGER_POD=replace-with-relevant-manager

kubectl -n "$AP_NS" get armorprofile "$AP_NAME" -o yaml
kubectl -n "$VARMOR_NS" describe pod "$AGENT_POD"
kubectl -n "$VARMOR_NS" logs "$AGENT_POD" --all-containers=true --since=30m --timestamps=true
kubectl -n "$VARMOR_NS" logs "$MANAGER_POD" --all-containers=true --since=30m --timestamps=true
```

对于已重启的容器，使用 `kubectl logs --previous -c <container>` 查看上次运行日志，并将时间范围调整为覆盖故障时段。部署了多个 Manager 时，确认相关 Leader 和接收状态报告的实例；如果发生过 Leader 切换或请求路由变化，需要检查其他实例。将 Profile 名称、节点、Pod UID、容器身份和时间戳一起保留。

### Status 能说明什么 {#status-limits}

- **Policy Status** 汇总生成与加载报告进度。错误消息可能指向 ArmorProfile，而不包含具体节点错误。
- **ArmorProfile Status** 记录失败节点的 Conditions 和加载报告数量。`currentNumberLoaded` 统计报告成功的数量，不是所有响应数量，也不是对内核状态的实时检查。
- **Agent 日志** 用于定位保存、解析、加载、应用规则和上报错误。**Manager 日志** 用于区分收到报告与成功将状态写入 API server。

状态是异步更新的。报告请求成功不代表任一 CR 已经更新。上报失败、Manager 重启或 API 错误，都可能导致状态缺失或过时。后续成功也可能在你看到错误之前将其替换。状态报告没有携带能证明旧成功记录适用于最新规则的规则版本。因此，Status 是当前记录的上报状态，不能作为持久故障历史或当前防护效果的证明。

将两个 CR 与日志关联后，再在受控工作负载中验证应允许和应拒绝的操作。没有审计事件也不能证明没有执行防护：是否记录取决于 Enforcer 和策略配置。参见[审计日志](../getting_started/usage_instructions.md#audit-logs)。

## 策略匹配与实际防护 {#policy-matching-and-enforcement}

按以下顺序检查，优先定位能解释现象的最早异常环节：

1. **匹配：** 检查命名空间、目标 kind/name/selector、实际标签（包括启用注入的 `sandbox.varmor.org/enable="true"` 标签）、容器范围和显式 `unconfined` 设置。注入器先检查集群策略，再检查命名空间策略；不要假设多个匹配策略会合并，也不要按创建时间推断选择结果。
2. **生成：** 检查模式、Enforcer、规则支持范围、策略 Conditions 和生成的 ArmorProfile 内容。内核版本满足要求，不代表所需 LSM 已启用。
3. **注入：** 检查 Webhook 可用性与匹配条件，以及最终工作负载 PodTemplate 和实际 Pod 的注解、安全上下文。NetworkProxy 还需检查 InitContainer、Sidecar 和卷引用。
4. **生命周期：** 将 Pod 的所有者、UID、创建时间与模板更新对应起来。修复模板或 Webhook 不会自动修改现有容器。
5. **节点加载：** 将实际 Pod 的 Profile 引用、所在节点 Agent 和 ArmorProfile Conditions 对应起来。
6. **运行时行为：** 确认测试操作被规则覆盖，以及规则预期是允许、审计还是拒绝。组合使用多个 Enforcer 时，需要判断实际产生结果的层次。

更新 Seccomp 文件不会替换运行中容器已安装的过滤器。修复 Profile 后，受影响的应用容器需要重建才能使用更新的过滤器；请遵循工作负载的发布流程。重新处理 ArmorProfile 不会重建应用 Pod。参见[使用说明](../getting_started/usage_instructions.md)。

## 工作负载启动失败与崩溃 {#workload-startup-and-crashes}

修改策略前，先检查 `kubectl describe pod`、容器的 `state`/`lastState`、事件和上次运行日志。缺少与 vArmor 相关的证据时，应先排查调度、镜像拉取、PVC、资源、节点健康和 CNI 问题。

| 信号 | 排查方向 |
| --- | --- |
| 找不到 AppArmor/Seccomp Profile | 核对 Profile 引用、对应节点 Agent、文件和加载结果；检查策略删除后是否仍保留旧引用 |
| `Permission denied`、`EACCES`、`EPERM` | 按 Profile、Pod UID、操作和时间关联审计或内核日志；Capabilities、其他安全机制和应用自身错误也可能产生相同现象 |
| `SIGSYS` 或 `Bad system call` | 检查 Seccomp 动作和系统调用证据；单凭信号不能判断是哪条策略安装的过滤器 |
| 节点 NotReady、重启、内核 BUG/Oops | 先排查节点和内核健康，保留内核日志，再判断是否与应用规则有关 |
| NetworkProxy Init/Sidecar 失败 | 按[专项指南](enforcers/networkproxy/troubleshooting.md)检查流量重定向、证书、资源和代理就绪状态 |

不要将关闭所有策略或切换到 AlwaysAllow 作为通用修复。如果需要受控隔离实验，应明确工作负载范围、持续时间和回滚方式，并评估失去防护的影响。

## Profile 加载失败 {#profile-loading-failures}

### AppArmor 保存、解析和加载失败 {#apparmor-failures}

根据完整错误区分失败阶段，不要只看 `exit status 1`：

| 错误阶段 | 检查内容 |
| --- | --- |
| `SaveAppArmorProfile()` | 文件创建或写入错误、空间和 inode、只读挂载与权限；还包括读取 `/proc/partitions` 及模板解析、渲染 |
| Parser 语法/include/ABI 错误 | 生成内容、引用的 include/ABI 文件、Parser 与内核兼容性 |
| `LoadAppArmorProfile()` / `UpdateAppArmorProfile()` | 完整 Parser 输出、内核接口访问、Agent 实际受到的限制与 Capabilities，以及 Profile 冲突 |

`interface file missing` 或 `unable to find a suitable fs` 等警告指向接口发现或访问问题，不能单独证明宿主机未挂载 securityfs、缺少内核补丁或某个 Webhook 修改了 Agent。应区分缓存警告与最终加载错误。

比较已安装 Chart 的渲染结果、在线 DaemonSet 模板和对应 Agent Pod。先核对容器名称与滚动更新版本，再判断配置差异。除了应用配置，还要检查 Agent 自身的安全设置与挂载：

- `/etc/apparmor.d` 存放 Profile 和 include，默认宿主机来源是 `/var/run/varmor/apparmor.d`。
- `/sys/module/apparmor` 用于启用状态检查，`/sys/kernel/security` 暴露内核安全接口。
- 文件写入成功不代表内核接口可用。Root 身份、声明的 Capabilities 和实际进程限制需要分别检查。
- 核对已安装 Chart 为 Agent 设置的预期 `Unconfined` 配置，包括结构化 AppArmor 字段和可能存在的旧注解；注解后缀必须匹配容器名。该豁免用于 Agent 的管理操作，不代表应用不受保护。

发现差异后，追踪最早出现变化的位置：渲染、DaemonSet 更新、Pod 创建或运行时执行。字段缺失且存在旧版 Controller/Webhook，不足以证明归因。条件允许时，应检查成功请求的请求与响应、实际 Patch；PATCH 中未提及某字段不等于删除它。只恢复证据指向的设置，不要将特权模式、全局关闭 AppArmor 或移除所有 Webhook 作为通用修复。

### 磁盘写满及空 AppArmor/Seccomp 文件 {#disk-full}

Profile 文件可能创建成功，但后续写入返回 `no space left on device`，留下空文件或部分内容；原有文件也可能已经被截断。因此，文件存在不足以证明保存成功。应在实际承载 Agent 挂载目录的文件系统上检查可用空间和 inode。

Agent 内默认 AppArmor 路径为 `/etc/apparmor.d`，Seccomp 路径为 `/var/lib/kubelet/seccomp`。检查宿主机前，先确认实际卷映射和配置路径。恢复前保留错误、文件大小和必要内容，不要手工清空或删除无关 Profile 文件。

保存函数返回错误时，Agent 会尝试上报 `Failed`，但是否写入任一 CR 仍受 [Status 的限制](#status-limits)影响。仅凭零字节文件不能证明错误曾被上报：进程中断或其他失败路径也可能留下类似结果。

释放空间不会自动补齐文件。修复存储与权限后，使用[手动协调](#retry-after-correcting-the-cause)重新生成文件，核实文件与加载结果；涉及 Seccomp 时，还需遵循应用容器重建要求。

### BPF 应用失败 {#bpf-application-failure}

根据完整的 `SaveAndApplyBpfProfile()` 错误，区分节点能力不支持、规则容量超限和 BPF Map 操作失败。核对所选 BPF 变体及节点侧实际规则数量，包括磁盘设备展开后的数量；参见 [BPF 限制](enforcers/bpf.md#limits-and-performance)。

修复错误指向的原因后，在受影响容器中验证应允许和应拒绝的操作。仅凭重试报告成功，不能确认内核规则已经恢复。重试前，请检查文末的 [BPF 版本限制](#known-bpf-retry-issue)。

## 组件与 API 连通性 {#component-and-api-connectivity}

Manager 异常影响生成、协调和准入，Agent 异常影响节点加载，Classifier 异常主要影响 BehaviorModeling。根据具体错误检查重启、OOMKilled、镜像错误、资源限制、挂载、RBAC、CRD 兼容性、证书和端点。Running/Ready 不代表每个 Profile 或建模任务都在正常推进。

滚动更新期间出现 API 超时时，关联错误时间、Pod UID、节点和发布变更。启用 `hostNetwork` 会替换 Pod，原有 Pod 不会原地切换网络命名空间。应检查相应节点或 Pod 的路由、Service 转发和网络组件，但没有证据时不能直接归因于 CNI。

稍后执行 `curl -k https://<kubernetes-service-ip>:443/` 得到匿名用户的 `403`，只能说明这次请求到达了 API server，不能证明之前网络可用，也不能证明 Agent 凭证、CA 校验或 ArmorProfile API 访问成功。首先确认是否仍有新的超时日志。

如果 Agent 报告不支持 Seccomp，应结合节点实际前提条件，检查启动日志中的 API 版本获取和能力检测结果。网络恢复后，能力判断仍与环境不符时，请检查文末的[启动版本检测问题](#known-seccomp-startup-issue)。

## 修复原因后重新协调 {#retry-after-correcting-the-cause}

此流程适用于已修复原因的 Agent 侧 Profile 处理故障，例如磁盘空间耗尽或目录异常。它不能修复无效策略、不支持的节点能力或注入错误。用于 BPF 前，请先检查[特定版本的重试限制](#known-bpf-retry-issue)；受影响版本可能报告成功却未恢复规则。

### 为什么等待不一定能恢复 {#automatic-retry-limits}

Agent 的有限工作队列重试取决于处理函数是否返回错误。如果处理失败但成功上报 `Failed`，工作项可以结束而不再重试。Informer 的定期同步遇到 Profile spec 和协调计数均未变化时，也会过滤该更新事件。

Manager 状态周期默认是两小时。它仍会刷新状态，但仅在没有节点报告失败、且成功数不等于期望数时强制协调 Profile。这不是对所有失败 Profile 的定期重试：同一 Profile 下，一个已报告的失败也可能阻止该机制催促其他缺少报告的节点。不能依赖这两个循环自动恢复已经确认上报的失败。

### 请求重新处理 {#manual-reconciliation}

1. 按[前述步骤](#collect-evidence)，从策略的 `status.profileName` 确定 ArmorProfile，核实命名空间和所有者。保存当前状态与相关日志。
2. 读取协调计数和资源版本：

   ```bash
   kubectl -n "$AP_NS" get armorprofile "$AP_NAME" \
     -o jsonpath='{.metadata.annotations.profile-reconcile-counter}{"\t"}{.metadata.resourceVersion}{"\n"}'
   ```

3. 将计数加一。注解不存在时按零处理，设置为 `1`。已有值为 `7` 时，按下面示例设置为 `8`。将示例资源版本替换为刚读取的值。如果计数格式异常，应先调查，不要按零处理。

   ```bash
   kubectl -n "$AP_NS" annotate armorprofile "$AP_NAME" \
     profile-reconcile-counter=8 --overwrite \
     --resource-version='<resource-version-from-the-read>'
   ```

   如果资源版本冲突，重新读取对象并计算下一值，避免覆盖并发的计数更新。修改对象是 **ArmorProfile**，不是 VarmorPolicy/VarmorClusterPolicy；不要直接修改生成的 Profile spec 来绕过恢复流程。

4. 观察新产生的 Agent 日志、ArmorProfile 节点 Conditions 和 Policy Status。该更新可能让**所有监听此 Profile 的 Agent** 入队，而不只是失败节点，应选择合适的操作窗口。
5. 核实实际结果：AppArmor 文件内容与加载状态；Seccomp 文件内容及必要的应用容器重建；所选 Enforcer 下应允许和应拒绝的操作。重复设置相同计数或重新应用未变化的对象，不会请求新的处理尝试。

Agent 进程重启或 Pod 重建，也会让新 Informer 为已有 ArmorProfile 提供初始 Add 事件。在故障原因已修复时，这可以恢复部分问题，但影响范围比请求 Profile 协调更大。仅重启 Manager 不会修复节点上的 Profile 文件。任何操作前都应保留证据。

## 报告问题 {#report-a-problem}

提供 vArmor 镜像标签与摘要或代码版本、Chart 版本、Kubernetes/运行时/内核版本、受影响节点与 Pod 身份、策略/Enforcer/模式、脱敏后的策略和 ArmorProfile spec/status、相关事件，以及同一时段的 Agent/Manager 日志。说明故障前的变更、已尝试的恢复动作，以及适用时的一组受控允许/拒绝操作。明确哪些证据缺失，不要从健康状态推断缺失的结论。

移除 Token、凭证、私钥和无关工作负载数据。[诊断参考指南](https://github.com/bytedance/vArmor/tree/main/skills/varmor-diagnosis/references/troubleshooting)提供更深入的调查路径；这些资料跟随 main，可能与安装版本不同。NetworkProxy 专项证据与恢复步骤见其[故障排查指南](enforcers/networkproxy/troubleshooting.md)。

## 已知问题与版本说明 {#known-issues-and-version-notes}

以下问题与安装版本有关，版本信息核对日期为 **2026-10-30**。列出的受影响版本是已确认的版本，不代表完整范围；自定义构建还需确认是否包含对应修复。

### 启动期 API 失败导致 Seccomp 能力判断错误 {#known-seccomp-startup-issue}

| 项目 | 说明 |
| --- | --- |
| 现象 | Agent 启动时获取 API 版本失败；后续环境满足前提条件，却仍报告不支持 Seccomp |
| 已确认受影响版本 | v0.10.6；最早受影响版本尚未确定 |
| 修复状态 | 已合入 main，修复版本待发布 |
| 跟踪链接 | [PR #424](https://github.com/bytedance/vArmor/pull/424) |

受影响版本在首次 API 版本请求失败后仍会初始化能力状态。后续 API 恢复或定期刷新版本，不会重新计算 Agent 的 Seccomp 支持标志。仅递增 ArmorProfile 协调计数也不能纠正该标志。

**处理方式：** 先恢复 API 连通性，在修复版本可用时升级。如果暂时无法升级，可在网络恢复后受控重启受影响的 Agent，使其有机会重新正确初始化。检查新进程日志中的版本获取与能力检测结果，再验证 Profile 处理和工作负载。重启不能解决节点确实缺少能力或网络仍不通的问题。

修复后的实现会等待取得有效 API 版本，再进入正常 Agent 初始化；等待期间保持未就绪，并支持可取消的重试。

### BPF 重试报告成功但未恢复规则 {#known-bpf-retry-issue}

| 项目 | 说明 |
| --- | --- |
| 现象 | 现有容器的 BPF Profile 更新失败；后续协调相同内容时报告成功，但预期规则未恢复 |
| 已确认受影响版本 | v0.10.6；最早受影响版本尚未确定 |
| 修复状态 | 已合入 main，修复版本待发布 |
| 跟踪链接 | [PR #428](https://github.com/bytedance/vArmor/pull/428) |

受影响版本中，变更后的 Profile 在完成内核应用前就写入缓存。失败后，相同内容可能命中缓存并跳过应用。因此，递增 `profile-reconcile-counter` 可能清除失败节点的 Condition，却没有恢复防护。更新失败还可能移除失败容器的旧规则，而其他容器保留旧规则或已经收到新规则。

规则容量错误和 BPF Map 操作失败都可能触发此路径。例如，unrolled 变体的节点支持最多 50 条挂载规则，而控制面允许最多 64 条；磁盘设备展开也可能使规则超过节点容量。

**修复后行为：** 包含 PR #428 的构建会按容器保留待完成的应用任务，在后续协调时重试，即使预期 Profile 没有变化。磁盘设备展开后的规则数量会先按节点容量校验，通过后才替换缓存中的预期状态或已有内核规则。

**处理方式：** 保留最初错误，修复容量或资源问题。使用包含修复的构建时，可通过[手动协调](#manual-reconciliation)重试待完成任务，再验证加载状态和实际应允许、应拒绝的操作。该修复保留现有 Agent/Manager 重试策略，没有新增自动重试循环，也没有改变容器首次启动时应用失败的上报机制。

仍使用受影响版本时，应升级到包含修复的构建。暂时无法升级时，重启受影响的 Agent 会重建内存状态，提供恢复机会，但可能中断节点防护，也不能解决持续故障，操作前需评估影响。即使已包含修复，多张 Map 的替换仍非原子操作：运行时 Map 更新失败后，容器仍可能缺少旧规则，直到重试成功。注解更新成功或 Ready 状态，都不足以证明防护已经恢复。
