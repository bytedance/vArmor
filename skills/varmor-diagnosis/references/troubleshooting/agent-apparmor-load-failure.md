# Agent AppArmor Profile 加载失败诊断路标

## 入口信号

AppArmor 策略创建或更新后，AP 的节点条件或 agent 日志指向 Profile 保存、解析、加载或替换失败时使用。
agent Pod Running/Ready 不排除这类故障；启动自检通过也不证明后续能访问内核管理接口。
从已失败的节点与 AP 开始，复用已有证据，不要求遍历全部节点。查询示例见
[节点检查](../../playbooks/node.md)，操作边界见 [统一约定](../../playbooks/README.md)。

## 1. 定位失败阶段

关联 AP/Profile 名、失败节点、agent Pod 与容器身份、日志时间，保留加载器的原始输出与退出状态。
按日志选择后续分支，不把所有 `exit status 1` 都解释成权限不足：

| 信号示例 | 优先验证 |
|---|---|
| `SaveAppArmorProfile()` 失败 | 按底层错误区分内容检查、文件创建/写入、`/proc/partitions` 读取及模板解析/渲染失败；文件问题再查路径、目录挂载、只读状态、空间和权限 |
| parser 报语法、include、ABI 或规则不支持 | 实际生成内容、对应文件及 parser/内核能力；区分文件缺失与语法错误 |
| `LoadAppArmorProfile()` / `UpdateAppArmorProfile()` 失败 | 结合完整 parser 输出区分接口访问、权限、兼容性和 Profile 冲突 |
| `interface file missing`、`unable to find a suitable fs`、`--subdomainfs` | AppArmor 启用状态、agent 的接口挂载视图与访问约束 |
| `Permission denied` / `Operation not permitted` | 实际运行身份、管理能力、安全约束、挂载和相关内核拒绝日志 |

`Cache read/write disabled: interface file missing. (Kernel needs AppArmor 2.4 compatibility patch.)`
和 `Warning: unable to find a suitable fs in /proc/mounts, is it mounted?` 是接口发现/访问失败的线索。
它们既不能单独证明宿主机没有挂载接口，也不能证明缺少某个内核补丁或被特定 Webhook 修改。
缓存警告与最终加载失败分开判断；不要根据提示文字直接建议升级内核或添加 `--subdomainfs`。

`SaveAppArmorProfile()` 在创建文件后，还会读取 `/proc/partitions` 准备磁盘设备模板数据，
再解析并渲染 Profile 模板。这些步骤均可能返回错误；文件已存在不代表本次保存完整，
也不能据此判断宿主目录或内核接口已准备好。

## 2. 核对部署意图与实际 Pod

接口或权限方向的故障，应检查 **agent 自身** 的安全配置和挂载，而不只检查受保护业务 Pod。
将已安装版本的渲染清单、实际 DaemonSet 模板、对应 agent Pod 的相关字段按需比较。
先核对 owner、创建时间、镜像和模板修订，排除滚动升级中旧 Pod 与新模板的正常差异。

重点看容器与 Pod 级 `securityContext`、兼容注解、capabilities、运行用户，以及内核接口对应的
hostPath/volumeMount；挂载只读状态也要核对。root、管理能力、接口可见性和 AppArmor 约束是
不同条件，不能从 `runAsUser: 0` 或某个 capability 已声明推断加载一定成功。

当前 Chart 默认路径可帮助区分文件保存、自检与内核加载失败：

| agent 内路径 | 默认宿主来源 | 作用 |
|---|---|---|
| `/etc/apparmor.d` | `/var/run/varmor/apparmor.d` | 保存 Profile、ABI、include 等文件；agent 的 `AppArmorProfileDir` 指向此目录 |
| `/sys/module/apparmor` | 同名宿主路径 | `isAppArmorEnabled()` 读取其中的 `parameters/enabled` |
| `/sys/kernel/security` | 同名宿主路径 | 提供 AppArmor 等内核安全接口；文件保存成功不证明接口可访问 |

前两项的默认 volumes/volumeMounts 由 Chart 的 `appArmorLsmEnforcer.enabled` 控制，
`/sys/kernel/security` 在模板中单独挂载。现场路径可能被覆盖，应按实际渲染清单成对核对。
目录未挂载时写入也可能落到容器文件系统，不能仅凭文件写入成功认定宿主目录已准备好。

当前 vArmor Chart 为 agent 声明 AppArmor 豁免，其表达随目标 Kubernetes 版本变化：

| Chart 渲染分支 | 预期表达 |
|---|---|
| Kubernetes < 1.30 | Pod 注解 `container.apparmor.security.beta.kubernetes.io/agent: unconfined`；当前模板的后缀固定为 `agent` |
| Kubernetes >= 1.30 | agent 容器的 `securityContext.appArmorProfile.type: Unconfined` |

以现场安装版本的 Chart 与配置为准；这里的版本分界说明 API 表达迁移，不说明较新集群必然有故障。
新字段在 Kubernetes 1.30 引入、1.31 进入稳定状态；Chart 切换表达不等于旧注解停止兼容。
例如 [1.32 的 Pod 创建实现](https://github.com/kubernetes/kubernetes/blob/v1.32.0/pkg/registry/core/pod/strategy.go)
仍执行注解与字段的兼容转换；后续版本按对应文档和实现核对，不把废弃、移除 feature gate
与移除注解兼容混为一谈。
注解后缀必须匹配实际容器名。当前 Chart 的旧注解分支不会随 `agent.name` 自动调整后缀；
自定义该值时需检查渲染结果，不能把名称不匹配误判成准入删除配置。
容器级字段优先于 Pod 级字段；容器级字段缺失时，还需检查
Pod 级设置与该版本对旧注解的兼容处理。两种表达同时存在时核对一致性。

agent 的 `Unconfined` 用于避免它自身受 AppArmor profile 约束，不是业务容器绕过防护的证据。
删除显式设置后可能回落到继承或运行时默认值；仅发现一个字段缺失，不能直接断言实际状态。
自定义部署采用其他安全配置时，应验证其管理能力与实际限制，不自动要求改成特权模式。

## 3. 按缺口验证实际执行条件

先用 API 配置、AP 条件和有限日志判断；证据不足且授权覆盖时，再按
[节点检查 2.1](../../playbooks/node.md#21-apparmor-加载失败时的配置与运行约束) 定向只读验证。
根据缺口选择分支，不要求完成全部检查：

| 待区分条件 | 判读边界 |
|---|---|
| 内核/LSM 与 parser 能力 | 内核版本满足不等于 LSM 已启用；接口不可读也不等于未启用 |
| 实际挂载与接口访问 | 配置声明不等于实际可见；区分缺失、只读和访问拒绝 |
| agent/parser 的实际 AppArmor 约束 | 核对正确进程；字段缺失或属性读取失败不等于 `unconfined` |
| 实际管理能力与相关内核拒绝 | 声明 `MAC_ADMIN` 不等于实际保留或操作被允许；无审计记录不能单独排除限制 |

进程实际受默认或自定义 profile 约束时，结合接口可见性、拒绝记录和失败操作判断其影响。
若进程确为 `unconfined`，继续检查挂载、能力、规则内容和兼容性；不要坚持配置丢失假设。

## 4. 配置不一致时，再追查来源

确认 agent 的安全配置与对应部署意图不一致后，沿字段最早出现差异的位置调查：

| 差异位置 | 排查对象与请求 |
|---|---|
| 渲染结果已缺失 | 安装参数、Chart 版本、渲染时采用的 Kubernetes 版本及部署工具处理 |
| 渲染结果正确、线上 DaemonSet 模板不同 | DaemonSet 的 CREATE/UPDATE/PATCH 发起方、匹配 DaemonSet 的准入组件及后续配置管理 |
| 对应模板正确、实际 Pod 不同 | Pod 的创建处理及后续 UPDATE/PATCH 发起方、匹配 Pod 的准入组件 |
| Pod 声明正确、进程状态不符 | 节点 kubelet、运行时版本与日志、实际进程身份 |

按容器名对照 DaemonSet 的 `.spec.template.spec.containers[].securityContext.appArmorProfile`
与 Pod 的 `.spec.containers[].securityContext.appArmorProfile`；Pod 级字段与旧注解也要在
对应模板/对象层级核对。若模板已经丢字段，后续 Pod 可能只是正常继承，不必假设 Pod 准入再次删除。
若同一修订模板仍有字段而 Pod 没有，仅在 DaemonSet 上发生字段删除不能解释这项差异。

将部署渲染、请求发起方、API Server 兼容转换和准入修改分开判断，沿该对象的创建/更新记录
定位字段最早出现差异的位置。当前 Webhook 匹配配置只说明可能参与，不能证明历史上确实修改过。
直接 UPDATE/PATCH 与 Webhook 并不互斥，同一次请求可能先由控制器、Operator 或运维工具构造，
再被匹配的 Webhook 修改。审计资源是 DaemonSet 还是 Pod，应由 objectRef/requestURI 确认，
不依据口头描述选定。Webhook 的资源、operation、selector 等需与该次请求相符。
审计中的 ServiceAccount 是调用身份，还需结合 userAgent、来源和组件日志关联实际程序；
同一身份可能被多个进程使用。

旧组件使用的 Kubernetes API 类型可能不认识 `appArmorProfile` 等新字段。如果读取成旧类型后
重新生成 DaemonSet/Pod 更新请求，或在准入补丁中替换整个模板、容器列表或安全上下文，
就可能无意丢失新字段。Webhook 常见处理过程是“反序列化 → 加工 → 重新序列化 → 计算补丁”；
它通过 AdmissionResponse 中的补丁表达修改，并非仅返回重新序列化的对象就自动覆盖资源。
应核对计算差异时使用的原始对象与输出对象，以及补丁实际删除/替换的范围。
即使原始清单只使用旧注解，API Server 在支持兼容转换的版本中也可能在创建后补出结构化字段，
使旧更新方读取到它不认识的内容。旧注解是通用字符串字典，通常较容易被保留；不能因注解
仍在就推断更新请求完整，也不能把正常兼容转换当成删除配置的证据。

**不认识字段不等于一定删除。** 只对必要字段生成精确补丁的组件可以保留其余字段。
需结合组件支持范围、API 库版本、补丁实现或实际审计记录验证；组件较旧、Webhooks 存在及
字段缺失都不能单独证明归属。验证型准入拒绝创建与修改型准入改变配置也要区分。
其他已知字段不变而新字段缺失，与旧类型处理机制吻合，但不是特定组件执行删除的直接证据。

Webhook 注册本身不会追溯修改已有 Pod；后续匹配的请求或替代 Pod 的创建仍可能受影响。
更新已有 Pod 不会自动转成重建；修改 DaemonSet 的 Pod 模板后，是否自动替换由实际更新策略
决定（通常为 RollingUpdate，OnDelete 不自动替换已有 Pod）。结合修订、UID 与时间确认传播过程。

### 用请求与结果区分“遗漏”与“已修改”

已有审计记录可用时，按对象身份与故障时间限定范围，沿
[节点检查](../../playbooks/node.md#21-apparmor-加载失败时的配置与运行约束) 获取相关证据。
`requestObject` 记录客户端提交的内容，位于版本转换、默认处理、准入和合并之前；
它不是最终持久化对象，也不是更新前对象。

| 观察 | 可以判断与仍需验证的内容 |
|---|---|
| CREATE 请求只有旧注解，创建响应多出新字段 | 可能是正常兼容转换，不能判定第三方丢字段 |
| 更新前对象有字段，完整 UPDATE 请求缺字段 | 支持更新方输出遗漏；仍需核对响应及最终对象，不能直接写“已删除” |
| PATCH 请求未涉及字段 | 不能按完整对象理解；根据补丁类型、具体删除/替换内容和适用语义判断 |
| 请求带字段，响应或最终对象不同 | 沿服务端转换、准入及后续请求调查，不把差异直接归给请求发起方 |
| 已确认匹配 Webhook，机制能解释字段丢失，但没有该次补丁 | 保留为有依据的假设，列明缺少直接修改证据，不报告为已确认删除来源 |
| 同次请求的 Webhook 补丁删除字段或替换其父对象 | 支持定位修改来源；仍核对后续准入和最终成功响应，确认是否实际生效 |
| 请求被拒绝或冲突 | 这次请求不能证明线上配置已改变；继续查已有对象与其他成功请求 |

结合 `responseStatus`、可用的 `responseObject` 与修改前后快照确认结果，按 UID 区分同名重建，
按时间和 resourceVersion 关联版本；当前 Pod 不能单独代表历史请求完成时的状态。
上游普通 Pod 更新通常不允许改变此类安全字段，若发现“成功删除”，应再核对资源/子资源、
集群版本与实现，是否实际修改的是工作负载模板并重建 Pod；不能跳过更新校验推断。
成功写入配置也不证明已有进程的 AppArmor 约束已改变，仍需关联容器生命周期和实际进程状态。
审计级别不足或历史记录缺失时注明未确认项，不以猜测补齐修改来源。

## 5. 结论与处理建议

分别报告已经证明的失败阶段、配置差异、实际运行约束和修改来源；缺哪一项就说明缺口，
不要把“更新请求遗漏字段”写成“线上配置已删除”，也不要把“疑似配置丢失”写成“某个旧组件已删除字段”。
分别确认配置变化、agent 实际受限及该约束与本次加载失败的关系。影响按节点与 enforcer 界定：加载更新失败
不等于已有内核 Profile 已消失，也不代表其他 enforcer 全部失效。

建议随原因收敛：恢复正确的部署/挂载/能力配置，修正错误准入规则或字段丢失实现，必要时升级
不兼容组件；规则语法或 parser/内核兼容问题沿对应分支处理。涉及安全例外时限定 agent 范围，
说明影响、回滚和验证点，不把禁用整个 Webhook、全局关闭 AppArmor 或启用特权模式作为通用修复。

配置修正可能需要替换 agent Pod 才能改变进程启动约束；只提供建议，不代用户重建或重试加载。
验证点包括新 Pod 的最终配置、正确进程的运行约束、相关 AP 节点加载结果与日志。
已有修复记录可用于加强因果判断，不为验证经验而主动创建或修改策略。

## 参考依据

- [Kubernetes AppArmor 配置与运行状态](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [Kubernetes 1.31 AppArmor 稳定状态说明](https://kubernetes.io/blog/2024/08/13/kubernetes-v1-31-release/)
- [Webhook 只修改必要字段及版本兼容考虑](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
- [准入修改审计](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#monitoring-admission-webhooks)
- [审计请求与响应字段定义](https://github.com/kubernetes/apiserver/blob/master/pkg/apis/audit/types.go)
- [Pod 更新与替换的限制](https://kubernetes.io/docs/concepts/workloads/pods/#pod-update-and-replacement)
- [DaemonSet 模板更新策略](https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/#daemonset-update-strategy)

仓库维护时对照 `manifests/varmor/templates/daemonsets/agent.yaml`、
`internal/agent/agent.go`、`pkg/lsm/apparmor/apparmor.go`；分发后的诊断以现场版本和证据为准。
