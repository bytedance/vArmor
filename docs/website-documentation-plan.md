# vArmor 网站文档架构与实施计划

- 日期：2026-09-22
- 目标仓库：bytedance/vArmor
- 工作分支：update-docs
- 状态：已按 A/B/C/D 实施；本文是维护者实施文档，不加入网站导航。
- 验证结果与未完成的集群验证范围见 [验收记录](website-documentation-validation.md)。

## 1. 目标与范围

让用户在网站内完成以下过程，而不必先阅读源代码、博客或遍历测试目录：

1. 理解 vArmor 的用途、工作方式及防护边界。
2. 根据安全目标、运行环境选择 enforcer 和策略模式。
3. 安装适用版本，运行第一个可验证的策略。
4. 编写自己的策略，确认目标工作负载和规则真正生效。
5. 完成更新、凭据轮换、故障排查、撤销和升级。

本轮重点是公共使用路径和 NetworkProxy 使用指南。AppArmor、BPF、Seccomp 同时获得有实际内容的入口页，但不重复编写安装、CRD 和公共策略管理手册。保留现有 URL、文档 ID 和常用锚点；不为目录整齐进行大规模文件迁移。不修改产品行为，不发布网站，不自动提交已有用户文件。

## 2. 当前网站的主要缺口

- `getting_started/index.md` 和 `guides/index.md` 只有文档卡片，没有按用户目标提供阅读顺序。
- `guides/policies_and_rules/writing_policies.md` 主要指向 examples、policy-advisor 和 demos，缺少完整的策略编写与验证过程。
- enforcer 信息分散在简介、安装、策略模式、定制规则和实践页面，缺少统一选择入口。
- NetworkProxy 在实践页和规则/API 文档中已有介绍，但缺少独立的入门、语义、TLS、运维和排障路径。
- 部分“动态更新”“SNI 与 Host 一致”“凭据隔离”等表述过于宽泛，需要回到开源实现及对应版本限定条件。
- 网站默认稳定文档是 `v0.10`，首页两个入门按钮却硬编码到 `/docs/main/introduction`。入口版本不一致。
- 英文、中文、main、v0.10 各有文档副本；仅修改 `website/docs` 无法覆盖默认稳定版读者。

这些是本轮静态检查发现的文档缺口，不代表新增的产品缺陷。

## 3. 用户路径

| 用户问题 | 入口和阅读路径 | 用户应获得的结果 |
| --- | --- | --- |
| vArmor 能解决什么问题？ | Introduction → 场景与边界 → Enforcers Overview | 知道是否适用，以及应选哪些能力 |
| 如何第一次用起来？ | Getting Started → Installation → Writing Policies | 完成一个允许/拒绝均可验证的策略 |
| 如何限制文件、进程或系统调用？ | Enforcers Overview → 对应 enforcer → 内置/定制规则 | 理解支持的操作、依赖和审计方式 |
| 如何限制应用出站请求？ | Enforcers Overview → NetworkProxy Overview → Quick Start | 先完成明文 HTTP 允许/拒绝，再进入 HTTPS |
| 如何检查 HTTPS 或注入凭据？ | NetworkProxy TLS and Credentials → Policy Semantics | 正确建立信任、配置 MITM 和处理凭据 |
| 策略为什么未生效？ | Usage Instructions → 对应 enforcer 的验证/排障入口 | 区分未选中、未分发、未加载和规则不匹配 |
| 如何上线后维护？ | Usage Instructions / Metrics → NetworkProxy Lifecycle、Observability、Troubleshooting | 知道哪些变更热更新，哪些需要新 Pod 或显式修复模板 |

用户不应必须理解“enforcer”后才能找到功能。Introduction、Getting Started 和 Guides 都提供按“文件/进程保护、系统调用限制、网络访问控制、HTTPS 检查”等目标进入的链接。

## 4. 本轮落地导航

保留现有顶层分类和路径，通过调整侧栏顺序及落地页内容改善体验。下列树表示导航，不要求搬迁现有文件。

```text
Introduction
Getting Started
  Installation
  Usage Instructions
  Metrics
  Interface Specification
Guides
  Enforcers                         [新增，作为能力选择入口]
    Overview and Selection
    AppArmor
    BPF
    Seccomp
    NetworkProxy
      Overview
      Quick Start
      Policy Semantics
      TLS and Credentials
      Security and Compatibility
      Lifecycle and Upgrades
      Observability
      Troubleshooting
  Policies and Rules
    Writing Policies               [补齐，并调整到该分类靠前位置]
    Policy Modes
    Built-in Rules
    Custom Rules
  Policy Tools
  Performance
  Development
Practices
```

- **Introduction**：价值、体系结构、能力边界、下一步。保留现有 Quick Start 锚点，将其整理成简短入口，不维护第二套长教程。
- **Getting Started**：先决条件、安装、首次使用和公共管理入口。落地页给出推荐顺序，直接链接 Writing Policies，不新增内容重复的 First Policy 页面。
- **Enforcers**：选择与特有行为。Overview 给出任务、依赖、能力、限制、策略模式和可组合方式的对照；组合能力以开源代码支持为准，不暗示任意 enforcer 都能组合。
- **Policies and Rules**：跨 enforcer 的策略结构、模式、规则目录和编写方法。
- **Practices**：围绕真实任务组织场景、设计选择和验证结果；链接使用指南，不承载唯一的产品契约。
- **API 与运维参考**：本轮保留已有位置，避免同时迁移安装、指标和接口文档。导航展示与内容归属先清晰起来，将来内容规模需要时再独立拆分 Operations / Reference，并保留旧路由。

继续使用当前自动生成侧栏，通过目录 index 和 sidebar_position 控制导航。版本快照侧栏需要单独更新和验证，不能假定修改 current 侧栏会自动覆盖 v0.10。

## 5. 每类内容只有一个权威位置

| 内容 | 权威页面 | 其他页面如何使用 |
| --- | --- | --- |
| 集群依赖、Helm 安装、全局配置和卸载 | Installation | 摘要关键前提并链接，不复制整张参数表 |
| 选择目标、策略作用域、公共状态与操作 | Usage Instructions / Writing Policies | enforcer 教程只展示完成任务所需步骤 |
| 字段类型、默认值、校验、不可变属性 | Interface Specification | 指南解释行为并链接字段参考 |
| 模式兼容性、内置规则、定制语法 | Policies and Rules | enforcer 页提供适用范围和定位链接 |
| enforcer 特有的运行依赖、行为和限制 | 对应 Enforcer Guide | 简介和实践页概述后链接 |
| NetworkProxy 规则匹配和流量链选择 | NetworkProxy Policy Semantics | 示例在相关步骤提醒容易误解的条件 |
| TLS 信任、secretRef 和凭据轮换语义 | NetworkProxy TLS and Credentials | 生命周期页引用轮换流程，不另写冲突版本 |
| 公共指标定义 | Metrics | NetworkProxy Observability 解释如何结合指标定位问题 |
| 具体场景的完整策略及结果 | Practices / 可执行示例 | 不在场景页重新定义规则或安全承诺 |

Writing Policies 负责“为什么这样写、如何验证”；Usage Instructions 负责公共操作和状态；Interface Specification 负责字段定义。通过这个边界避免三页都成为不完整的使用手册。

## 6. 公共页面的具体改动

1. Introduction：补“如何开始”与目标到能力的入口；审校动态更新、零侵入和凭据保护的适用边界。
2. Getting Started：提供顺序清晰的任务清单；先检查运行环境，再安装、选择示例、验证和清理。
3. Guides：提供按任务进入的链接及每类文档的职责说明，保留文档卡片作为完整目录。
4. Writing Policies：补完整过程：定义目标 → 选择作用域与 target → 选择 enforcer/mode → 编写最小规则 → 应用 → 验证允许和拒绝 → 排查 → 更新/撤销。说明不同 enforcer 的验证和审计方式不同；不提供一个假定适用于所有环境的策略。
5. Installation：补 NetworkProxy 的运行和权限前提入口；复用已有资源配置、runtime 和 iptables backend 说明，避免重复。将“无内核 LSM 依赖”与“没有环境限制”区分开。
6. Custom Rules：保留语法和简短示例；明确 TLS 透传不能据此检查 HTTP path/method，MITM 前提必须与示例同时出现。
7. Policy Modes：校准 enforcer/mode 兼容性与 allowViolations 的适用范围。
8. Interface Specification：保留字段权威地位，核对 immutable 属性、secretRef 解析/更新语义和资源覆盖顺序，补到指南的交叉链接。
9. Practices：保留场景价值，删改与实际链选择、动态更新和凭据可见性不符的绝对承诺；指向完整指南。
10. 首页：让面向普通用户的入门按钮进入默认稳定文档；main 作为明确的未发布版本入口。采用项目适用的版本及 locale 链接方式，避免把新的硬编码版本散布到页面。

## 7. Enforcers 新页面

拟新增于 `website/docs/guides/enforcers/`：

- `index.md`：Overview and Selection。能力对照、运行依赖摘要、模式/组合支持、根据目标选择、指南入口。
- `apparmor.md`：适用目标、宿主机支持和运行前提、策略到 profile 的关系、规则入口、验证与审计、主要限制、示例链接。
- `bpf.md`：BPF enforcer 的能力范围、内核/运行时要求、与 NetworkProxy 网络控制的区别、规则入口、验证与审计、主要限制。
- `seccomp.md`：系统调用过滤的能力与限制、部署前提、支持模式、策略应用生命周期、验证与审计、示例入口。

三页按相同问题组织，但具体限制和生命周期分别查证；不把它们写成通用模板的替换名称版本。以后某个 enforcer 的教程、排障和运维内容足够多时，可扩展为目录并保持原入口 URL；现在不创建空分类。

## 8. NetworkProxy 八页的职责

拟新增于 `website/docs/guides/enforcers/networkproxy/`：

| 文件 | 必须回答的问题 |
| --- | --- |
| `index.md` | 适用场景、sidecar/流量重定向工作方式、HTTP/TLS 透传/MITM/TCP 能力矩阵、防护及归因边界、教程入口 |
| `quick-start.md` | 从零建立隔离示例：目标服务、客户端、策略、允许/拒绝断言、后端与审计证据、清理 |
| `policy-semantics.md` | 同一规则与多个规则的关系、L4/L7 组合、deny/allow、链选择、默认行为、host/SNI/path/method、IP 与域名、domain fronting 边界 |
| `tls-and-credentials.md` | 应用到 Envoy、Envoy 到上游两段信任；MITM 域名与授权规则；证书固定；header 注入、secretRef、轮换和敏感配置保护 |
| `security-and-compatibility.md` | init/sidecar 的权限和 UID、业务能力限制、Pod 级作用域、PSS、运行时、地址族/协议覆盖、代理共存等支持边界 |
| `lifecycle-and-upgrades.md` | 创建/更新/删除策略如何影响模板和运行中 Pod；动态配置与静态 bootstrap；首次启用 MITM、镜像更新、旧模板修复、回滚和撤销验证 |
| `observability.md` | 策略状态、实际 Envoy 配置和流量证据的区别；审计类型/字段/粒度；日志位置与 runtime 差异；指标入口 |
| `troubleshooting.md` | 按现象定位：未注入、启动失败、请求绕过/误拒绝、TLS 错误、配置未更新、凭据未轮换、审计缺失；安全的检查命令和恢复步骤 |

关键约束必须出现在用户将要执行相关操作的位置，完整原理再链接到专页。例如 MITM 教程在安装 CA 时解释信任边界，secretRef 示例旁说明解析后写入代理配置及源 Secret 更新行为；不能只在最后一页放一份长免责声明。

### 8.1 必须逐项核对的公开契约

以下是写作检查项，不是未经查证的能力承诺：

- HTTP、TLS 透传、MITM、TCP 的实际匹配字段、链选择与审计行为。
- L4 allow 与 L7 限制的组合关系，MITM domains 与允许列表的关系。
- SNI、HTTP Host 和目标 IP 的关系，哪些一致性或绑定没有实现。
- secretRef 的命名空间、解析时机、配置中明文值的可见范围、缺失/非法值处理、源 Secret 更新是否触发 reconcile。
- 两段 TLS 信任、SDS 更新、应用 CA reload、已有连接和证书缓存之间的差别。
- init/Envoy 实际 UID、安全上下文和权限；业务 UID 冲突和切换 UID 的影响。
- UDP/QUIC、IPv6、hostNetwork、其他 sidecar/Service Mesh、Kata 等按具体版本和证据标记；区分不支持、有条件支持和未验证。
- 首次注入、规则更新、首次 MITM、资源/镜像更新、静态 bootstrap、旧模板恢复、删除策略分别需要什么动作。
- Ready、Secret 更新与实际代理接受新配置的区别。
- DENIED/AUDIT 的语义及 L4/L7 审计粒度；不能只凭 HTTP 403 判断是代理拒绝。
- Envoy 原生能力不等于 vArmor 对外支持的配置接口；ext_proc 等只按实际 API 支持情况说明。

VKE 文档和以前的集群测试作为检查线索；公开文档以开源仓库、对应发布版本和可复现证据为依据。不能将 VKE 的实现、环境结论或待办设计直接复制成开源产品支持承诺。

## 9. 示例和阅读体验

- 第一条成功路径使用隔离 namespace 和自有测试后端，避免依赖真实 API Key、第三方接口配额或生产 CA。
- 第一个示例只展示必要的明文 HTTP 规则；TLS 透传、MITM、凭据注入逐步扩展。不能让用户先完成 MITM 才能理解基本策略。
- 每个教程都有：目标、版本/依赖、可复制资源、执行顺序、预期结果、证据、清理、下一步。
- deny 验证结合客户端结果与后端是否收到请求；需要审计证据时明确何时、何处能看到什么。
- 给出配置传播的等待条件和超时后的排障入口，不用固定 sleep 代替有效性检查。
- 快速开始提供完整最小 YAML；规则参考可用明确标注的片段，不能混淆可直接 apply 的资源与伪代码。
- 优先复用 `test/examples` 中经过验证且适合教学的资源。网站片段和可下载文件必须对应同一份内容；实施时优先采用可构建的源码引用方式，若需要生成静态副本，则明确源文件和同步检查，不手工长期维护多份独立 YAML。
- 网站代码块不能引导用户打印生产 header、完整敏感 LDS 或 Secret；排障展示必要字段或脱敏输出。
- 博客作为版本背景和案例补充，不能成为完成基本配置的必读材料。

## 10. 版本、语言与链接策略

本轮交付需要覆盖下列四个入口，按对应版本分别核对内容：

| 内容 | 位置 |
| --- | --- |
| 英文 main | `website/docs/` |
| 中文 main | `website/i18n/zh-cn/docusaurus-plugin-content-docs/current/` |
| 英文 v0.10 | `website/versioned_docs/version-v0.10/` |
| 中文 v0.10 | `website/i18n/zh-cn/docusaurus-plugin-content-docs/version-v0.10/` |

- 先在 main 建立结构和事实基线，再核对发布代码，将适用内容落到 v0.10，随后对齐双语语义；最终应一并交付，不能让稳定版和中文入口长期缺失。
- v0.10 是版本系列，不代表系列内所有补丁都有相同能力。涉及后续补丁的功能和修复标注最低版本；尚未发布的行为仅进入 main。
- 保留 v0.9 及更早版本历史，不批量灌入新指南。
- 保留既有 doc ID、slug 和公开锚点。若必须调整，提供重定向或兼容锚点，并检查旧入口。
- 正文优先使用能保持当前版本和语言的内部文档链接。已发布教程不得不加说明地链接到 GitHub main 上持续变化的配置示例。
- 双语核对策略字段、限制、预期错误和最低版本，不能只比较标题数量。
- 审校原有示例和声明时同步检查四份副本，避免新指南正确而旧页面仍有相反承诺。

## 11. 实施顺序与交付批次

### 批次 A：公共路径和导航

补 Introduction、Getting Started、Guides 的导读；建立 Enforcers 选择页及三个实质入口页；补 Writing Policies；修正首页版本入口；保持原路由可用。先确定 NetworkProxy 页面的名称和链接目标，再在批次 B 补完整内容，未完成的空页不作为最终交付。

### 批次 B：NetworkProxy 完整使用闭环

以开源实现建立行为和支持矩阵；完成八页指南及示例；同时修正现有 Custom Rules、Practices、Installation、Policy Modes 和 API 页面中的冲突或过度承诺。安全边界、生命周期和排障是本批必需内容，不作为以后可选优化。

### 批次 C：稳定版本和双语一致性

检查发布版本差异，更新 v0.10 文档和版本侧栏；完成中英文对齐；修复跨版本、跨语言和博客/首页的入口问题。

### 批次 D：构建与用户路径验收

完成构建、链接、示例、渲染和阅读路径验证。提交交付说明，列出已验证的命令、尚未运行的集群验证、剩余已知限制。不把静态检查或以前的 VKE 结果写成本次开源教程实测。

这些批次是审阅单位；不能以只完成目录或入口页作为整个文档任务完成。

## 12. 验收标准

### 内容验收

- 新用户不用浏览 GitHub 测试目录即可找到环境要求、选择合适的能力并执行第一个策略。
- 从 Introduction / Getting Started 到 NetworkProxy Quick Start 有直接、清晰的入口。
- AppArmor、BPF、Seccomp 均能从统一入口找到前提、规则、验证和限制。
- 快速开始同时验证允许和拒绝，说明证据和清理步骤。
- HTTPS 透传示例不会暗示可以检查未解密的 HTTP path/method。
- 用户能找到 UID/权限、CA 信任、secretRef 轮换、L4/L7 组合和动态更新边界，且与示例一致。
- 用户能区分策略被控制器接受、代理加载配置和真实流量执行效果。
- 每条关键限制都有开源代码/测试或版本证据支撑；无法确认的项明确保留为待核验，不能填成支持。

### 工程验收

- 记录网站原有构建和链接告警基线；当前配置把 broken links 设为 warn，不能只凭退出码 0 宣称链接通过。
- 构建英文和中文全部适用版本，检查新增 MDX、侧栏、图片和锚点；本轮引入的 broken links 为零。
- 检查首页、文档版本切换、语言切换和侧栏实际渲染，避免进入错误版本或丢失目标页面。
- YAML 做语法及匹配版本 CRD 的校验；需要集群的 apply、admission、注入和请求结果另行记录验证范围。
- 运行教程时只操作自有隔离资源，结束后清理；不修改其他工作负载或复用生产凭据。
- 检查 Git diff，保留原有用户文件；文档任务不夹带产品代码修改或大范围格式化。

## 13. 后续扩展边界

本轮不将四种 enforcer 扩展成四套重复手册。以后按用户实际问题增补 AppArmor/BPF/Seccomp 的专用教程、兼容性或排障页面；公共策略编写和 API 参考仍共享。若独立运维和参考内容明显增长，再考虑顶层 Operations / Reference 分类，届时单独规划路由兼容。

本轮完成的判断是用户能沿着网站完成学习、配置、验证和维护，而不是新增了多少篇文章。
