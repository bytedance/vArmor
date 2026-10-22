# 策略自动优化

[English](README.md) | 简体中文

这是一个面向 [vArmor](https://www.varmor.org/) 的智能体策略优化 Skill，帮助你减少安全规则对业务的误伤，降低手工定制和反复调试策略的成本。助手协助你从符合安全目标、较严格的 **EnhanceProtect（增强防护）** 策略出发，用真实业务的观察日志逐轮调整，逐步形成更贴合业务的防护策略。

其原理是先将策略以观察模式下发，在约定窗口持续采集违规日志，再由助手把事件关联到实际规则，解释哪些限制与必要业务冲突。你确认取舍后，助手生成并校验删除候选，经最终审核才更新策略；多轮观察与调整让策略逐步收敛。

## 如何工作

1. **选定初始策略**：提供已有 YAML，或让助手根据你确认的目标、Enforcer 和安全要求准备较严格的草稿。
2. **开始观察**：审核并授权下发观察策略，商定观察窗口；助手保存起点证据，并在窗口开始前启动采集。
3. **充分运行业务**：采集就绪后，尽可能触发有代表性的业务行为，例如启动、正常请求、重试、故障恢复和定时任务，让日志覆盖实际需要。
4. **审核并调整**：助手汇总违规、解释规则归因；你决定删除、保留或继续观察，再审核候选策略并确认更新。
5. **重复迭代**：为调整后的策略建立下一窗口，直到约定场景覆盖充分、没有新的确定误伤需要处理。收敛效果取决于业务覆盖，不以日志减少单独判断完成。

**适用范围**：支持命名空间级 `VarmorPolicy` 和集群级 `VarmorClusterPolicy` 的 EnhanceProtect 策略，通过删除已有规则收敛。本 Skill 不优化 DefenseInDepth（深度防护），也不生成 BehaviorModeling（行为建模）模型。

行为建模的产物可供深度防护作为白名单 Profile 使用，深度防护也支持自定义 Profile，见[官方模式说明](https://www.varmor.org/docs/v0.10/guides/policies_and_rules/policy_modes/)。模型中的行为数据还可通过官方 [Policy Advisor](https://varmor.org/docs/v0.10/guides/policy_tools/policy_advisor/) 辅助选择增强防护规则。本 Skill 采用增强防护观察日志收敛，无需先执行行为建模。

## 开始前需要准备什么

只了解流程时，无需执行命令或连接集群；进入执行步骤时需要：

| 你要做什么 | 所需条件 |
|---|---|
| 本地校验或准备策略草稿 | 支持 Skill 且能执行本地命令的助手；Python 3 与 PyYAML。本地校验无需连接集群。 |
| 真实业务观察 | 可用的 vArmor、明确的集群 context、已配置的 `kubectl`，以及策略、agent 和日志读取权限；按所选规则核对实际版本和 Enforcer 能力。 |
| 持续采集 | 类 Unix 本地环境、Python 的 SQLite 支持、持久可写目录，以及能覆盖整个观察窗口的运行进程；需要已授权的 agent 只读 exec 访问。 |
| 读取 agent 日志 | 已确认的日志目录，以及 agent 内的 `sh`、支持 `stat -L -c` 的工具、`tail`、`head`；存在压缩备份时还需 `gzip`、`wc`。 |
| 创建或更新策略 | 对目标策略资源的创建/更新权限，以及你对已审核变更的授权；读取权限不等于变更授权。 |

如尚未安装 PyYAML，可在当前 Skill 目录、助手使用的 Python 环境执行 `python3 -m pip install -r requirements.txt`。Skill 不会自动安装依赖。

提供策略 YAML 或计划保护的工作负载、**context 与 namespace**，并说明准备执行哪些业务场景。应用工作负载和 Pod 由你管理；助手会解释策略生效所需的重建或滚动步骤。可能触发工作负载更新的策略设置会在下发前说明并审核。

## 安装与第一次使用

将完整 `varmor-policy-optimization/` 目录复制到助手的技能目录。保留 `SKILL.md`、`references/`、`playbooks/`、`scripts/` 及其中的数据文件、`templates/`，不要只复制入口文件。其他支持 Skill 的助手请使用其对应的技能目录。

| 助手 | 用户级目录 | 当前项目目录 |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `<项目>/.claude/skills/` |
| Codex | `~/.agents/skills/` | `<项目>/.agents/skills/` |

例如安装到 Codex 用户级目录，将 `/ABS/varmor-policy-optimization` 替换为实际源目录的绝对路径：

```sh
mkdir -p ~/.agents/skills
cp -R /ABS/varmor-policy-optimization ~/.agents/skills/
```

目标已有同名 Skill 时，更新原副本，避免嵌套复制。目录位置与调用方式可查阅 [Claude Code 官方说明](https://code.claude.com/docs/en/skills) 和 [Codex 官方说明](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)。表中 Codex 路径按当前官方文档列出；使用历史版本时，请核对该版本的技能发现路径。

在 Claude Code 中输入 `/varmor-policy-optimization`，在 Codex CLI/IDE 中输入 `$varmor-policy-optimization`，再描述需求；也可用自然语言明确使用该 Skill。如果尚未发现 Skill，可以提供已安装 `SKILL.md` 的绝对路径，让助手读取。后续脚本操作由助手处理。

**本地检查已有 YAML：**

> 使用 varmor-policy-optimization，检查 ./checkout-policy.yaml 是否适合 EnhanceProtect 观察。说明校验结果、需要调整的内容，以及仍可能阻断业务的规则。不要连接集群或下发。

**没有 YAML，先准备草稿：**

> 使用 varmor-policy-optimization，为 staging 集群 shop 命名空间的 Deployment checkout 准备 EnhanceProtect 观察策略。先解释 Enforcer 和规则选择，再按我确认的需求生成草稿，暂不下发。

**建立观察任务：**

> 使用 varmor-policy-optimization，基于 ./checkout-policy.yaml 在 staging 集群准备观察任务。帮我安排覆盖启动、正常请求、重试和定时任务的窗口。先展示策略变更和采集计划，我确认后再开始。

**继续已有任务，也可以换会话：**

> 使用 varmor-policy-optimization，继续 /absolute/path/task.json 对应的任务。检查采集状态，就绪后分析证据。先汇报规则归因，等待我选择删除范围和最终确认更新。

## 观察与更新时需要知道

助手负责校验、采集、归因和候选检查；你负责确认安全目标、覆盖业务场景及审核删除范围。更新前会展示候选和删除 diff，完成服务端校验，并等待你对目标集群和变更的最终确认。

**观察不保证业务完全不被阻断。** 内置规则与基线进入观察，自定义 RawRules 仍保留原动作，可能继续拒绝行为；运行业务前需要审核这些影响。

规则收敛保留 target、enforcer、mode、privileged 和观察开关，不会自动将最终策略切成阻断模式。Seccomp 或注入变化可能需要新容器；相关生命周期操作由你协调，之后验证业务。

## 采集、继续任务与交付

新任务默认增量采集，通常每 30 秒读取一次。每轮日志处理默认 4 MiB，audit exec stdout 默认 16 MiB/滚动分钟，均由本任务全部节点共享；本地存储停止阈值默认 512 MiB。助手会说明约定限额，API 和协议开销不计入 stdout 预算。

保持采集宿主运行，保存**任务绝对路径及其引用的产物目录**。到期后，采集器完成确认读和数据准备；它不调用模型，也不发送通知。由你回来继续，或通过另行安排的宿主自动任务触发分析。业务测试已完成时，也可以明确要求提前结束观察。

无法持续运行采集器时，助手可说明快照回退及日志轮转限制；已经覆盖的日志、事后缺失的起点证据无法补造。

你会得到任务记录、采集与覆盖结论、规则归因及审核决定。有确认删除项时，还会交付候选 YAML、精确删除 diff、分析报告，以及验证和回滚建议。不确定的匹配保持规则不变。

## 观察覆盖决定结果是否可用

- 需要运行业务的代表性场景；日志安静或事件减少，不单独证明策略适用或安全。
- 节点扩缩容、agent 替换或 agent DaemonSet 调度数变化，会阻断本窗口的整策略删除。已有证据仍可只读分析，拓扑稳定后另建窗口。
- 中断后，只有原身份和文件检查点能证明连续时才恢复；无法恢复的缺口或策略漂移阻断删除。
- NetworkProxy 规则删除要求 vArmor v0.10.3+、runc 及合格的节点日志；版本未知、旧版本或 micro-VM 证据不具备本流程的 NetworkProxy 删除资格。

需要排查已有异常时，使用 [自动诊断](../varmor-diagnosis/README.zh_CN.md)。

## 进一步了解

- [SKILL.md](SKILL.md)：供助手执行的指引。
- [增量采集设计](references/incremental-collection.md)：启动、预算、中断恢复与遗留分析任务处理。
- [策略语义](references/enhance-protect-semantics.md)：观察、自定义规则与隐式基线。

<!-- package:source-only:start -->
## 维护者说明

### 从源码安装

在当前 Skill 目录运行；交付工具需要 Python 3.9+：

```sh
python3 install.py --tool codex --project /ABS/PROJECT
python3 install.py --tool both
```

安装器创建指向源码的相对符号链接，Codex 使用所选项目或用户目录下的
`.agents/skills/`，Claude Code 使用 `.claude/skills/`。已有不同安装时拒绝覆盖；
不安装依赖。使用链接期间请保留源码目录。

### 构建分发包

```sh
python3 package.py
python3 package.py --full
python3 package.py --output /ABS/RELEASE/varmor-policy-optimization-skill.zip
```

默认生成 `dist/varmor-policy-optimization-skill.zip`（运行资源、中英文说明和许可证）及
`dist/varmor-policy-optimization-full.zip`（另含安装器、打包器和回归测试），解压后均为
`varmor-policy-optimization/`。精简包移除本节维护说明。打包使用显式文件清单，排除未列入
清单的本地证据、会话、缓存和旧压缩包；构建成功后才替换旧 ZIP。同一 Python/zlib 环境中，
相同输入生成相同字节。新增资源或测试时同步更新 `package.py` 清单；ZIP 用于发布附件，
不要提交生成的压缩包。

### 运行回归测试

在任一仓库的当前 Skill 目录或解压后的完整包中运行：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

两个仓库的测试均直接放在当前 Skill 的 `tests/` 目录，结构一致。

测试使用本地样本，不连接集群，覆盖脚本行为、分发包可移植性与安装冲突处理。
<!-- package:source-only:end -->

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
