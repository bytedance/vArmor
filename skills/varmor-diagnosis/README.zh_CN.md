# 自动诊断

[English](README.md) | 简体中文

这是一个面向 [vArmor](https://www.varmor.org/) 的智能体诊断 Skill，帮助你排查容器防护中的配置、生效与运行异常。遇到“策略显示 Ready，但似乎没有保护”“应用突然出现权限错误”或“Pod 启动失败”等问题时，可以直接把现象告诉助手，由它协助定位原因。

助手结合 vArmor 的工作原理与集群实际状态，沿“目标匹配 → Profile 生成 → Pod 注入 → 节点加载 → 运行时执行”关联策略、事件和日志，区分防护未生效、规则拦截与业务自身异常。你无需先熟悉所有组件或手工串联查询结果。

## 如何工作

1. **描述问题**：提供已知的应用、Pod、策略或节点，以及现象和大致发生时间。
2. **按需取证**：助手从相关状态、事件和日志开始，按线索检查策略链路，必要时补充容器或节点检查。
3. **定位原因**：交叉核对配置与实际运行结果，说明已确认的原因、影响范围和仍缺少的证据。
4. **给出建议**：提供处理方式与验证步骤；需要时整理成正式诊断报告。

覆盖策略、Profile、Webhook、vArmor 组件、行为建模和 NetworkProxy 等相关问题。**诊断全程只读**，不代为修改策略、重启工作负载或调整节点。

## 开始前需要准备什么

| 你要做什么 | 所需条件 |
|---|---|
| 了解问题或分析已有材料 | 支持 Skill 的助手，以及相关配置、状态、事件或日志片段；可以不连接集群。 |
| 排查真实集群 | 助手能执行命令；`kubectl` 已配置目标 context；具备相关资源、事件和日志的读取权限。 |
| 使用可选辅助脚本 | Python 3；脚本仅使用标准库，无额外 Python 包依赖。 |
| 检查容器、节点或主动探测连通性 | 具备该项操作的访问权限与授权；仅在确有需要时使用。 |

尽量提供**集群 context、namespace、一个已知目标、异常现象和大致发生时间**。目标可以是 Pod、工作负载、策略或节点；如果知道 vArmor 版本和近期变更，也一并说明。不需要提前找齐所有对象名称，助手会补充发现和关联。

## 安装与第一次使用

将完整 `varmor-diagnosis/` 目录复制到助手的技能目录。保留 `SKILL.md`、`references/`、`playbooks/`、`scripts/` 及其中的数据文件、`templates/`，不要只复制入口文件。其他支持 Skill 的助手请使用其对应的技能目录。

| 助手 | 用户级目录 | 当前项目目录 |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `<项目>/.claude/skills/` |
| Codex | `~/.agents/skills/` | `<项目>/.agents/skills/` |

例如安装到 Codex 用户级目录，将 `/ABS/varmor-diagnosis` 替换为实际源目录的绝对路径：

```sh
mkdir -p ~/.agents/skills
cp -R /ABS/varmor-diagnosis ~/.agents/skills/
```

目标已有同名 Skill 时，更新原副本，避免嵌套复制。目录位置与调用方式可查阅 [Claude Code 官方说明](https://code.claude.com/docs/en/skills) 和 [Codex 官方说明](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)。表中 Codex 路径按当前官方文档列出；使用历史版本时，请核对该版本的技能发现路径。

在 Claude Code 中输入 `/varmor-diagnosis`，在 Codex CLI/IDE 中输入 `$varmor-diagnosis`，再描述问题；也可用自然语言明确使用该 Skill。如果尚未发现 Skill，可以提供已安装 `SKILL.md` 的绝对路径，让助手读取。

排查业务异常：

> 使用 varmor-diagnosis，排查 staging 集群 shop 命名空间里的 Deployment checkout。修改策略后，约十分钟前开始出现 permission denied。请只读排查，说明是否有证据将异常关联到 vArmor。

排查“策略 Ready，但似乎没有防护”：

> 使用 varmor-diagnosis，检查 staging 集群 shop 命名空间的策略 checkout。它显示 Ready，但应用似乎没有受到保护。请核对目标匹配、实际 Pod 注入和 Profile 使用情况。

只分析本地材料：

> 使用 varmor-diagnosis，分析这些策略 YAML、Pod 事件和审计片段。不要连接集群，说明目前能确认什么、还缺什么证据。

你不需要自行选择操作手册或执行辅助脚本。

## 你会得到什么

你负责补充业务背景，并在调查需要扩大范围时提供相应授权。诊断结果包括：

- 结论、关键证据、置信度及影响范围。
- 已确认事实、可能原因与缺失证据的区分。
- 处理建议和验证步骤，以及相关影响与前置条件；需要时可生成正式 Markdown 报告。

策略 Ready 不单独证明防护生效，权限错误也不单独证明由 vArmor 引起。证据不足时，助手会给出下一项有效检查，不会强行判定根因。

需要创建或收敛 EnhanceProtect 策略时，使用 [策略自动优化](../varmor-policy-optimization/README.zh_CN.md)。

## 进一步了解

- [SKILL.md](SKILL.md)：供助手执行的指引。
- [诊断操作手册](playbooks/README.md)：查询方法、访问边界与证据约定。

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
python3 package.py --output /ABS/RELEASE/varmor-diagnosis-skill.zip
```

默认生成 `dist/varmor-diagnosis-skill.zip`（运行资源、中英文说明和许可证）及
`dist/varmor-diagnosis-full.zip`（另含安装器、打包器和回归测试），解压后均为
`varmor-diagnosis/`。精简包移除本节维护说明。打包使用显式文件清单，排除未列入
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
