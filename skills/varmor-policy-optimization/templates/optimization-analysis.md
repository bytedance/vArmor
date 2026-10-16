<!--
优化分析报告模板。一次优化只依赖"用户给的时间戳闭区间 + 起点策略快照 + 当前策略"，
不依赖隐藏轮次状态。
括号占位符按实际情况替换；没有内容的小节明确写"无"，不要删除小节。
-->

# vArmor 策略优化分析

## 1. 范围

- 目标策略：<VarmorPolicy|VarmorClusterPolicy> <namespace>/<name>（VCP 的 namespace 为空）
- 时间窗口：start=<原始时间戳>，end=<原始时间戳>（固定闭区间）
- 采集完成：collectionStartedAt=<最早节点采集起点>，manifestBuiltAt=<epoch>，
  windowComplete=<true|false>
- 采集模式：<incremental|snapshot>；增量节点 coveredFrom / lastReadStartedAt / lastDrainedAt、
  backlogBytes 与 collectionIssues：<摘要；快照 N/A>
- 增量末次确认：<逐节点 firstCleanCompletedAt / confirmationReadStartedAt / 扫描间隔；快照 N/A>；
  疑点恢复：<resolvedAt / recoveryBasis 或仍阻断的原因>
- 采集预算：<audit exec stdout 滚动限额与实际账本摘要；不含 API 元数据/协议开销；快照 N/A>
- 目标集群 / context：<cluster / context>
- 起点策略快照：capturedAt=<epoch>，uid=<uid>，generation=<n>，resourceVersion=<rv>，specSha256=<hash>
- 起止一致性：<一致|漂移；resourceVersion-only 变化单列>
- 规则表来源：catalogProvenance=<version@commit>
- 实际使用规则兼容性：<verified|unknown|incompatible>；依据：<已验证版本范围或具体缺失规则>

## 2. 日志概况

- 原始日志：<n>；窗口内匹配：<n>；窗口外：<n>；属其他策略：<n>；解析失败：<n>
- 起止 Agent inventory：<capturedAt 与 desired/current/ready>；拓扑变化：<节点增删/Pod UID/DS 或无>
- 起止节点并集/实际采集节点：<集合摘要>；节点覆盖：<完整|不完整>
- NetworkProxy 证据：status=<not-applicable|eligible|ineligible>；模式=<node-central-runc|其他>
- 逐节点 retention 证据：<node：earliest/latest/basis>；日志保留覆盖：<完整|未知>
- 无效日志（Envelope / event）：<n>
- 非 Seccomp 聚合事件：<n>；Seccomp syscall：<去重列表>

## 3. 归因结论

对每个聚合事件列出：eventId、业务行为摘要、matches（source + rule + context.targets）及证据
（事件字段与规则限制如何对应；enforcer 兼容性）。

- 已确定关联：
  - <eventId>：<rule>（<evidence>）
- 一个事件多匹配：<eventId>：<rule A>、<rule B>
- 无法归因 / 证据不足（matches 为空）：<eventId：缺什么>

## 4. 本次移除的规则

用户确认记录：<2.1.5-attribution.json 路径；每个 match 的 decision；对应用户确认消息/时间>。
最终审核哈希：<candidate SHA256；恢复 shell 时从本记录读取，不重新生成审核值>。由 guard 计算的结构化
diff（只含删除）：

- <source>：<rule>（enforcer=<…>，关联事件=<eventId>）
- 合计：<n> 条

## 5. Seccomp 歧义与扩大允许范围风险

- 多规则命中的 syscall：<syscall：原始命中哪些规则>；处理结果：<全部保留|用户已确认部分或全部删除及歧义>。
- 内置规则决定：<builtinRemovals / keptBuiltinRules；无候选时写无>。
- 自定义 syscall 组决定：<customRemovals / keptSyscalls / keptCustomRules>。
- 重建参数：<remove/keep-seccomp-rule、remove/keep-seccomp-syscall、allow-ambiguous 的确认值>。
- 忽略的非限制型 RawRule：<SCMP_ACT_ALLOW/LOG 完整规则；不进入删除候选>。
- 未匹配 syscall：<列表>

## 6. 基线来源（删规则无效）

归因到隐式 RuntimeDefault 基线、不属于任何策略原子规则的事件：
- <事件>：删规则无法消除；需用户决策（接受 / `privileged=true`，注意后者同时移除基线与 Seccomp）。

## 7. 待进一步观察

低频、偶发、覆盖不足或业务语义不明确、本轮未移除的规则/行为：
- <描述：为何留观>

## 8. 风险提示

观察窗口是否覆盖启动/发布/扩缩容/定时任务；规则移除后影响面可能大于单条事件；多 enforcer
关联；版本差异等：
- <风险点>

## 9. 验证与回滚

- 变更对象与方式：<apply 单个 VP/VCP CRD>
- 生效边界：AppArmor/BPF 检查实际 Profile 加载；Seccomp/注入变化需新容器，
  `updateExistingWorkloads=true` 不保证规则更新触发滚动。
- 验证：更新后观察 <策略状态 / 新 Pod / 业务表现>；下一窗口建议起始时间戳：<timestamp>。
- 回滚：保留变更前 YAML 作为规则恢复依据。其 resourceVersion 已过期，不能原样 apply；
  重新读取当前对象，按独立确认的回滚流程恢复规则、server dry-run、审核 diff 后执行。

## 10. 下一观察任务

- 任务记录：<下一轮任务记录绝对路径>
- 建议窗口：start=<timestamp>，end=<timestamp>；选择依据：<业务周期 / 日志速率 / 保留能力>。
- 触发方式：<一次性定时任务 | 提醒 | 用户手动继续 | 本轮结束不再观察>
- 自动化边界：自动任务最多采集日志并完成归因汇总；先等待用户决定删除范围，再生成候选策略；
  更新 CRD 仍需最终确认。

## 11. 数据处置

- 运行目录：<本地目录；权限 0700>
- 脱敏说明：<报告中省略或泛化的业务路径、进程和网络目标>
- 留存与清理：<保留期限或用户确认后的清理安排>
