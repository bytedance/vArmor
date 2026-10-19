# 运行时审计事件查询（Audit）

执行与授权遵循 [统一约定](README.md)。用于关联业务错误与 vArmor 的运行时处置，
按实际 enforcer 选择来源。日志位置、版本和字段边界见
[违规日志参考](../references/modules/violation-log.md)。

## 1. 从业务现象确定范围

先取目标容器 state/lastState、退出码、signal、重启和时间；必要时读取有限业务日志。
已有这些事实时直接复用，不必重新查询。

```bash
kubectl --context <context> -n <namespace> get pod <pod-name> -o jsonpath='{range .status.containerStatuses[*]}CONTAINER={.name}{"\n"}STATE={.state}{"\n"}LAST_STATE={.lastState}{"\n"}RESTARTS={.restartCount}{"\n"}{end}'
kubectl --context <context> -n <namespace> logs <pod-name> -c <container-name> --since-time=<RFC3339-start> --tail=200 --timestamps
# 重启相关时按需加 --previous；上一个实例不存在不等于权限/连接失败。
```

根据错误时间选择窗口；kubectl logs 无结束时间筛选时，在本地核对到期末的记录。
关键词可以缩小候选，但允许查看必要的上下文；错误行也可能含凭据，展示前脱敏。
`EPERM/EACCES` 可能来自 vArmor、DAC、SELinux、runtime 或业务自身；`SIGSYS/Bad system call`
也可能来自其他 Seccomp 沙箱。exitCode=137 需结合 OOMKilled/事件，不能直接当 OOM。

## 2. 定位事件来源

从 Pod nodeName 找该节点 agent，结合 DaemonSet owner、容器和 Pod 生命周期确认候选。
异常/旧 agent 的日志仍可取证，不以 Running+Ready 作为查询前提；exec 时再确认具体运行容器。

- **组件运行错误**：读取目标节点 agent 的有限 stdout 日志，检查审计采集、身份关联、加载或
  写日志错误。未出现事件不能据此认定无违规。
- **统一违规文件**：优先已知来源的受限本地副本；否则按实际挂载确认 agent 中的日志路径。
  先读取相关活动文件的有限尾部；需要早期窗口才检查同目录轮转备份。高流量/较早故障时，
  尾部未命中不足以排除，按窗口与文件大小选择受限复制到本地解析，不默认导出全部节点日志。
- **NetworkProxy**：按版本与 runtime 判断 agent ALS、sidecar sink 或部署日志通道；既有
  sidecar access log 可用于辅助关联，但不假定它包含所有规则处置。
- **内核 audit/日志聚合**：已存在对应通道时按时间、节点和 Profile 定向取证，不为此创建
  调试 Pod 或枚举所有 CRD。APM 仅在行为建模问题中使用。

```bash
kubectl --context <context> -n <varmor-namespace> logs <agent-pod> -c <agent-container> --since-time=<RFC3339-start> --tail=300
# 仅在已确认路径与访问授权、且该文件相关时执行；由执行工具限定 exec 时长。
# 限制远端读取行数；日志敏感时将 stdout 写入受限本地文件，解析后仅展示必要摘要。
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- tail -n 500 <confirmed-violations-file>
```

文件缺失、不可读、轮转覆盖与传输失败分开记录。需要目录发现时只列已确认日志目录的浅层
元数据，不递归扫描宿主 `/var/log`。必要原始片段保留事件时间、身份、操作和 action，不默认
用优化 skill 的全节点采集、manifest 或预处理流水线。

## 3. 本地筛选与关联

优先结构化解析 JSON 行，以 `eventTimestamp` 筛选故障区间，再按 profileName、实际 enforcer
和运行身份交叉匹配；policy identity 存在时作为附加校验。Pod UID/containerID 优于单独 Pod 名。
缺字段时保留可关联候选与未知项；格式异常记录为解析失败，不当作零命中。
关键词筛选适合初步搜索，`AUDIT/DENIED/ALLOWED` 只是 action，不能与目标身份用“或”拼接后
当作目标事件。已有本地解析工具可复用，也可由模型做小段解析，不要求使用固定脚本。

分开表达三类结论：

1. **观察到处置**：某 Profile/enforcer 对某操作拒绝或放行；只说明事件直接支持的事实。
2. **与目标关联**：用 Pod UID/containerID，或节点、时间、进程/命名空间与对象映射确认归属。
   短进程缺完整身份时可补强，但 Profile 共享或对象重建等歧义应保留。
3. **解释业务故障**：实际阻断、时间、运行身份和被拒操作共同与业务错误吻合，且替代解释得到
   相应排查。标明置信度，不要求每条事件有固定六字段，也不因字段不全把已证明事实全部抹掉。

`AUDIT/ALLOWED/AUDIT|ALLOWED` 不能证明该动作被拦截；放行事件也不能排除其他 enforcer 的
拒绝。Seccomp 或代理处置按实际 action 与对应版本语义解释，不把字符串 DENIED 当作唯一门槛。

## 4. 无匹配事件的分支

检查：审计开关与 enforcer 语义、agent 采集链路、实际文件与版本、故障窗口、轮转/容器重建、
身份缺失和过滤范围。EnhanceProtect 的 allowViolations/auditViolations 组合按 enforcer 判读；
阻断未记录时不能靠无日志排除。再考虑 runtime 默认 Seccomp、SELinux、DAC、网络隔离或
业务自身错误，不触发新业务行为来强行生成证据。

## 可选汇总要点

业务错误及时间、实际日志来源与读取范围、匹配事件的 enforcer/action/Profile/身份/操作，
可证明的结论与置信度、缺失证据和最小下一探针。规则关联需要结合当前策略实际规则，不能凭
操作名称直接认定某条内置规则。
