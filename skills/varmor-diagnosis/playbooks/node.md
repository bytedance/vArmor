# 节点 enforcer 状态检查（Node）

执行与授权遵循 [统一约定](README.md)。从 AP 失败节点或目标 Pod 的 nodeName 进入，
按实际 enforcer 选用检查；不要求完成整套节点体检。

## 检查目标

区分 agent 未覆盖/启动异常、内核能力不满足、Profile 准备或加载失败，以及已加载但容器未使用。
节点 NotReady、OOM、BUG/Oops/panic 时优先已有 API 与日志证据，避免继续增加节点负担。

## 1. 节点与 agent 的 API 证据

```bash
kubectl --context <context> get node <node-name> -o jsonpath='READY={.status.conditions[?(@.type=="Ready")].status}{"\n"}KERNEL={.status.nodeInfo.kernelVersion}{"\n"}RUNTIME={.status.nodeInfo.containerRuntimeVersion}{"\n"}ARCH={.status.nodeInfo.architecture}{"\n"}'
kubectl --context <context> -n <varmor-namespace> get pods -l <agent-selector> --field-selector spec.nodeName=<node-name> -o wide
```

结合 DaemonSet owner、Pod UID、创建/删除时间、目标 agent 容器 Ready 和重启状态确认身份。
多个 Pod 可能是更新中的新旧实例；保留相关候选并说明角色。不 Ready 的 Pod 仍是状态、事件和
日志的取证对象；无需等到唯一 Running+Ready 才诊断。exec 前再确认单个 Pod 与容器。

优先看相关 AP node condition、agent lastState、事件和有限日志。AP namespace 沿
[policy.md 第 2.1 节](policy.md#21-ap-是否存在且状态正确) 的 VP/VCP 关系或按名称跨 namespace
摘要查询确认，复用前一步结果；CRD scope 不能单独给出 namespace。

```bash
kubectl --context <context> -n <confirmed-ap-namespace> get armorprofiles.crd.varmor.org <profile-name> -o json
kubectl --context <context> -n <varmor-namespace> logs <agent-pod> -c <agent-container> --since=<duration> --tail=300
# 重启相关时，可改用 --previous，区分无上一实例与权限/连接错误。
```

Cluster-scoped AP 不传 namespace。对单 AP 的本地 JSON 按目标 nodeName 筛选 conditions；
失败 reason/message 是加载方向的线索，不直接证明最终根因。

## 2. 按需验证 enforcer 能力

Node API 的版本/架构与 agent 加载错误通常足以决定下一步。复杂版本前置条件可借助：

```bash
python3 scripts/check-enforcer-compatibility.py --context <context> --node <node-name> --enforcer <apparmor|bpf|seccomp>
```

脚本可选。内核版本满足不能证明 LSM 已启用；`TO_PROVE/PARTIALLY_VERIFIED` 可由下面的独立
证据补齐。NetworkProxy 转到专项手册。BTF 只在 BehaviorModeling、版本依赖或加载错误指向它时
检查，不把 BTF 未验证作为普通 BPF enforcer 不兼容的依据。

需要节点视图时，经已有 agent 的已确认挂载做短时定向读取；exec 进入 agent 前确认当前授权
覆盖该容器、路径与读取动作，不能仅因命令只读就推定已获授权。已有覆盖授权无需重复询问。
以下示例一次只选当前问题相关项，显式指定容器，并由执行工具限定 exec 时长：

```bash
# LSM：精确读取一个内核状态文件
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /sys/kernel/security/lsm
# AppArmor 启用状态
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /sys/module/apparmor/parameters/enabled
# BTF 只检查已知文件是否可读，不读取整个 BTF 文件
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- test -r /sys/kernel/btf/vmlinux
```

文件不可访问时区分挂载视图、权限和能力缺失，不自动判不支持。需要挂载信息时一次读取
`/proc/self/mountinfo` 并本地筛选，复用结果；它只描述 agent 的挂载视图。
Seccomp 路径按 agent 参数、volumes/volumeMounts 与日志确认，不默认搜索整个 kubelet 目录。

### 2.1 AppArmor 加载失败时的配置与运行约束

按 [专项路标](../references/troubleshooting/agent-apparmor-load-failure.md) 解释日志与版本差异。
先比较已确认 agent Pod 及其对应模板的相关字段，不用业务 Pod 的配置代替 agent 的配置：

```bash
kubectl --context <context> -n <varmor-namespace> get pod <agent-pod> -o jsonpath='{.spec.securityContext}{"\n"}{range .spec.containers[*]}{.name}{"\t"}{.securityContext}{"\n"}{end}'
kubectl --context <context> -n <varmor-namespace> get ds <agent-daemonset-name> -o jsonpath='{.spec.template.spec.securityContext}{"\n"}{range .spec.template.spec.containers[*]}{.name}{"\t"}{.securityContext}{"\n"}{end}'
```

结合 Pod 创建时间与模板修订排除旧实例；按实际容器名定向读取对应 AppArmor 旧注解，避免
整体展示 annotations。容器字段缺失时检查 Pod 级继承及该版本的注解兼容，不直接认定受限。
若线上 DaemonSet 模板也缺字段，向前比较安装渲染清单并调查 DaemonSet 请求；模板有而 Pod
没有时，调查对应 Pod 请求。不要将两个层级的安全上下文路径混用。

已有授权覆盖时，下面两项按需选择，读取失败保留错误：

```bash
# exec 命令自身的 AppArmor 状态；若该内核不提供专用路径，可选 /proc/self/attr/current。
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /proc/self/attr/apparmor/current
# 核对实际管理进程时，先从已有运行时/进程信息确认 PID，再定向读取。
kubectl --context <context> -n <varmor-namespace> exec <agent-pod> -c <agent-container> -- cat /proc/<confirmed-agent-pid>/attr/apparmor/current
```

hostPID 环境下 `/proc/1` 可能指向宿主机 init，不能当作 agent 状态。exec 进程与 agent/parser
存在 profile 切换时需分别确认；属性读取失败不能当作 `unconfined`。

接口问题复用已确认挂载与一次 `/proc/self/mountinfo` 读取，核对接口是否可见、挂载是否只读。
需要权限证据时，可从已确认进程的 `/proc/<pid>/status` 等已有信息核对实际 capabilities，
再按时间、进程、profile、operation 和路径关联有限内核审计；声明了管理能力不能代替实际状态。
不通过加载 Profile 或写入 `.load`、`.replace` 等内核接口测试权限。
配置差异的修改来源按专项路标追查，覆盖创建及后续更新；不预设来自 Webhook。

需要追查写入来源时，使用已有审计通道按 namespace、对象名/UID 和时间筛选，复用已提供记录。
保留 auditID、stage、verb、objectRef（含 subresource）、requestURI、调用/模拟身份、userAgent、
来源、responseStatus，以及相关字段的请求/响应差异；旧注解、容器和 Pod 级字段一并按需核对。
Request 级别可有请求体，RequestResponse 级别可有响应体；缺失内容注明未采集，不假设总能读取。
只展示必要的脱敏字段，不输出完整请求体。完整 UPDATE 与 PATCH 按各自语义解释，确认请求
是否成功，再与同 UID 的前后版本关联；审计请求不等于实际写入。
怀疑准入修改时，按同次请求的 auditID 关联 Webhook 调用与可用补丁，检查是否删除字段或替换
其父对象；仅有“发生过 mutation”的标记不能证明修改了 AppArmor 配置。无补丁时注明证据缺口，
不根据匹配范围或旧依赖版本直接给出确定归因。具体判读见专项路标第 4 节。

## 3. 目标 Profile 是否落地

先使用 AP node condition 与该节点 agent 日志；只有证据不足时才补充以下检查。

- **AppArmor**：需要核对具体 Profile 时，可读取内核 Profile 列表并按已确认名称精确匹配，
  复用一次结果。`aa-status` 是可选替代，不要求两种方式都执行；列表未包含目标也要确认读取成功。
- **Seccomp**：确认实际挂载点与文件名后用 `test -r <exact-profile-file>` 或 `stat` 检查。
  文件名未知才做浅层搜索，限定目录、深度和时长，不默认递归 `find`。文件存在只证明资源存在，
  不证明容器已使用；文件可读性也是当前 agent 身份下的事实。
- **BPF**：先从日志、AP 和已知 bpffs 对象引用定位。需要 bpftool 时优先查询已知 ID/对象；
  没有定位线索且确有必要才枚举程序/映射，评估节点开销并限制时长。关键词可发现候选，
  名称无匹配不能直接写“没有 vArmor 程序”。

加载成功后仍需核对实际 Pod 的 Profile 引用和运行时身份，见 `workload.md` 与 `audit.md`。
Seccomp 规则变化需要新容器生效，不能由文件存在或 AP Ready 推断旧容器已更新。

## 4. 内核异常分支

节点事件、agent 错误与已收集内核日志先按故障时间关联。需要 journal/kernel 日志时限定
时间与读取量，优先现有节点日志通道，不创建特权调试 Pod 或进入宿主命名空间。
BPF 加载与 BUG/Oops/Call Trace 同时出现只能先建立时间关联；建议按节点风险处理，
不要通过反复加载 Profile 验证。隔离节点、切换 enforcer、升级内核只提供建议。

## 可选汇总要点

当前节点与 agent 身份、失败 AP 条件、相关能力证据、Profile 落地与实际使用的区别，
以及节点风险、未确认项和最小下一探针。仅汇总已采集且与问题相关的项。
