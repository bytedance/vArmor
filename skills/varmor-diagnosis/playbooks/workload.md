# Workload/Pod 注入与生命周期验证（Workload）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
验证目标 Pod 是否已获得 vArmor 注入，并区分「PodTemplate 未注入」「模板已注入但 Pod 未更新（旧 Pod）」「Pod 已注入但 Profile 未加载」「注入后被其他机制覆盖」。这是「策略已就绪但无防护」最核心的验证环节。

## 适用场景
- 策略/AP Ready，但目标 Pod 无加固行为
- Pod Pending/ContainerCreating 涉及 Profile 报错
- 部分 Pod 有防护、部分没有
- 容器 Crash/权限错误但不确定是否 vArmor 导致

## 前置依赖
- 已知目标 namespace、Workload 类型与名称（kind 必须与实际资源一致：deploy/statefulset/daemonset）或 Pod 名称
- 已知策略 profileName（从 [policy.md](policy.md) 获取）
- 已知策略使用的 enforcer

---

## 1. Workload 生命周期验证

策略更新后，旧 Pod 不会自动获得新注入。必须区分 PodTemplate 状态和实际 Pod 状态。

### 1.1 PodTemplate 注入检查

可直接读取相关 SecurityContext、annotation 或容器字段；需要成组提取时使用以下可选脚本。
已有对象 JSON 可本地分析，不必为调用脚本重新查询。

```bash
# 从 Skill 根目录执行；kind 仅允许 deployment/statefulset/daemonset。
# 脚本只提取 PodTemplate 的 annotation 键名、SecurityContext、容器、镜像和 volume 引用。
# initContainer 额外输出 AppArmor/Seccomp、privileged 和 capability add/drop 事实。
python3 scripts/inspect-injection.py \
  --namespace <namespace> \
  --kind <deployment|statefulset|daemonset> \
  --name <workload-name>
```

`INTERPRETATION status=NOT_EVALUATED` 是预期输出：这些是注入相关事实，不代表脚本已判定 vArmor 是否完成注入。必须结合策略 enforcer、profileName、实际 Pod 和已确认的 vArmor 组件名称解释。

### 1.2 实际 Pod 列表与创建时间

```bash
# 发现目标 Workload 的候选 Pod，随后按 ownerReferences 确认归属
kubectl -n <namespace> get pods -l <workload-label-selector> -o wide --sort-by=.metadata.creationTimestamp

# 仅 Deployment 通过 ReplicaSet 管理 Pod；用于判断 Pod 属于哪个模板版本
kubectl -n <namespace> get rs -l <workload-label-selector> -o custom-columns='NAME:.metadata.name,DESIRED:.spec.replicas,CURRENT:.status.replicas,READY:.status.readyReplicas,AGE:.metadata.creationTimestamp'

# 对待验证 Pod 提取创建时间、唯一 controller owner 和注入相关事实。
python3 scripts/inspect-injection.py \
  --namespace <namespace> \
  --kind pod \
  --name <pod-name>
```

label selector 用于发现候选，ownerReferences 与控制器关系用于确认归属；不把相同 label 的 Pod 全部当作该 Workload 管理。

**生命周期判断逻辑：**
1. 如果 PodTemplate 有注入 → 新创建的 Pod 应该有注入
2. 如果实际 Pod 没有注入但 PodTemplate 有 → 比较 Pod 创建时间和策略生效时间/模板更新时间
3. Deployment Pod 属于旧 ReplicaSet，或 StatefulSet/DaemonSet Pod 创建早于当前模板 → 当前 Pod 仍可能使用旧配置
4. 如果是裸 Pod（无 ownerReferences）→ 策略更新/Webhook 恢复不会自动修改已存在的裸 Pod

### 1.3 PodTemplate 与实际 Pod 的注入对比

对比模板与实际 Pod 的等价字段；使用脚本时可参考输出中的 `ANNOTATION_KEY`、`POD_APPARMOR`、`POD_SECCOMP`、`CONTAINER_SECURITY`、`INIT_CONTAINER`、`INIT_CONTAINER_SECURITY`、`CONTAINER` 和 `VOLUME`：

- `UNSET` 是对象中没有该标准 SecurityContext 字段，不代表对应 enforcer 一定未注入；
- `INIT_CONTAINER_SECURITY` 中的 `NET_ADMIN` 等 capability 只是注入交叉证据，不能单独证明该 initContainer 来自 vArmor；
- annotation 只输出键名。确认键名属于 vArmor 后，如确需核对 Profile 引用，再定向读取该单个键值；
- `VOLUME source_type=hostPath source_name="REDACTED"` 只证明存在 hostPath，不暴露节点路径；
- 容器、镜像、volume 只是交叉证据，不能通过 `proxy`、`bpf` 等泛词单独认定为 vArmor 注入。

---

## 2. Pod 注入痕迹清单

根据策略使用的 enforcer，逐一检查实际 Pod 是否有对应注入。annotation 可先列键名发现候选，再定向读取必要的非敏感值（Profile 引用、开关等）；避免展示无关或敏感配置。

### 2.1 AppArmor 注入痕迹

```bash
# 旧版 annotation（键名是 k8s 稳定 API，直接查键名是否存在）
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}' | grep -i 'apparmor.security.beta.kubernetes.io'

# 新版 SecurityContext（Pod 级 + Container 级）
kubectl -n <namespace> get pod <pod-name> -o jsonpath='POD_APPARMOR={.spec.securityContext.appArmorProfile.type}{"/"}{.spec.securityContext.appArmorProfile.localhostProfile}{"\n"}'
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}CTR_APPARMOR[{.name}]={.securityContext.appArmorProfile.type}{"/"}{.securityContext.appArmorProfile.localhostProfile}{"\n"}{end}'
```

**正常注入值：**
- Annotation: `container.apparmor.security.beta.kubernetes.io/<container-name>: localhost/varmor-<profile-name>`（profile 后缀需与 AP profileName 一致）
- SecurityContext: `type: Localhost`, `localhostProfile: varmor-<profile-name>`

### 2.2 Seccomp 注入痕迹

```bash
# Pod 级
kubectl -n <namespace> get pod <pod-name> -o jsonpath='POD_SECCOMP={.spec.securityContext.seccompProfile.type}{"/"}{.spec.securityContext.seccompProfile.localhostProfile}{"\n"}'
# Container 级
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}CTR_SECCOMP[{.name}]={.securityContext.seccompProfile.type}{"/"}{.securityContext.seccompProfile.localhostProfile}{"\n"}{end}'
```

**正常注入值：** `type: Localhost`, `localhostProfile: varmor/<profile-name>.json` 或类似路径

### 2.3 BPF 注入痕迹

```bash
# BPF 注入通过 vArmor 自定义 annotation 标记；键名因版本/部署而异。
# 先列出全部 annotation 键名，再根据 AP 中 profileName 和部署已知键名定向查找；
# bpf/sandbox 等通用词可用于发现候选，不能仅凭关键词认定来源
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}'

# 确认具体 BPF annotation 键名后（从 AP 或已知部署配置获取），再定向查询单个键值：
# kubectl -n <namespace> get pod <pod-name> -o jsonpath='{.metadata.annotations.<confirmed-bpf-key>}'

# 如加载证据指向 LSM，再按 node.md 选择定向检查，无需为注入验证重复查节点能力
```

### 2.4 显式 Unconfined 检查

```bash
# 检查 Pod 是否有显式 unconfined annotation（仅列键名，再筛选）
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}' | grep -i unconfined
# 检查 label 中是否有 unconfined 标记
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.labels}}{{$k}}{{"="}}{{$v}}{{"\n"}}{{end}}' | grep -i unconfined
```

**unconfined 语义：** unconfined annotation 或 AppArmor 的 `unconfined` 值会绕过策略；具体键名以实际部署版本为准。

### 2.5 NetworkProxy 注入痕迹

（详见 [networkproxy.md](networkproxy.md)，这里列出关键检查项）

```bash
# 以下可列出单 Pod 的相关 initContainer/container/volume，也可用关键词发现候选。
# "proxy" 关键词会匹配 Istio(istio-proxy)、Linkerd(linkerd-proxy) 等其他 Service Mesh sidecar。
# 判断是否为 vArmor NetworkProxy 注入需多信号交叉验证：
#   1) initContainer/sidecar 镜像是否来自 vArmor 部署的镜像仓库
#   2) annotation 键名是否包含 vArmor 特有域名/前缀（对比 AP profileName 和已知部署配置）
#   3) volume/secret 名是否与 vArmor 部署的 Secret/ConfigMap 名一致
#   4) 结合实际策略 enforcer 与 NetworkProxy 配置确认是否预期注入
#   5) 参考 networkproxy.md 做详细区分

# 列出全部 initContainer（name + image）
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.initContainers[*]}{.name}{"\t"}{.image}{"\n"}{end}'
# 列出全部 container（name + image）
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}{.name}{"\t"}{.image}{"\n"}{end}'
# 列出全部 annotation 键名（用于识别 vArmor 特有注解）
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}'
# 列出全部 volume（name + secretName）
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.volumes[*]}{.name}{"\t"}{.secret.secretName}{"\t"}{.configMap.name}{"\n"}{end}'
```

---

## 3. Pod 事件与状态

```bash
# 查看 Pod 事件
kubectl -n <namespace> describe pod <pod-name> | grep -A30 "Events:"

# Pod 状态和容器状态
kubectl -n <namespace> get pod <pod-name> -o jsonpath='PHASE={.status.phase}{"\t"}NODENAME={.spec.nodeName}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}READY={.ready}{"\t"}RESTARTS={.restartCount}{"\t"}LAST_STATE={.lastState}{"\n"}{end}'

# Pod Pending/ContainerCreating 时的原因
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.status}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

**Pod Pending 与 vArmor 相关的常见原因：**
- `Profile not found` / `AppArmor profile not loaded` → 节点上 Profile 未落地，进 [node.md](node.md)
- `Seccomp profile not found` → 节点 Seccomp 文件路径不可见
- NetworkProxy init/sidecar 启动失败 → 证书/Secret/资源问题，进 [networkproxy.md](networkproxy.md)
- 调度失败 → 通用 K8s 调度问题，优先排除非 vArmor 原因

---

## 4. 注入状态判定矩阵

| PodTemplate | 实际 Pod | 结论 | 下一步 |
|---|---|---|---|
| 无注入 | 无注入 | Webhook 未注入，策略未匹配或 Webhook 故障 | → [webhook.md](webhook.md) / [policy.md](policy.md) target验证 |
| 有注入 | 无注入，Pod创建早于策略 | 旧 Pod 未更新，需滚动更新 | 确认后建议重建 Pod（需授权） |
| 有注入 | 无注入，Pod创建晚于策略 | 注入被覆盖或 Webhook 未调用 | → [webhook.md](webhook.md) |
| 有注入 | 有注入但无 Profile 引用值 | 注入不完整，检查 Webhook 版本 | → [webhook.md](webhook.md) |
| 有注入 | 有注入，Profile 值正确 | 注入成功，问题在节点加载或运行时 | → [node.md](node.md) / [audit.md](audit.md) |
| 无注入（unconfined） | 任意 | 显式绕过策略 | 检查 unconfined 设置 |

---

## 可选汇总要点
Workload 检查可汇总：
1. PodTemplate 注入状态（有/无/部分），明确使用的 workload kind
2. 目标 Pod 列表、创建时间、ownerReferences；Deployment 额外记录所属 ReplicaSet
3. 每个目标 Pod 的实际注入痕迹对比（AppArmor/Seccomp/BPF/NetworkProxy）
4. 是否存在 unconfined 绕过
5. Pod 事件和容器状态（Pending/Crash/Running）
6. 按上面矩阵得出的明确结论
7. 下一步方向
