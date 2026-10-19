# NetworkProxy 专项检查（NetworkProxy）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
分层排查 NetworkProxy 问题：注入层 → 启动层 → 转发层 → 规则层 → HTTPS层 → 绕过层。在采用 sidecar/Envoy 实现的部署中，NetworkProxy 通过注入的代理组件提供相应的 L4/L7、SNI 或 TLS MITM 能力；具体能力和注入形态以实际版本和 Pod 配置为准。

## 适用场景
- 策略包含 NetworkProxy enforcer
- Pod 创建失败涉及 initContainer/sidecar/Secret/证书
- 出口连接失败、TLS 错误、HTTP 请求异常
- L7 规则（path/method）不生效
- HTTPS 规则不生效

## 前置依赖
- 已知目标 namespace、Pod 名
- 已知策略类型（VP/VCP）、策略名和 VP 的 namespace

---

## 1. 注入层检查

确认 Pod 是否有 NetworkProxy 完整注入痕迹。

```bash
# 1. annotation 键名（仅列键名，不输出值）
# proxy 可用于发现候选，但也会匹配 Istio/Linkerd 等注解，不能仅凭命中认定归属。
# 根据候选键名，结合策略 profileName、组件镜像和配置引用判断；必要时定向读非敏感值
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}'

# 2. initContainer（流量重定向）：列出全部 initContainer 的 name + image
# vArmor NetworkProxy initContainer 的镜像来自 vArmor 部署的仓库，名称与部署配置一致
kubectl -n <namespace> get pod <pod-name> -o jsonpath='INIT_CONTAINERS={range .spec.initContainers[*]}{.name}{"("}{.image}{") "}{end}{"\n"}'

# 3. sidecar（Envoy 代理）：列出全部 container 的 name + image
kubectl -n <namespace> get pod <pod-name> -o jsonpath='CONTAINERS={range .spec.containers[*]}{.name}{"("}{.image}{") "}{end}{"\n"}'

# 4. proxy 配置 volumes（Secret/证书）：列出全部 volume 的 name + secretName + configMapName
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.volumes[*]}{.name}{"\t"}{.secret.secretName}{"\t"}{.configMap.name}{"\n"}{end}'

# 5. 容器环境变量键名（不输出值；CA/证书/token 等敏感值不得打印）
# proxy/ca/cert/port 可帮助发现候选，必要的开关/端口值可定向读取；敏感值不展示
# 直接列出全部 env 键名，或在已确认 proxy sidecar 容器名后定向查看该容器的 env
kubectl -n <namespace> get pod <pod-name> -o jsonpath='{range .spec.containers[*]}{.name}{":\n"}{range .env[*]}{"  "}{.name}{"\n"}{end}{end}'
```

**注入层问题表现：**
- 缺少 initContainer → Webhook 未注入 NetworkProxy 组件
- 缺少 sidecar → Webhook 注入不完整
- 缺少 Secret volume → 代理配置/证书未挂载，Pod 可能启动失败
- 全部缺失 → NetworkProxy 注入完全未发生，回到 [webhook.md](webhook.md)

---

## 2. 启动层检查

确认 initContainer 和 sidecar 是否正常启动。

```bash
# Pod 状态和各容器状态
kubectl -n <namespace> get pod <pod-name> -o jsonpath='PHASE={.status.phase}{"\n"}{range .status.containerStatuses[*]}CONTAINER={.name}{"\t"}READY={.ready}{"\t"}RESTARTS={.restartCount}{"\t"}STATE={.state}{"\n"}{end}{range .status.initContainerStatuses[*]}INIT={.name}{"\t"}READY={.ready}{"\t"}STATE={.state}{"\n"}{end}'

# initContainer 失败详情（根据故障时间选择 duration）
kubectl -n <namespace> logs <pod-name> -c <proxy-init-name> --since=<duration> --tail=50

# sidecar 状态和日志
kubectl -n <namespace> logs <pod-name> -c <proxy-sidecar-name> --since=<duration> --tail=100

# Pod 事件
kubectl -n <namespace> describe pod <pod-name> | grep -A30 "Events:"
```

**启动层常见问题：**
- **initContainer CrashLoop**：通常是 iptables 重定向失败，检查 NET_ADMIN 权限、节点 iptables/nftables 兼容性
- **sidecar 不 Ready**：Envoy 配置加载失败、证书错误、端口冲突
- **Secret not found**：manager 未传播 proxy 配置 Secret，或 Secret 名称不匹配
- **资源不足**：sidecar OOMKilled，检查 resources 配置

---

## 3. 转发层检查

先从 init 日志、相关配置和已有连接/访问日志判断流量是否经过 sidecar。
证据不足时可在已确认 sidecar 中做短时监听状态检查；容器身份与实际命令一起评估风险。

```bash
# 定向只读检查；exec 显式选择容器，由执行工具限定时长。
kubectl -n <namespace> exec <pod-name> -c <proxy-sidecar-name> -- ss -tln
# ss 不可用时可选 netstat；不安装工具。结合已确认端口解释结果。
```

ProxyUID、proxyAdminPort 与绕过配置先从实际策略/Pod/代理配置中确认，允许读取相关非敏感值。
需要核对重定向规则时先确认所在网络视图与权限，只读查询特定链；不默认 dump 全部规则。
从业务容器主动测试会产生真实请求，选择用户授权的目标、请求方式和端口，限定连接与总时长，
不把任意业务 URL 当作无副作用测试：

```bash
# 仅在当前授权覆盖具体请求且必要时选用。
kubectl -n <namespace> exec <pod-name> -c <app-container> -- curl --connect-timeout 5 --max-time 10 http://<confirmed-test-target>:<port>/<confirmed-path>
```

**转发层问题表现：**
- 连接超时/拒绝：可能来自重定向、代理规则、目标服务或网络；结合日志和已确认规则定位
- 代理循环：ProxyUID 配置错误导致 sidecar 自身流量被重定向
- 管理端口绕过异常：proxyAdminPort 配置错误导致无法绕过代理

---

## 4. 规则层检查

确认 L4/L7 规则是否正确下发和命中。

优先实际策略规则、代理配置加载日志和相关访问事件。管理端点只在已确认地址、端口、
访问授权与必要性时使用；选择相关统计或配置部分，限定连接/总时长和输出量。
不默认导出整个 config_dump 或全部 stats，管理接口请求按具体动作评估，禁止调用变更端点。
工具不支持定向输出时评估完整响应大小，必要时存本地脱敏分析。

```bash
kubectl -n <namespace> logs <pod-name> -c <proxy-sidecar-name> --since=<duration> --tail=200
```

**规则层关键概念：**
- 具体匹配层次、顺序和终止条件必须以实际版本支持的 qualifier、规则优先级和配置为准；不要仅凭 L4/SNI/L7 的概念顺序推断最终处置
- L4 规则：基于 IP/CIDR + 端口
- SNI/host 规则：基于 TLS SNI 或 HTTP Host 头
- L7 规则：基于 HTTP path/method/header（仅在 TLS MITM 或 HTTP 明文时生效，未配置 MITM 的 HTTPS 流量无法按 L7 规则匹配）
- 不要假设 deny 跨层次优先于 allow；依据实际版本支持的 qualifier、规则优先级、匹配层次和 `defaultAction` 判断
- 未命中任何规则时由 `defaultAction` 决定处置
- 详细规则层次和冲突处理见 `../references/troubleshooting/enforcer-conflicts.md`

**常见规则问题：**
- L7 path/method 规则对未启用 TLS MITM 的 HTTPS 不生效（只能按 SNI 判断）
- 不要把规则文本顺序等同于执行优先级；根据 qualifier、规则优先级、匹配层次和 `defaultAction` 验证最终处置
- `defaultAction` 的取值和未命中行为必须从实际策略及版本语义确认；不要仅凭字段名称推断所有流量的最终处置
- 不要把 L7 规则未命中误判为 L4 网络故障

---

## 5. HTTPS/TLS MITM 层检查

从实际策略/代理配置确认 MITM 开关，再检查业务容器的 CA 引用和挂载。优先 PodSpec 中
相关 env/volume 配置；运行时差异确有必要时，定向检查一个已知 CA 路径或非敏感变量。
不读取全部环境变量再过滤，不输出证书私钥或凭据。主动 HTTPS 测试沿用转发层的请求授权、
目标与超时约定，不默认跳过证书验证。

**HTTPS 问题判断：**
- 证书验证错误（x509: certificate signed by unknown authority）→ 检查 CA 注入、业务 trust store 与实际证书链
- 连接被重置/EOF → MITM 配置问题或 sidecar 未处理 CONNECT
- TLS 握手失败 → 证书/协议版本/cipher 不匹配
- **未配置 TLS MITM 时，HTTPS 的 L7 path/method 规则不会生效**，只能根据 SNI 判断

---

## 6. 绕过层检查

确认是否有流量绕过了代理。

```bash
# 检查 bypass 相关 annotation 键名（仅列键名，不输出值）
kubectl -n <namespace> get pod <pod-name> -o go-template='{{range $k,$v := .metadata.annotations}}{{$k}}{{"\n"}}{{end}}' | grep -iE 'bypass|exclude|ignore'

# 常见绕过路径：
# 1. NET_ADMIN 能力：如果其他容器也有 NET_ADMIN，可能修改 iptables 绕过
# 2. ProxyUID：Sidecar 自身 UID 的流量绕过重定向
# 3. proxyAdminPort：管理端口的流量绕过
# 4. Pod CIDR/集群内部流量：通常绕过代理（取决于配置）
# 5. localhost/127.0.0.1：通常绕过
```

---

## 7. 策略 NetworkProxy 配置验证

回到策略对象检查配置是否正确：

复用阶段前面获取的 VP/VCP，按实际 CRD、策略模式和版本定位 NetworkProxy 配置；
VP 带策略 namespace，VCP 不带 namespace。不要从示例字段路径推定所有版本的配置结构。
查看相关规则、qualifier/优先级、defaultAction、监听端口、ProxyUID、TLS MITM 与绕过配置，
必要时读取非敏感值。Secret 仅检查引用、挂载与证书元数据，不输出凭据或私钥。

---

## 可选汇总要点
NetworkProxy 检查可汇总：
1. 六层中哪一层有问题（注入/启动/转发/规则/HTTPS/绕过）
2. 各容器状态（init/sidecar/app）
3. 证书/Secret 挂载情况
4. 流量重定向是否生效
5. 规则类型（L4/SNI/L7）和 defaultAction
6. TLS MITM 是否启用
7. sidecar 日志中的错误和访问记录
8. 下一步方向
