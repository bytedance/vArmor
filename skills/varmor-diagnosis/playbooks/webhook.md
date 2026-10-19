# Webhook 注入验证（Webhook）

执行与授权遵循 [统一约定](README.md)。以下是按需选用的检查点与命令示例；
复用已有事实，按当前问题选择字段与分支，不需要完整执行或填齐输出清单。

## 检查目标
验证 Admission Webhook 配置、可用性和匹配规则，区分「请求未命中」「Webhook 未调用」「调用失败后放行」「注入成功但被覆盖」四种情况。

## 适用场景
- 策略/AP 健康但目标 Pod 无 vArmor 注入痕迹
- 创建 Workload 时出现 Webhook 相关报错
- 部分 Pod 有注入、部分没有
- 策略更新后新 Pod 未获得新配置

## 前置依赖
- 已知 vArmor 安装 namespace（<varmor-namespace>，需从实际部署对象确认）
- 已知目标 namespace、Workload 名称

---

## 1. Webhook 配置存在性

```bash
# 列出所有 vArmor 相关 Webhook 配置
kubectl get mutatingwebhookconfigurations | grep -i varmor
kubectl get validatingwebhookconfigurations | grep -i varmor

# 查看完整 Webhook 配置（替换 <webhook-name>）
kubectl get mutatingwebhookconfiguration <mutating-webhook-name> -o yaml
kubectl get validatingwebhookconfiguration <validating-webhook-name> -o yaml
```

**重点关注字段：**
| 字段 | 含义 |
|---|---|
| `webhooks[*].rules` | 匹配的 API group/version/resource/operation |
| `webhooks[*].namespaceSelector` | namespace 标签选择器 |
| `webhooks[*].objectSelector` | 对象标签选择器 |
| `webhooks[*].failurePolicy` | Fail/Ignore：调用失败时是阻断还是放行 |
| `webhooks[*].clientConfig.service` | Webhook Service 引用（namespace/name/path/port） |
| `webhooks[*].clientConfig.caBundle` | CA 证书，非空且有效才能建立 TLS |

### 1.1 匹配规则验证

```bash
# 列出所有 MutatingWebhookConfiguration 的全部 webhook 条目，不假设目标位于 webhooks[0]
kubectl get mutatingwebhookconfigurations -o go-template='{{range .items}}{{$config := .metadata.name}}{{range .webhooks}}{{$config}}{{"\t"}}{{.name}}{{"\t"}}{{.clientConfig.service.namespace}}{{"/"}}{{.clientConfig.service.name}}{{":"}}{{.clientConfig.service.port}}{{"\n"}}{{end}}{{end}}' | grep -i varmor
# 选择 clientConfig.service.namespace 指向 <varmor-namespace> 的配置和具体 webhook entry
# 旧安装残留的 Webhook 通常 service.namespace 指向已被删除的命名空间或不同的安装实例
MUTATING_WEBHOOK=<select-the-webhook-whose-service-points-to-varmor-namespace>
MUTATING_WEBHOOK_ENTRY=<selected-webhook-entry-name>
echo "Selected MutatingWebhook: $MUTATING_WEBHOOK / $MUTATING_WEBHOOK_ENTRY"
# 精确选择 entry，并输出其全部 rules；找不到或重复时停止，不能静默选择首项
kubectl get mutatingwebhookconfiguration "$MUTATING_WEBHOOK" -o json | WEBHOOK_ENTRY="$MUTATING_WEBHOOK_ENTRY" python3 -c "
import json, os, sys
obj = json.load(sys.stdin)
name = os.environ['WEBHOOK_ENTRY']
matched = [w for w in obj.get('webhooks', []) if w.get('name') == name]
if len(matched) != 1:
    print(f'WEBHOOK_ENTRY_ERROR: expected one entry named {name}, found {len(matched)}')
    sys.exit(1)
w = matched[0]
print('FAILURE_POLICY=' + str(w.get('failurePolicy', '')))
print('NS_SELECTOR=' + json.dumps(w.get('namespaceSelector', {}), separators=(',', ':')))
print('OBJ_SELECTOR=' + json.dumps(w.get('objectSelector', {}), separators=(',', ':')))
for i, rule in enumerate(w.get('rules', [])):
    print(f'RULE[{i}] apiGroups={rule.get(\"apiGroups\", [])} apiVersions={rule.get(\"apiVersions\", [])} resources={rule.get(\"resources\", [])} operations={rule.get(\"operations\", [])}')
"
```

**匹配规则检查清单：**
1. API groups/versions/resources 是否覆盖目标 Workload 类型（如 `apps/v1/deployments`、`v1/pods`）
2. operations 是否包含 CREATE（和 UPDATE，若支持更新时注入）
3. namespaceSelector 是否要求特定标签（目标 namespace 是否有该标签）
4. objectSelector 是否要求特定标签（目标 Pod/Workload 是否满足实际 WebhookConfiguration、部署配置和版本声明的匹配字段；不要把固定 annotation 或标签值当作通用默认）
5. failurePolicy 是 Fail 还是 Ignore（Ignore 模式下调用失败会静默放行无注入）

---

## 2. Webhook Service 与端点

```bash
# 查看 Webhook Service
kubectl -n <varmor-namespace> get svc | grep -E 'webhook|manager'

# 查看 Service 详情
kubectl -n <varmor-namespace> get svc <webhook-service-name> -o jsonpath='TYPE={.spec.type}{"\t"}SELECTOR={.spec.selector}{"\n"}{range .spec.ports[*]}PORT_NAME={.name}{"\t"}PORT={.port}{"\t"}TARGET_PORT={.targetPort}{"\n"}{end}'

# 查看 Endpoints 是否存在
kubectl -n <varmor-namespace> get endpoints <webhook-service-name> -o jsonpath='{range .subsets[*]}ADDRESSES={.addresses[*].ip}{"\t"}PORTS={.ports[*].port}{"\n"}{end}'

# 无 Endpoints 时：用 Service 自身的 selector（而非假设的 label key）查询匹配的 Pod
# 将 selector map 转换为逗号分隔的 key=value 格式用于 -l 参数
SVC_SELECTOR_RAW=$(kubectl -n <varmor-namespace> get svc <webhook-service-name> -o go-template='{{range $k,$v := .spec.selector}}{{$k}}={{$v}}{{","}}{{end}}') ||
  { echo "SERVICE_QUERY_FAILED: cannot read webhook Service selector"; return 1 2>/dev/null || exit 1; }
SVC_SELECTOR_L=$(printf '%s' "$SVC_SELECTOR_RAW" | sed 's/,$//')
echo "Service selector: $SVC_SELECTOR_L"
[ -n "$SVC_SELECTOR_L" ] && kubectl -n <varmor-namespace> get pods -l "$SVC_SELECTOR_L" --show-labels || echo "Cannot resolve service selector to label query; list manager pods manually"
```

**判读规则：**
- Service 不存在 → Webhook 配置残留或安装异常
- Endpoints 为空（没有 subsets 或 addresses 为空）→ manager Pod 未就绪或 Service selector 不匹配
- Endpoints 有地址但 Pod 不 Ready → 健康检查失败或启动中
- Service 和端点正常 → 只证明配置与端点存在；API Server 到 Webhook 的实际连通性仍需请求报错或调用证据

---

## 3. TLS 证书验证

```bash
# 提取已选 webhook entry 的 CA Bundle，只查看证书元数据
WEBHOOK_JSON=$(kubectl get mutatingwebhookconfiguration "$MUTATING_WEBHOOK" -o json) ||
  { echo "WEBHOOK_QUERY_FAILED: cannot read selected configuration"; return 1 2>/dev/null || exit 1; }
CA_BUNDLE=$(printf '%s' "$WEBHOOK_JSON" | WEBHOOK_ENTRY="$MUTATING_WEBHOOK_ENTRY" python3 -c "
import json, os, sys
obj = json.load(sys.stdin)
matched = [w for w in obj.get('webhooks', []) if w.get('name') == os.environ['WEBHOOK_ENTRY']]
if len(matched) != 1:
    sys.exit('WEBHOOK_ENTRY_ERROR: cannot uniquely select CA bundle')
print(matched[0].get('clientConfig', {}).get('caBundle', ''))
") || { echo "CA_BUNDLE_SELECTION_FAILED"; return 1 2>/dev/null || exit 1; }
if [ -z "$CA_BUNDLE" ]; then
  echo "CA_BUNDLE_EMPTY"
else
  CERT_META=$(printf '%s' "$CA_BUNDLE" | base64 -d | openssl x509 -noout -text 2>/dev/null) ||
    { echo "CA_BUNDLE_DECODE_FAILED"; return 1 2>/dev/null || exit 1; }
  printf '%s\n' "$CERT_META" | head -20
fi

# 查看 manager 的证书挂载
kubectl -n <varmor-namespace> get deploy <manager-deploy-name> -o jsonpath='{range .spec.template.spec.volumes[*]}{.name}{"\t"}{.secret.secretName}{"\n"}{end}' | grep -i cert
kubectl -n <varmor-namespace> get secrets | grep -iE 'webhook|cert|tls'
```

**证书问题表现：**
- Admission 请求报错 `x509: certificate signed by unknown authority`
- Admission 请求报错 `x509: certificate is valid for ... not ...`
- 连接超时或 connection refused
- caBundle 为空或过期

---

## 4. Webhook 连通性快速测试

```bash
# 优先：对照已有失败 Admission 请求的报错、事件与 manager 日志；不创建测试 Pod
# 先看 namespace 是否有匹配标签
kubectl get ns <namespace> --show-labels

# 方法2：通过 port-forward 测试 Webhook 端口可达性（L3，仅在已获授权时执行）
# 先从实际 WebhookConfiguration/Service 确认目标、端口和路径；限定单个目标、短超时和总时限。
# 保存 port-forward 的 PID，并在验证结束或超时后清理；不要默认使用 -k 跳过证书校验。
# 示例仅表达流程，不提供固定端口或固定路径：
# kubectl -n <varmor-namespace> port-forward svc/<webhook-service-name> <local-port>:<service-port> &
# PF_PID=$!
# timeout <seconds> curl --connect-timeout <seconds> --max-time <seconds> https://127.0.0.1:<local-port>/<confirmed-path>
# PF_STATUS=$?; kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; exit "$PF_STATUS"

# 方法3：从相关 manager 实例读取有限 Admission 日志；按 component.md 确认候选。
# Webhook 问题不必先定位 reconcile Leader。
kubectl -n <varmor-namespace> logs <manager-pod> -c <manager-container> --since=<duration> --tail=200
# 本地按请求时间、目标对象和 admission/webhook/mutate/validate/inject 筛选。
```

---

## 5. 区分四种未注入场景

| 场景 | 判断依据 | 下一步 |
|---|---|---|
| **请求未命中** | Webhook rules/selector 不匹配目标对象；namespace 缺少标签；目标缺少 objectSelector 标签 | 检查标签和匹配规则，参考 [policy.md](policy.md) target 验证 |
| **Webhook 未调用** | Service 无 Endpoints、证书错误、网络不通、端口不匹配 | 修复 Service/Endpoint/证书，参考 [component.md](component.md) manager 部分 |
| **调用失败后放行** | failurePolicy=Ignore + manager 日志有错误；目标事件中无 Webhook 相关记录 | 查 manager 日志和错误原因，恢复 Webhook 服务能力 |
| **注入后被覆盖** | Admission 响应显示已注入，但最终对象缺少对应字段；或其他 admission/controller 后续改写对象 | 检查其他 Mutating Webhook 的 patch、`reinvocationPolicy` 及后续控制器；Webhook 调用顺序不存在可配置的通用“优先级” |

### 5.1 验证 PodTemplate 是否被注入

```bash
# <workload-kind> 必须替换为实际资源类型：deploy、statefulset 或 daemonset
# 查看目标 Workload 的 PodTemplate 中是否有注入痕迹；先查看相关注入字段，必要时补充其他非敏感字段
kubectl -n <namespace> get <workload-kind> <workload-name> -o jsonpath='CONTAINERS={.spec.template.spec.containers[*].name}{"\n"}INIT_CONTAINERS={.spec.template.spec.initContainers[*].name}{"\n"}POD_SECCOMP={.spec.template.spec.securityContext.seccompProfile.type}{"/"}{.spec.template.spec.securityContext.seccompProfile.localhostProfile}{"\n"}POD_APPARMOR={.spec.template.spec.securityContext.appArmorProfile.type}{"/"}{.spec.template.spec.securityContext.appArmorProfile.localhostProfile}{"\n"}{range .spec.template.spec.containers[*]}CTR_SECCOMP[{.name}]={.securityContext.seccompProfile.type}{"/"}{.securityContext.seccompProfile.localhostProfile}{"\n"}CTR_APPARMOR[{.name}]={.securityContext.appArmorProfile.type}{"/"}{.securityContext.appArmorProfile.localhostProfile}{"\n"}{end}'

# 列出全部 annotation 键名（仅键名不出值），不做 grep 过滤和二元信号输出。
# 判断是否为 vArmor 注入需结合 initContainer/sidecar/securityContext 等多信号验证，
# 不能仅凭 annotation 键名中是否含 apparmor/seccomp/varmor 子串就下结论。
kubectl -n <namespace> get <workload-kind> <workload-name> -o go-template='{{range $k,$v := .spec.template.metadata.annotations}}{{$k}}{{"\n"}}{{end}}'

# 重点查找以下注入痕迹：
# AppArmor: container.apparmor.security.beta.kubernetes.io/<container>（k8s 标准 annotation 键名）或 spec.securityContext.appArmorProfile（Pod/Container 级）
# Seccomp: spec.securityContext.seccompProfile (type=Localhost)（Pod/Container 级）
# BPF: vArmor 自定义 annotation 键名（因版本而异，先列键名再对照 AP profileName 确认）
# NetworkProxy: proxy annotation 键名、initContainer（<proxy-init-name>）、sidecar（<proxy-sidecar-name>）、证书 volumes
# annotation 可先查键名发现候选，再定向读取必要的非敏感值（如 Profile 引用）；归属结合策略、配置和实际版本确认。
```

---

## 可选汇总要点
Webhook 检查可汇总：
1. Webhook 配置是否存在，rules/selectors 是否覆盖目标
2. Service/Endpoint 状态和端口
3. failurePolicy 设置
4. 证书有效性
5. 注入失败属于四种场景中的哪一种
6. 若是注入后被覆盖，指出可能的覆盖源
7. 下一步方向
