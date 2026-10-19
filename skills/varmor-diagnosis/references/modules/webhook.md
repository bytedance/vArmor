# vArmor Admission Webhook

## 1. 两类 Webhook

- **MutatingWebhook**：处理目标 Workload/Pod 的创建或更新，为匹配对象注入 AppArmor/BPF/Seccomp Profile 引用；使用 NetworkProxy 时还注入 initContainer、sidecar、Secret/volume、重定向和 TLS MITM 相关设置。
- **ValidatingWebhook**：校验 VP/VCP 的 target、模式必需字段、enforcer 组合、NetworkProxy 参数、不可变字段和其他语义约束。

Webhook 服务由 manager 提供，但配置、Service、Endpoint、证书和对象匹配范围是独立证据链。

## Admission 与控制器的关系

Webhook 只处理进入 API Server 的 Admission 请求，不直接修改已存在的 Pod。对 Deployment、StatefulSet、DaemonSet 的请求，注入通常先体现在 PodTemplate，随后由对应控制器创建带注入的 Pod；对裸 Pod 则直接体现在 PodSpec。由此可将“未生效”分为：请求未命中、Webhook 未调用、调用失败后放行、模板已注入但旧 Pod 未替换、实际 Pod 已注入但节点未加载。

WebhookConfiguration 的 rules、namespace/object selector、failurePolicy、Service/Endpoint 和 CA bundle 必须与 manager Deployment 的实际服务能力一起判断。配置存在不等于请求一定到达 manager，调用成功也不等于最终 Pod 保留了期望字段。

## 2. 匹配条件

诊断“策略存在但没注入”时不要只看策略 selector，还要核对：

- API group/version/resource 和 operation 是否在 Webhook 规则范围；
- namespace/object selector 是否匹配；
- Workload kind 与 `spec.target.kind` 是否一致；
- Workload/Pod label 是否满足实际部署配置声明的匹配字段；不要把固定 annotation 或标签值当作通用默认；
- VP 的 namespace 与请求 namespace 是否一致，VCP 是否与 VP 重叠，以及实际版本如何处理覆盖、合并或优先关系；
- target.name/selector、container 列表和显式 `unconfined` 是否改变最终结果。

## 3. 注入后的观察点

AppArmor 可能同时出现兼容 annotation 和 Kubernetes SecurityContext；Seccomp 应关注 `type` 与 `localhostProfile`；BPF 常见为 vArmor annotation；NetworkProxy 应同时出现 proxy annotation、initContainer、sidecar、配置/证书 volumes，以及必要的容器 CA mount/env。

不要只根据 Workload 模板推断实际 Pod：检查 Pod 最终 spec、owner、创建时间和是否由新模板产生。

## 4. 故障模式

### 配置不存在或规则不匹配

策略/Workload 请求正常通过，但没有注入或校验。常见原因是升级残留、配置名称不一致、API 规则不覆盖当前请求、selector/label 错误。

### Service/Endpoint 不可用

API Server 无法调用 manager。必须结合实际 `failurePolicy` 判断影响：本地 vArmor 当前实现默认生成的 Mutating/Validating Webhook 是 `Ignore`，但部署或其他版本可能不同。`Fail` 会阻断匹配请求；`Ignore` 会放行请求但可能静默失去注入/校验。

### TLS/CA/Service 路径错误

通常表现为 connection、x509、certificate、timeout 或 no endpoint。核对 CA bundle、服务引用/地址、端口、路径和 manager readiness；不要把所有 admission rejection 归因于策略语法。

### 目标已存在

Webhook 主要影响 Admission 请求；已有 Pod 不会因 Webhook 配置恢复而自动获得注入。结合 `updateExistingWorkloads` 和实际 Workload 类型判断是否会触发滚动更新。

## 5. 建议方向（仅建议）

优先通过对象最终状态和 Webhook 配置定位“未匹配、未调用、调用失败还是注入后被覆盖”。涉及修改 Webhook、证书、匹配标签或重建 Pod 时，只给出风险、影响范围和验证点，不直接操作。
