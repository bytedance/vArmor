# vArmor 组件异常诊断路标

## 入口信号

manager/agent/classifier Pod 不 Ready、反复重启、OOMKilled、ImagePullBackOff、功能假活，或对应的 AP/Webhook/建模链路异常。

## 分组件判断

- **manager**：Leader、reconcile、CRD/RBAC、Webhook、证书、API Server；
- **agent**：节点覆盖、AP 处理、Profile load、内核/LSM/BTF/runtime；
- **classifier**：仅在 BehaviorModeling 启用时关注采集、归一化和上报；
- **NetworkProxy 相关 Pod/sidecar**：注入、Secret、证书、资源、端口和 readiness。

## 诊断层次

manager 异常主要影响策略编译、reconcile 和 Webhook；agent 异常主要影响节点 Profile 加载；NetworkProxy sidecar 异常主要影响注入后的转发和规则执行；classifier 主要影响 BehaviorModeling。组件 Pod Running/Ready 不能替代 VP/VCP、AP、Pod 实际配置和运行时事件证据。

## 证据顺序

先看 Pod 状态、lastState、事件和资源，再看组件日志；manager 异常时关联 Leader 和 Webhook；agent 异常时关联节点与 AP node condition；classifier 异常时关联 APM 和上报链路。

## 常见根因

RBAC/配置/CRD 版本不一致、镜像或资源问题、节点污点/资源/挂载、内核能力不满足、证书/Endpoint、API Server 限流或行为建模存储不足。Running 但 AP/建模/代理不前进时，按假活处理。

## 修复方向

优先恢复控制面可用性和节点覆盖，再处理策略内容。任何重启、扩容、重建、切换模式或修改安全策略的建议都要说明影响、范围和回滚方案。
