---
sidebar_position: 6
---

# 可观测性 {#observability}

分别验证配置和行为。先用 policy status/conditions 定位调和问题，再检查实际 Pod、代理和请求。

## 收集哪些证据 {#evidence-to-collect}

| 层次 | 有用证据 | 不能单独证明 |
| --- | --- | --- |
| 控制器 | generation、phase、ready、错误条件 | 每个代理都接受了该版本 |
| Pod | 注入容器、挂载、imageID、就绪及重启 | 预期规则已经执行 |
| 代理 | reload/rejection 日志、非敏感配置版本/摘要 | 应用信任或后端可用 |
| 流量 | 客户端结果和自有后端收到/未收到请求 | 审计交付成功 |
| 审计 | action、Pod/策略身份、可见 path/method | 故障时 exactly-once 交付 |

Secret 可以已经更新，但 Envoy 因拒绝新配置而继续使用旧配置。TCP readiness 也不是对策略版本的确认。

## 审计决策矩阵 {#audit-decision-matrix}

普通 egress 规则在对应 HTTP 请求或 TCP/TLS 连接日志位置遵循：

| 默认动作 | 匹配规则 | 执行 | 审计事件 |
| --- | --- | --- | --- |
| allow | 无 | 放行 | 无 |
| allow | deny，无 audit 匹配 | 拒绝 | 无 |
| allow | deny + audit | 拒绝 | DENIED |
| allow | audit | 放行 | AUDIT |
| deny | 无 | 拒绝 | DENIED |
| deny | allow | 放行 | 无 |
| deny | allow + audit | 放行 | AUDIT |
| deny | deny 与 allow + audit | 拒绝 | DENIED |

audit-only 在默认拒绝下不授予权限。分开的 deny 与 audit 规则同时匹配，也会选择 DENIED。重叠审计条件不会在同一日志位置故意产生多条记录，但不保证传输/存储 exactly-once。

NetworkProxy 只报告 DENIED 或 AUDIT，不报告 ALLOWED。是否由代理拒绝依据 Envoy RBAC reason；**上游返回 HTTP 403 且命中审计时仍是 AUDIT**。L4 拒绝可能表现为连接关闭或 TLS 失败，没有 HTTP 响应。

DefenseInDepth 未配置规则时的特殊兜底拒绝不执行普通审计矩阵，不能用它验证默认拒绝的审计行。

## 日志位置 {#where-logs-appear}

节点集中审计（通常为 runc）由 Envoy 向节点 Agent 发送 ALS，Agent 在宿主机 `/var/log/varmor/violations.log` 写入记录。配置的微虚机部署使用内嵌接收器，在 sidecar 文件系统内相同路径写入。参见[运行时识别](../../../getting_started/installation.md#micro-vm-kata-detection-for-networkproxy-auditing)。

事件包含 Pod/策略身份，不识别共享 Pod 网络命名空间中具体业务进程或容器。可见 HTTP 是请求级记录；TCP/TLS 透传为连接级。L4 应按 Pod、目标和时间窗口关联，不能使用记录中不存在的 HTTP 请求 ID 做唯一对应。

采集范围限定为测试 namespace/Pod，脱敏 URL 和 header。不要为诊断凭据注入而公开整个生成 Secret 或 LDS。

## 常用检查 {#useful-checks}

```bash
kubectl get varmorpolicy -n YOUR_NAMESPACE YOUR_POLICY -o yaml
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o wide
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy-init
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy --since=10m
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o jsonpath='{range .status.containerStatuses[*]}{.name}{" "}{.imageID}{" restarts="}{.restartCount}{"\n"}{end}'
```

组件监控见[指标](../../../getting_started/metrics.md)，错误解释见[故障排查](troubleshooting.md)。日志是按条件选择的，没有日志必须结合矩阵和实际运行配置解释。
