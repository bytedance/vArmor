---
sidebar_position: 6
---

# 可观测性 {#observability}

分别验证配置和行为。先用策略的 status/conditions 定位配置处理问题，再检查实际 Pod、代理和请求。

## 检查策略是否生效 {#evidence-to-collect}

| 检查对象 | 查看内容 | 用途 |
| --- | --- | --- |
| 策略 | generation、phase、ready 和错误条件 | 确认策略是否处理成功，定位配置错误 |
| Pod | 注入容器、挂载、就绪状态和重启次数 | 确认代理是否正常运行 |
| 代理日志 | 配置加载或拒绝信息 | 确认规则更新是否被接受 |
| 请求与后端日志 | HTTP 状态码、响应及后端访问记录 | 确认允许或拒绝结果 |
| 审计日志 | action、Pod、策略、请求路径和方法 | 定位触发规则的流量 |

策略更新后，应同时检查代理日志和请求结果。代理拒绝新配置时可能继续使用旧配置，需要先处理加载错误。

## 审计决策矩阵 {#audit-decision-matrix}

配置 egress 规则后，HTTP 请求和 TCP/TLS 连接的审计行为如下：

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

audit-only 在默认拒绝下不授予权限。分开的 deny 与 audit 规则同时匹配，也会选择 DENIED。一个请求匹配多条审计条件时，在同一日志位置生成一条记录。

NetworkProxy 只报告 DENIED 或 AUDIT，不报告 ALLOWED。审计事件区分代理拒绝和上游响应；**上游返回 HTTP 403 且命中审计时仍是 AUDIT**。L4 拒绝可能表现为连接关闭或 TLS 失败，没有 HTTP 响应。

`DefenseInDepth` 下未配置网络规则时，流量被拒绝，但不会生成上述审计记录。需要审计时请配置明确的 egress 规则。

## 日志位置 {#where-logs-appear}

runc 等普通容器运行时的审计日志位于工作负载所在节点的 `/var/log/varmor/violations.log`。已配置的微虚机运行时在 `varmor-network-proxy` sidecar 内的相同路径记录日志。参见[运行时识别](../../../getting_started/installation.md#micro-vm-kata-detection-for-networkproxy-auditing)。

事件包含 Pod/策略身份，不识别共享 Pod 网络命名空间中具体业务进程或容器。可见 HTTP 是请求级记录；TCP/TLS 透传为连接级。L4 应按 Pod、目标和时间窗口关联，一条连接记录可能对应多个请求。

按受影响的命名空间和 Pod 筛选日志。对外分享日志或代理配置前，请脱敏凭据以及 URL、请求头中的敏感信息。

## 常用检查 {#useful-checks}

```bash
kubectl get varmorpolicy -n YOUR_NAMESPACE YOUR_POLICY -o yaml
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o wide
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy-init
kubectl logs -n YOUR_NAMESPACE YOUR_POD -c varmor-network-proxy --since=10m
kubectl get pod -n YOUR_NAMESPACE YOUR_POD -o jsonpath='{range .status.containerStatuses[*]}{.name}{" "}{.imageID}{" restarts="}{.restartCount}{"\n"}{end}'
```

组件监控见[指标](../../../getting_started/metrics.md)，错误解释见[故障排查](troubleshooting.md)。日志是按条件选择的，没有日志必须结合矩阵和实际运行配置解释。
