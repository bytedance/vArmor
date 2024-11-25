---
sidebar_position: 3
description: 使用指标监控和观察 vArmor
---

# vArmor 指标

## 概述
vArmor 目前支持可观测性指标，本文档描述了可用的指标、配置选项以及如何在您的环境中启用它们。

## 安装流程
1. 安装 prometheus-stack：
   ```bash
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm repo update
   helm install prometheus prometheus-community/kube-prometheus-stack
   ```

2. 安装启用了指标系统的 vArmor
   ```bash
   helm install varmor varmor/varmor \
     --set metrics.enable=true \
     --set metrics.serviceMonitorEnabled=true
   ```

3. 导入 Grafana 仪表板：
    - 访问您的 Grafana 实例
    - 导航至 Dashboards > Import
    - 上传位于 `grafana/panel.json` 的仪表板配置文件
    - 选择合适的 Prometheus 数据源
    - 点击导入完成

## 启用指标系统
要启用指标系统，需要：
1. 在配置文件中将 `metrics.enable` 设置为 `true`
2. 如需创建 Prometheus ServiceMonitor，将 `metrics.serviceMonitorEnabled` 设置为 `true`

启用后，指标将在管理器的 8081 端口的 `/metric` 端点上暴露。

## 可用指标

### 配置文件处理指标
这些指标用于跟踪由 Agent 处理的 ArmorProfile 对象的状态和性能
所有配置文件处理指标包含以下标签：
- `namespace`：配置文件所在的命名空间
- `profile_name`：配置文件名称
- `node_name`：节点名称

| 指标名称 | 类型 | 描述 |
|------------|------|-------------|
| `varmor_profile_processing_success` | 计数器 | 成功的配置文件处理操作数量 |
| `varmor_profile_processing_failure` | 计数器 | 失败的配置文件处理操作数量 |
| `varmor_profile_change_count` | 计数器 | 配置文件变更次数 |

### Webhook 指标
这些指标提供了 Manager 中 webhook server 的详细信息。

#### 基本 Webhook 指标（无标签）
| 指标名称 | 类型 | 描述 |
|------------|------|-------------|
| `varmor_admission_requests_total` | 计数器 | 准入请求总数 |
| `varmor_mutated_requests` | 计数器 | 被修改的请求数量 |
| `varmor_non_mutated_requests` | 计数器 | 未被修改的请求数量 |

#### Webhook 延迟指标
`varmor_webhook_latency` 指标是一个直方图，用于测量 webhook 处理延迟，包含 0.1、0.5、1、2 和 5 秒的区间。
此指标包含以下标签：
- `request_uid`：请求 UID
- `request_kind`：工作负载类型
- `request_namespace`：工作负载的命名空间
- `request_name`：工作负载的名称
- `request_operation`：工作负载是否被 Manager 变更

## Grafana 仪表板
代码库中提供了一个预配置的 Grafana 仪表板，用于可视化这些指标。该仪表板提供了配置文件处理和 webhook 性能指标的全面视图。

## 使用场景

### 监控配置文件处理
- 跟踪不同命名空间中配置文件处理的成功和失败率
- 监控配置文件随时间的变化
- 识别存在配置文件处理问题的节点

### Webhook 性能分析
- 监控准入请求数量
- 跟踪修改率
- 分析 webhook 延迟模式
- 识别请求处理中的潜在瓶颈

## 技术实现细节
指标系统使用 float64 计数器和仪表进行精确测量。实现包括：
- Float64Counter 用于累积指标
- Float64Gauge 用于当前状态指标
- Histogram 用于延迟分布分析

## 与监控系统集成
指标系统设计为与 Prometheus 生态系统无缝集成：
1. 在配置中启用指标
2. 如果使用 Prometheus Operator，配置 ServiceMonitor
3. 导入提供的 Grafana 仪表板进行可视化