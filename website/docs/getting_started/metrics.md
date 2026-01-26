---
sidebar_position: 3
description: Monitor and observe vArmor using metrics.
---

# Metrics

## Overview
vArmor now includes a comprehensive metrics system. This document describes the available metrics, their configurations, and how to enable them in your environment.

## Setup Workflow
1. Install prometheus-stack:
   ```bash
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm repo update
   helm install prometheus prometheus-community/kube-prometheus-stack
   ```

2. Install vArmor with metrics enabled:
   ```bash
   helm install varmor varmor/varmor --set metrics.enable=true
   ```

3. Import Grafana dashboard:
    - Access your Grafana instance
    - Navigate to Dashboards > Import
    - Upload the dashboard JSON file from `grafana/panel.json`
    - Select the appropriate Prometheus data source
    - Click Import to finish

## Available Metrics

### Profile Processing Metrics
These metrics track the status and performance of the ArmorProfile object processed by the Agent.
All profile processing metrics include the following labels:
- `node_name`: Name of the node

| Metric Name | Type | Description |
|------------|------|-------------|
| `varmor_profile_processing_success` | Counter | Number of successful profile processing operations |
| `varmor_profile_processing_failure` | Counter | Number of failed profile processing operations |
| `varmor_profile_change_count` | Counter | Number of profile changes |

### Webhook Metrics
These metrics provide insights into admission webhook operations of the Manager.

#### Basic Webhook Metrics (No Labels)
| Metric Name | Type | Description |
|------------|------|-------------|
| `varmor_admission_requests_total` | Counter | Total number of admission requests |
| `varmor_mutated_requests` | Counter | Number of requests that were mutated |
| `varmor_non_mutated_requests` | Counter | Number of requests that were not mutated |

#### Webhook Latency Metric
The `varmor_webhook_latency` metric is a histogram that measures webhook processing latency with buckets at 0.1, 0.5, 1, 2, and 5 seconds.
This metric includes the following labels:
- `request_kind`: The type of workload be submitted
- `request_operation`: The operation type of the request
- `request_mutated`: Whether the workload be mutated by Manager or not

## Grafana Dashboard
A pre-configured Grafana dashboard is available in the codebase for visualizing these metrics. The dashboard provides comprehensive views of both profile processing and webhook performance metrics.

## Use Cases

### Monitoring Profile Processing
- Track success and failure rates of profile processing across different namespaces
- Monitor profile changes over time
- Identify nodes with profile processing issues

### Webhook Performance Analysis
- Monitor admission request volumes
- Track mutation rates
- Analyze webhook latency patterns
- Identify potential bottlenecks in request processing

## Technical Implementation Details
The metrics system uses float64 counters and gauges for precise measurements. The implementation includes:
- Float64Counter for cumulative metrics
- Float64Gauge for current state metrics
- Histogram for latency distribution analysis

## Integration with Monitoring Stack
The metrics system is designed to integrate seamlessly with the Prometheus ecosystem:
1. Enable metrics in your configuration
2. Configure ServiceMonitor if using Prometheus Operator
3. Import the provided Grafana dashboard for visualization