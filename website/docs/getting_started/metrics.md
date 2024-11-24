---
sidebar_position: 2
description: Metrics introduction.
---

# Metrics

## Overview
Varmor now includes a comprehensive metrics system that provides insights into profile processing and webhook operations. This document describes the available metrics, their configurations, and how to enable them in your environment.

## Setup Workflow
1. Install prometheus-stack:
   ```bash
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm repo update
   helm install prometheus prometheus-community/kube-prometheus-stack
   ```

2. Install Varmor with metrics enabled:
   ```bash
   helm install varmor varmor/varmor \
     --set metrics.enable=true \
     --set metrics.serviceMonitorEnabled=true
   ```

3. Import Grafana dashboard:
    - Access your Grafana instance
    - Navigate to Dashboards > Import
    - Upload the dashboard JSON file from `grafana/panel.json`
    - Select the appropriate Prometheus data source
    - Click Import to finish

## Enabling Metrics
To enable the metrics system:
1. Set `metrics.enable` to `true` in your values configuration
2. To create a Prometheus ServiceMonitor, set `metrics.serviceMonitorEnabled` to `true`

Once enabled, metrics are exposed at the `/metric` endpoint on port 8081 of the manager.

## Available Metrics

### Profile Processing Metrics
These metrics track the status and performance of profile processing operations.
All profile processing metrics include the following labels:
- `namespace`: The namespace of the profile
- `profile_name`: Name of the profile
- `node_name`: Name of the node

| Metric Name | Type | Description |
|------------|------|-------------|
| `profile_processing_success` | Counter | Number of successful profile processing operations |
| `profile_processing_failure` | Counter | Number of failed profile processing operations |
| `profile_change_count` | Counter | Number of profile changes |

### Webhook Metrics
These metrics provide insights into admission webhook operations.

#### Basic Webhook Metrics (No Labels)
| Metric Name | Type | Description |
|------------|------|-------------|
| `admission_requests_total` | Counter | Total number of admission requests |
| `mutated_requests` | Counter | Number of requests that were mutated |
| `non_mutated_requests` | Counter | Number of requests that were not mutated |

#### Webhook Latency Metric
The `webhook_latency` metric is a histogram that measures webhook processing latency with buckets at 0.1, 0.5, 1, 2, and 5 seconds.
This metric includes the following labels:
- `uid`: Request UID
- `kind`: Resource kind
- `namespace`: Resource namespace
- `name`: Resource name
- `operation`: Operation type

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