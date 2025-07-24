---
sidebar_position: 1
description: Understand how to install, configure, upgrade and uninstall vArmor.
---
# Installation

## Prerequisites

The prerequisites required by different enforcers are as shown in the following table.

|Enforcer|Requirements|Recommendations|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15 and above<br />2. The AppArmor LSM is enabled|GKE with Container-Optimized OS<br />AKS with Ubuntu 22.04 LTS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0<br />Debian 10 and above<br />Ubuntu 18.04.0 LTS and above<br />[veLinux 1.0](https://www.volcengine.com/docs/6396/74967) etc.
|BPF         |1. Linux Kernel 5.10 and above (x86_64)<br />2. containerd v1.6.0 and above<br />3. The BPF LSM is enabled|EKS with Amazon Linux 2<br />GKE with Container-Optimized OS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux 1.0 (with 5.10 kernel)<br />AKS with Ubuntu 22.04 LTS <sup>\*</sup><br />ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br />OpenSUSE 15.4 <sup>\*</sup><br />Debian 11 <sup>\*</sup><br />Fedora 37 <br />[veLinux 1.0 with 5.10 kernel](https://www.volcengine.com/docs/6396/74967) etc.<br /><br />* *Manual enabling of BPF LSM is required*
|Seccomp     |1. Kubernetes v1.19 and above|All Linux distributions

## Installation

vArmor can be deployed via a Helm chart which is the recommended and preferred method for a production install.

In order to install vArmor with Helm, first fetch the chart.

```
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.8.1
```

Then install it with helm optional [configurations](#configuration).

```
helm install varmor varmor-0.8.1.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-ap-southeast-1.cr.volces.com"
```

*You can use the domain `elkeid-cn-beijing.cr.volces.com` inside of the CN region.*

## Configuration

vArmor allows you to configure its functionality during installation using the helm command.

### General Options

#### Disable AppArmor Enforcer
The AppArmor enforcer should be disabled when the system doesn't support AppArmor LSM. Default: enabled.

```bash
--set appArmorLsmEnforcer.enabled=false
```

#### Enable BPF Enforcer
The BPF enforcer can be enabled when the system supports BPF LSM. Default: disabled.

```bash
--set bpfLsmEnforcer.enabled=true
```

#### Enable the BehaviorModeling Mode
This is an experimental feature. Currently, only the AppArmor and Seccomp enforcers support the BehaviorModeling mode. Please refer to the [BehaviorModeling Mode](../guides/policies_and_rules/policy_modes/behavior_modeling.md) for more details. Default: disabled.

```bash
--set behaviorModeling.enabled=true
```

#### Configure the Search List for System Audit Logs
vArmor sequentially checks whether the system audit logs exist and monitors the first valid file to consume AppArmor and Seccomp audit events for the violation auditing and behavioral modeling features. If you are using *auditd*, the audit events of AppArmor and Seccomp will be stored by default in `/var/log/audit/audit.log`. Otherwise they will be stored in `/var/log/kern.log`. 

You can use the option to specify the audit logs or determine the search order yourself. Please use a vertical bar to separate file paths. Default: `/var/log/audit/audit.log|/var/log/kern.log`.

```bash
--set "agent.args={--auditLogPaths=FILE_PATH|FILE_PATH}"
```

#### Configure Metrics
You can enable metrics to monitor the operation of vArmor. All metrics are exposed at the `/metric` endpoint on port `8081` of every manager instance. Default: disabled.

```bash
--set metrics.enabled=true
```

You can use the following command to create a `ServiceMonitor` object in the namespace where vArmor is installed. Default: disabled.

```bash
--set metrics.serviceMonitorEnabled=true
```

#### Set the Log Output Format to JSON
The default format of agent and manager is TEXT. You can use the following command to set it to JSON.

```bash
--set jsonLogFormat.enabled=true
```

#### Inject Metadata into Violation Events
This feature enables you to inject custom metadata into violation events. It enhances the observability of vArmor's audit logs by associating violation events with environment-specific context. Default: No custom metadata.

You can add key-value pairs of metadata using commands similar to the following.

```bash
--set auditEventMetadata.clusterID="ID" \ 
--set auditEventMetadata.clusterName="NAME" \  
--set auditEventMetadata.region="REGION"  
```

### Advanced Options

#### Set the Match Label of Webhook
vArmor will only enable sandbox protection for workloads that contain a specific label. You can set the label you want or disable this feature by using `--set 'manager.args={--webhookMatchLabel=}'`. Default: `sandbox.varmor.org/enable=true`.

```bash
--set "manager.args={--webhookMatchLabel=KEY=VALUE}"
```

#### Disallow Restarting the Existing Workloads
vArmor allows users to decide whether to perform a rolling restart on all target workloads or not, when creating or deleting a policy with the `.spec.updateExistingWorkloads` field. You can disable this feature with following option. Default: enabled.

```bash
--set restartExistWorkloads.enabled=false
```

#### Disable Pod and Service Egress Control
The feature extends network access control to restrict container access to specific Pods and Services. You can use the following option to disable it. Default: enabled.

```bash
--set podServiceEgressControl.enabled=false
```

The feature is currently only supported by the BPF enforcer and requires Kubernetes v1.21 or higher.

#### Run Agent in HostNetwork Mode
The agent runs in its own network namespace and exposes the readinessProbe on port `6080` by default. If you want to run it in the host's network namespace, you can use following options.

```bash
--set agent.network.hostNetwork=true \
--set agent.network.readinessPort=HOSTPORT
```

#### Enable Exclusive Mode for BPF Enforcer
If your system supports AppArmor LSM, the default AppArmor profile of container runtime will be applied to the workloads which don't have an AppArmor setting explicitly.
You can use this option to disable the default AppArmor profile if a policy with a BPF enforcer is applied to the workload. Default: disabled.

```bash
--set bpfExclusiveMode.enabled=true
```

#### Unload All AppArmor Profiles
All AppArmor profiles managed by vArmor will not be unloaded when the Agent exits or vArmor is uninstalled.
You can use the following option to change this behavior. Default: disabled.

```bash
--set unloadAllAaProfiles.enabled=true
```

#### Remove All Seccomp Profiles
All Seccomp profiles managed by vArmor will not be removed when the Agent exits or vArmor is uninstalled.
You can use the following option to change this behavior. Default: disabled.

```bash
--set removeAllSeccompProfiles.enabled=true
```


## Upgrade

You can use helm commands to upgrade, rollback, and perform other operations.

```bash
helm upgrade varmor varmor-0.8.1.tgz \
    --namespace varmor --create-namespace \
    --set image.registry="elkeid-ap-southeast-1.cr.volces.com" \
    --set bpfLsmEnforcer.enabled=true \
    --set appArmorLsmEnforcer.enabled=false
```
```bash
helm rollback varmor -n varmor
```

## Uninstallation

vArmor can be uninstalled via helm command.

```bash
helm uninstall varmor -n varmor
```

If you are using the AppArmor & Seccomp enforcer, please follow these steps to uninstall vArmor:
* Filter out all VarmorPolicy/VarmorClusterPolicy objects using the AppArmor or Seccomp enforcer (`.spec.policy.enforcer` contains AppArmor or Seccomp)
* Process each VarmorPolicy/VarmorClusterPolicy and its corresponding workloads one by one.
  * Delete the VarmorPolicy/VarmorClusterPolicy object
  * When the workloads' type is Deployment, StatefulSet, or DaemonSet,
    * If you have enabled `--restartExistWorkloads`, you don't need to perform any additional steps.
    * If `--restartExistWorkloads` is not enabled, you will need to manually remove the annotations and seccompProfiles added by vArmor from the corresponding workloads.
  * When the workloads' type is Pod, you will need to recreate the Pod (make sure there are no annotations and seccompProfiles added by vArmor in the Pod).
* Uninstall vArmor using Helm.
