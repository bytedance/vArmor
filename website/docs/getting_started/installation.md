---
sidebar_position: 1
description: Understand how to install, configure, upgrade and uninstall vArmor.
---
# Installation

## Prerequisites

The prerequisites required by different enforcers are as shown in the following table.

|Enforcer|Requirements|Recommendations|
|------------|--------------------------------------------|--------|
|AppArmor    |1. Linux Kernel 4.15+<br />2. The AppArmor LSM is enabled|GKE with Container-Optimized OS<br />AKS with Ubuntu<br />[VKE](https://www.volcengine.com/product/vke) with veLinux<br />Debian 10 and above<br />Ubuntu 18.04.0 LTS and above<br />[veLinux](https://www.volcengine.com/docs/6396/74967) etc.
|BPF         |1. Linux Kernel 5.10+ (x86_64) or 6.6+ (arm64)<br />2. containerd v1.6.0+<br />3. The BPF LSM is enabled|EKS with Amazon Linux 2<br />GKE with Container-Optimized OS<br />[VKE](https://www.volcengine.com/product/vke) with veLinux (with 5.10 kernel)<br />AKS with Ubuntu 22.04 LTS <sup>\*</sup><br />ACK with Alibaba Cloud Linux 3 <sup>\*</sup><br />OpenSUSE 15.4 <sup>\*</sup><br />Debian 11 <sup>\*</sup><br />Fedora 37 <br />[veLinux (with 5.10 kernel)](https://www.volcengine.com/docs/6396/74967) etc.<br /><br />* *Manual enabling of BPF LSM is required*
|Seccomp     |1. Kubernetes v1.19+|All Linux distributions
|NetworkProxy|-|All Linux distributions

## Installation

vArmor can be deployed via a Helm chart which is the recommended and preferred method for a production install.

In order to install vArmor with Helm, first fetch the chart.

```
helm pull oci://elkeid-ap-southeast-1.cr.volces.com/varmor/varmor --version 0.10.4
```

Then install it with helm optional [configurations](#configuration).

```
helm install varmor varmor-0.10.4.tgz \
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

If the `monitoring.coreos.com/v1` API is available in the cluster, vArmor will automatically create a `ServiceMonitor` object during deployment for integration with Prometheus.

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

#### Enable Pod Egress Control
The feature extends network access control to restrict container access to specific Pod IPs. You can use the following option to enable it. Default: disabled.

```bash
--set podEgressControl.enabled=true
```

The feature is currently only supported by the BPF enforcer. When enabling this feature, you may need to allocate more memory to the manager to watch pods. It is not recommended to enable this feature in large-scale clusters (such as those with 10k+ nodes).

#### Run Agent in HostNetwork Mode
The agent runs in its own network namespace and exposes the readinessProbe on port `9580` by default. If you want to run it in the host's network namespace, you can use following options.

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


### Dynamic Configuration

Besides the install-time Helm options above, vArmor ships a runtime-reloadable configuration carried by the `varmor-config` ConfigMap in vArmor's namespace. The manager watches this ConfigMap via an informer and hot-reloads changes **without a restart**. If the ConfigMap is absent or malformed, the manager falls back to the built-in defaults (which are identical to the values shipped by the chart). You can seed its initial content through the `dynamicConfig` value at install time, or edit the ConfigMap directly afterwards.

```bash
kubectl -n varmor edit configmap varmor-config
```

#### Default Resources of the NetworkProxy Sidecar
You can set the cluster-wide default resource requests/limits for the injected NetworkProxy (Envoy) sidecar, so an administrator can tune sidecar resources once instead of setting `.spec.policy.networkProxyConfig.resources` on every policy.

The injector resolves the final resources with a three-layer, field-level merge chain, where each leaf value (`requests.cpu`/`requests.memory`/`limits.cpu`/`limits.memory`) falls back independently:

> per-policy override (`.spec.policy.networkProxyConfig.resources`) > this cluster-global config > built-in defaults

Two independent, MITM-aware tiers are provided, because a MITM sidecar runs heavier (double TLS handshakes). A MITM sidecar reads **only** the `mitm` tier and a non-MITM sidecar reads **only** the `nonMitm` tier — the tiers are **not** inherited from each other. The built-in defaults are:

| Tier | CPU requests | Memory requests | CPU limits | Memory limits |
|------|-------------|----------------|-----------|--------------|
| `nonMitm` | 50m | 64Mi | 500m | 256Mi |
| `mitm` | 100m | 128Mi | 1000m | 512Mi |

```bash
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.cpu="50m" \
--set dynamicConfig.networkProxy.defaultResources.nonMitm.requests.memory="64Mi" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.cpu="1000m" \
--set dynamicConfig.networkProxy.defaultResources.mitm.limits.memory="512Mi"
```

Notes:
* Always quote quantities as strings (e.g. `"500m"`, `"256Mi"`). An unquoted bare number is parsed as an integer, so `memory: 100` means **100 bytes**, not 100Mi.
* The tier keys must be spelled exactly `nonMitm` and `mitm`. A misspelled tier key is silently ignored and that tier falls back to the built-in defaults.
* Invalid entries (an unknown resource name, an unparseable quantity, a non-positive value, or a limit set below its request in the same tier) are ignored and logged by the manager at load time; that field falls back to its built-in default.

#### Micro-VM (Kata) Detection for NetworkProxy Auditing
The NetworkProxy enforcer persists egress violation audit logs through its Envoy sidecar. Under a runc runtime, Envoy streams the records over a node-level hostPath Unix socket to the `varmor-agent` DaemonSet. Under a micro-VM runtime (kata / serverless sandbox) the sidecar runs inside a micro-VM, so that hostPath socket cannot cross the VM boundary (and is rejected at admission by some serverless providers). For such workloads vArmor omits the hostPath volume/mount and starts an in-sidecar audit sink that binds the socket in the container's own rootfs and writes the container-local `/var/log/varmor/violations.log` — producing byte-identical normalized records to the runc path.

The `microVMDetection` config tells the injector which workloads run under a micro-VM runtime. A workload matches if its `runtimeClassName` is listed **OR** any annotation rule matches **OR** any label rule matches (for annotation/label rules, an empty value matches on key presence alone; a non-empty value must match exactly). The built-in defaults already cover upstream kata and the major cloud serverless runtimes:

* `runtimeClassNames`: `kata`, `kata-qemu`, `kata-clh`
* annotation: `vke.volcengine.com/burst-to-vci=enforce` (Volcengine VKE burst-to-VCI)
* label: `alibabacloud.com/eci=true` (Alibaba Cloud ECI)

To extend the rules for a custom micro-VM runtime, edit the `varmor-config` ConfigMap or set the `dynamicConfig.microVMDetection` values at install time.

#### iptables Backend for NetworkProxy Traffic Redirection
The NetworkProxy enforcer transparently redirects traffic by injecting iptables rules through an init container. Starting from the `proxyinit:v0.2` image, vArmor automatically detects the iptables backend (`legacy` vs `nft`) already in use in the target network namespace and drives the matching backend, instead of hardcoding one. This prevents traffic from being silently blackholed in shared-netns setups — for example a kata Pod whose netns is also programmed by a PaaS mesh init using the `legacy` backend. On a fresh netns it defaults to `nft` (matching prior behaviour); if both backends already carry rules it aborts with a `CONFLICT` rather than guessing. This is fully automatic and requires no configuration; just make sure the chart pulls `proxyinit:v0.2` or later.


## Upgrade

You can use helm commands to upgrade, rollback, and perform other operations.

```bash
helm upgrade varmor varmor-0.10.4.tgz \
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
