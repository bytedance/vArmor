---
sidebar_position: 2
description: Understand how to use vArmor.
---
# Usage Instructions

## Interface Operations
vArmor provides API interfaces through [VarmorPolicy](interface_specification.md#varmorpolicy) and [VarmorClusterPolicy](interface_specification.md#varmorclusterpolicy) CR. The VarmorClusterPolicy CR have higher priority than VarmorPolicy CR. It means prioritizing the use of VarmorClusterPolicy objects to protect matched workloads. You can create, modify, and delete VarmorPolicy or VarmorClusterPolicy objects in the cluster to protect specified workloads.

vArmor supports performing a rolling restart of existing workloads that meet the matching conditions when a VarmorPolicy or VarmorClusterPolicy object is created or deleted. This rolling restart enables or disables protection for those workloads.

The following constraints and usage requirements must also be observed:
* Workloads must have the label **`sandbox.varmor.org/enable="true"`** to be processed by vArmor's webhook server during creation and updates. If they meet the matching conditions specified in a VarmorPolicy or VarmorClusterPolicy object's `spec.target`, vArmor will enable sandbox for them.
* Once a VarmorPolicy or VarmorClusterPolicy object is created, its `spec.target` cannot be changed. Please create a new VarmorPolicy or VarmorClusterPolicy with the desired target to make changes.
* After creating a VarmorPolicy or VarmorClusterPolicy object, you can dynamically add enforcers, switch the policy mode and update rules by updating `spec.policy`. However, switching from **BehaviorModeling** mode to other modes is not supported, and vice versa (Note: Switching policy mode and updating rules does not require triggering a rolling restart of workloads).

## State Management
You can check the status of VarmorPolicy or VarmorClusterPolicy object to get information about the processing stage, error messages, and the processing status of AppArmor/BPF/Seccomp Profiles.

You can check the `profileName` field by examining the status of VarmorPolicy or VarmorClusterPolicy object. Afterwards, you can look at the corresponding ArmorProfile object with the same name to obtain the status and error information when the Agent processes the Profile.

## Log Management

### Component Logs
The Manager and Agent components log through standard output. By default, the log format is TEXT. You can switch it to JSON format through [this option](../getting_started/installation.md#set-the-log-output-format-to-json).

### Audit Logs
vArmor supports configuring policy objects in alarm-only mode (observation mode) and alarm-interception mode. You can achieve this through the `auditViolations` and `allowViolations` fields of the policy object. For common usage, please refer to [this document](../practices/index.md#common-usage-methods). All violation events will be logged in JSON format to the /var/log/varmor/violations.log file on the host machine (the maximum file size is 10MB, and up to 3 old files will be retained).

The format of violation events is as follows. Behaviors that are intercepted and alarmed will generate `warn` level events, and behaviors that are alarmed only without interception will generate `debug` level events.

* Currently, only the AppArmor and BPF enforcers support the alarm-interception mode.
* Limited by the principle and performance impact of Seccomp, you can only use `auditViolations=true` and `allowViolations=true` in combination to implement the alarm-only mode (observation mode) for the Seccomp enforcer when there is no policy in the BehaviorModeling mode.
* Limited by the principle of the AppArmor LSM and Seccomp, when using the AppArmor or Seccomp enforcer, in some cases, the corresponding container and Pod information cannot be matched.

```json
{
  "level": "warn",
  "nodeName": "192.168.0.24",
  "containerID": "fd808d9394a76680bd9f4de84413e6521cfc4e4c5097e0c6904b0f58e5f564cc",
  "containerName": "c1",
  "podName": "demo-2-57cd6498bb-472vk",
  "podNamespace": "demo",
  "podUID": "be8ea9dd-28c0-4401-b1e5-09fa06b14761",
  "pid": 887808,
  "mntNsID": 4026532637,
  "eventTimestamp": 1740381264,
  "eventType": "BPF",
  "action": "DENIED",
  "profileName": "varmor-demo-demo-2",
  "event": {
    "permissions": [
      "read"
    ],
    "path": "/run/secrets/kubernetes.io/serviceaccount/..2025_02_24_06_32_23.1519281840/token"
  },
  "time": "2025-02-24T07:14:24Z",
  "message": "violation event"
}
```

```json
{
  "level": "warn",
  "nodeName": "192.168.0.8",
  "containerID": "5b24d520534b9ad2b618cd9f014a7cca045e5d217718852af6d12d587ef2b6c6",
  "containerName": "c1",
  "podName": "demo-1-5bccf6777c-c8lzr",
  "podNamespace": "demo",
  "podUID": "7efce0ca-5609-4cf5-aba4-eba24036cc6c",
  "pid": 3811300,
  "mntNsID": 4026532725,
  "eventTimestamp": 1740366282,
  "eventType": "AppArmor",
  "action": "DENIED",
  "profileName": "varmor-demo-demo-1",
  "event": {
    "version": 1,
    "event": 4,
    "pid": 3811300,
    "peerPID": 0,
    "task": 0,
    "magicToken": 0,
    "epoch": 1740366282,
    "auditSubId": 674,
    "bitMask": 0,
    "auditID": "1740366282.121:674",
    "operation": "mknod",
    "deniedMask": "c",
    "requestedMask": "c",
    "fsuid": 0,
    "ouid": 0,
    "profile": "varmor-demo-demo-1//child_0",
    "peerProfile": "",
    "comm": "bash",
    "name": "/etc/5",
    "name2": "",
    "namespace": "",
    "attribute": "",
    "parent": 0,
    "info": "",
    "peerInfo": "",
    "errorCode": 0,
    "activeHat": "",
    "netFamily": "",
    "netProtocol": "",
    "netSockType": "",
    "netLocalAddr": "",
    "netLocalPort": 0,
    "netForeignAddr": "",
    "netForeignPort": 0,
    "dbusBus": "",
    "dbusPath": "",
    "dbusInterface": "",
    "dbusMember": "",
    "signal": "",
    "peer": "",
    "fsType": "",
    "flags": "",
    "srcName": ""
  },
  "time": "2025-02-24T03:04:42Z",
  "message": "violation event"
}
```

```json
{
  "level": "debug",
  "nodeName": "192.168.0.8",
  "containerID": "8c1058d1159d3ed20960c0c9f53fc26968a1c75cd3b390a503e060ffd8c972da",
  "containerName": "c0",
  "podName": "demo-5-5f689fcfc4-5gxll",
  "podNamespace": "demo",
  "podUID": "72ae1199-c061-4bc0-a00e-9dc8061caddf",
  "pid": 1448697,
  "mntNsID": 4026533364,
  "eventTimestamp": 1740621808,
  "eventType": "Seccomp",
  "action": "ALLOWED",
  "profileName": "varmor-demo-demo-5",
  "event": {
    "auditID": "1740621808.346:683",
    "epoch": 1740621808,
    "subj": "varmor-demo-demo-5 (enforce)",
    "pid": 1448697,
    "comm": "unshare",
    "exe": "/usr/bin/unshare",
    "syscall": "unshare"
  },
  "time": "2025-02-27T02:03:28Z",
  "message": "violation event"
}
```

## System Interface
### VarmorPolicy
* Namespace-scoped resource, consistent with the namespace of the protected object.
* The VarmorPolicy interface details can be found in [Interface Specification](interface_specification.md).
* The definition of VarmorPolicy can be found in [VarmorPolicy CRD](https://github.com/bytedance/vArmor/tree/main/config/crds/crd.varmor.org_varmorpolicies.yaml).
* Explanation of `VarmorPolicy/Status`:

  | Fields | Value | Interpretation |
  |--------|-------|----------------|
  |Phase|Pending|The ArmorProfile has been created, waiting for a response from the Agent component.
  |     |Protecting|Enforcing access control on the containers of the target workload.
  |     |Modeling|Currently modeling the behavior of the target application.
  |     |Completed|Behavior modeling for the target application has been completed.
  |     |Error|Error occurred, please retrieve error information through the conditions fields.
  |Conditions|Type=Created<br />Status=True|The creation event of VarmorPolicy has been responded by the controller and processed successfully.
  |          |Type=Created<br />Status=False<br />Reason=XXX<br />Message=YYY|The creation event of VarmorPolicy has been responded to by the controller, but processing has failed. This includes the reason for the failure and error information.
  |          |Type=Updated<br />Status=True|The update event of VarmorPolicy has been responded to by the controller and processed successfully.
  |          |Type=Updated<br />Status=False<br />Reason=XXX<br />Message=YYY|The update event of VarmorPolicy has been responded to by the controller, but processing has failed. This includes the reason for the failure and error information.
  |Ready|True|The profile has been processed and loaded by all agents.
  |     |False|The profile has not yet been processed and loaded by all agents.

### VarmorClusterPolicy
* Cluster-scoped resource.
* The VarmorClusterPolicy interface details can be found in [Interface Specification](interface_specification.md)
* The definition of VarmorClusterPolicy can be found in [VarmorClusterPolicy CRD](https://github.com/bytedance/vArmor/tree/main/config/crds/crd.varmor.org_varmorclusterpolicies.yaml)
* `VarmorClusterPolicy/Status` same as `VarmorPolicy/Status`

### ArmorProfile
* Namespace-scoped resource, consistent with the namespace of the protected object or the namespace of the vArmor components.
* **As an internal interface, used by vArmor only.**
* The definition of ArmorProfile can be found in [ArmorProfile CRD](https://github.com/bytedance/vArmor/tree/main/config/crds/crd.varmor.org_armorprofiles.yaml).
* Explanation of `ArmorProfile/Status`:

  | Fields | Value | Interpretation |
  |--------|-------|----------------|
  |DesiredNumberLoaded|int|The desired number of agents for processing and responding
  |CurrentNumberLoaded|int|The number of agents that have already been processed and responded.
  |Conditions|type=Read<br />Status=False<br />NodeName=XXX<br />Message=YYY|The failed node and error information

## Example
The following example is for demonstration of functionality only, and should not be considered as recommended policy.

```yaml
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: deployment-policy
  namespace: default
spec:
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: nginx
      matchExpressions:
      - key: environment
        operator: In
        values: [dev, qa]
  policy:
    enforcer: AppArmor
    mode: EnhanceProtect
    enhanceProtect:
      hardeningRules:
      - disable_cap_privileged
      - disable_cap_net_raw
      attackProtectionRules:
      - rules: 
        - disable-write-etc
      - rules:
        - mitigate-sa-leak
        targets:
        - "/bin/sh"
        - "/usr/bin/sh"
        - "/bin/dash"
        - "/usr/bin/dash"
        - "/bin/bash"
        - "/usr/bin/bash"
        - "/bin/busybox"
        - "/usr/bin/busybox"
```

The policy enables sandbox with **EnhanceProtect** mode for deployments in the default namespace (with `sandbox.varmor.org/enable="true"` and `app=nginx` labels, and an `environment` label value of `dev` or `qa`).

The built-in rules used are as follows:
- Disable all privileged capabilities (those that can lead to escapes)
- Disable CAP_NET_RAW capability (Prohibit the use of the AF_PACKET protocol family to create sockets, preventing the construction of link-layer packets and activities like network sniffing.)
- Prohibit writing to the /etc directory
- Prohibit shell and its subprocesses from accessing the container's ServiceAccount information

## Demos
Here are some [demos](https://github.com/bytedance/vArmor/tree/main/test/demos) on how to use vArmor to mitigate vulnerabilities or harden containers with privileged capabilities.
