---
sidebar_position: 2
description: Understand how to use vArmor.
---
# Usage Instructions

## Interface Operations
vArmor provides API interfaces through [VarmorPolicy](usage_instructions#varmorpolicy) and [VarmorClusterPolicy](usage_instructions#varmorclusterpolicy) CR. The VarmorClusterPolicy CR have higher priority than VarmorPolicy CR. It means prioritizing the use of VarmorClusterPolicy objects to protect matched workloads. You can create, modify, and delete VarmorPolicy or VarmorClusterPolicy objects in the cluster to protect specified workloads.

vArmor supports performing a rolling restart of existing workloads that meet the matching conditions when a VarmorPolicy or VarmorClusterPolicy object is created or deleted. This rolling restart enables or disables protection for those workloads.

The following constraints and usage requirements must also be observed:
* Workloads must have the label **`sandbox.varmor.org/enable="true"`** to be processed by vArmor's webhook server during creation and updates. If they meet the matching conditions specified in a VarmorPolicy or VarmorClusterPolicy object's `spec.target`, vArmor will enable sandbox for them.
* Once a VarmorPolicy or VarmorClusterPolicy object is created, its `spec.target` cannot be changed. Please create a new VarmorPolicy or VarmorClusterPolicy with the desired target to make changes.
* After creating a VarmorPolicy or VarmorClusterPolicy object, you can dynamically switch the policy mode and update rules by updating `spec.policy`. However, switching from **BehaviorModeling mode** to other modes is not supported, and vice versa (Note: Switching policy mode and updating rules does not require triggering a rolling restart of workloads).

## State Management
You can check the status of VarmorPolicy or VarmorClusterPolicy object to get information about the processing stage, error messages, and the processing status of AppArmor/BPF/Seccomp Profiles.

You can check the `profileName` field by examining the status of VarmorPolicy or VarmorClusterPolicy object. Afterwards, you can look at the corresponding ArmorProfile object with the same name to obtain the status and error information when the Agent processes the Profile.

## Log Management
vArmor's manager and agent components currently log messages only to standard output.

You can leverage logging components for collection and configuring alerts. Such as `\* | select count(*) as ErrCount where __content__ LIKE 'E%'`

## System Interface
### VarmorPolicy
* Namespace-scoped resource, consistent with the namespace of the protected object.
* The VarmorPolicy interface details can be found in [Interface Instructions](interface_instructions).
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
* The VarmorClusterPolicy interface details can be found in [Interface Instructions](interface_instructions)
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

```
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

The policy enables sandbox with **EnhanceProtect mode** for deployments in the default namespace (with `sandbox.varmor.org/enable="true"` and `app=nginx` labels, and an `environment` label value of `dev` or `qa`).

The built-in rules used are as follows:
- Disable all privileged capabilities (those that can lead to escapes)
- Disable CAP_NET_RAW capability (Prohibit the use of the AF_PACKET protocol family to create sockets, preventing the construction of link-layer packets and activities like network sniffing.)
- Prohibit writing to the /etc directory
- Prohibit shell and its subprocesses from accessing the container's ServiceAccount information

## Demos
Here are some [demos](https://github.com/bytedance/vArmor/tree/main/test/demos) on how to use vArmor to mitigate vulnerabilities or harden containers with privileged capabilities.
