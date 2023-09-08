# Usage Instructions
English | [简体中文](usage_instructions.zh_CN.md)

## Configuration
vArmor allows you to configure its functionality during installation using the helm command.

| Helm Options | Description |
|--------------|-------------|
| `--set appArmorLsmEnforcer.enabled=false` | Default: enabled. The AppArmor enforcer can be disabled with it when the system does not support AppArmor LSM.
| `--set bpfLsmEnforcer.enabled=true` | Default: disabled. The BPF enforcer can be enabled when the system supports BPF LSM.
| `--set bpfExclusiveMode.enabled=true` | Default: disabled. When enabled, AppArmor protection for the target workload will be disabled when a VarmorPolicy object uses the BPF enforcer.
| `--set restartExistWorkloads.enabled=true` | Default: disabled. When enabled, vArmor will perform a rolling restart of existing workloads (only for Deployments, DaemonSet, and StatefulSet resources) that meet the conditions when creating or deleting a VarmorPolicy object.
| `--set unloadAllAaProfile.enabled=true` | Default: disabled. When enabled, all AppArmor profiles loaded by vArmor will be unloaded when the Agent exits.
| `--set "manager.args={--webhookMatchLabel=KEY=VALUE}"` | The default value is: `sandbox.varmor.org/enable=true`. vArmor will only enable sandbox protection for Workloads that contain this label. You can disable this feature by using `--set 'manager.args={--webhookMatchLabel=}'`.
| `--set defenseInDepth.enabled=true` | Default: disabled. Experimental feature. Currently, only the AppArmor enforcer supports the DefenseInDepth mode.


## Usage
### Interface Operations
* The API interface for vArmor is the VarmorPolicy CR, which is a namespace-scoped resource. Users can create, modify, and delete VarmorPolicy objects in the cluster to protect workloads within the same namespace.
* Workloads must have the label `sandbox.varmor.org/enable="true"` to be processed by vArmor's webhook server during creation and updates. If they meet the matching conditions specified in a VarmorPolicy object's `spec.target`, vArmor will enable sandbox protection for them.
* vArmor supports performing a rolling restart of existing workloads that meet the matching conditions when a VarmorPolicy object is created or deleted. This rolling restart enables or disables protection for those workloads.
* Once a VarmorPolicy object is created, its `spec.target` cannot be changed. Please create a new VarmorPolicy with the desired target to make changes.
* After creating a VarmorPolicy object, you can dynamically switch protection modes and update protection rules by updating `spec.policy`. However, switching from DefenseInDepth mode to other modes is not supported, and vice versa (Note: Switching protection modes and updating protection rules does not require triggering a rolling restart of workloads).
### State Management
* You can check the VarmorPolicy/Status to get information about the object's processing stage, error messages, and the processing status of AppArmor/BPF Profiles.
* You can check the Profile Name by examining VarmorPolicy/Status. Afterwards, you can look at the corresponding ArmorProfile object with the same name in the same namespace to obtain the status and error information when the Agent processes the Profile. For example, you can determine which node failed to process it and the reasons for the failure.
### Log Management
* vArmor's manager and agent components currently log messages only to standard output.
* You can leverage logging components for collection and configuring alerts. Such as `\* | select count(*) as ErrCount where __content__ LIKE 'E0%'`
### Uninstallation Guide
If you are using the AppArmor enforcer, follow these steps to uninstall vArmor:
* Filter out all VarmorPolicy objects using the AppArmor enforcer (`.spec.policy.enforcer` is AppArmor)
  ```
  kubectl get VarmorPolicy -A -o wide | grep AppArmor
  ```
* Process each VarmorPolicy and its corresponding workloads one by one.
  * Delete the VarmorPolicy object
  * When the workloads' type is Deployment, StatefulSet, or DaemonSet,
    * If you have enabled --restartExistWorkloads, you don't need to perform any additional steps.
    * If --restartExistWorkloads is not enabled, you will need to manually remove the annotations with key 'container.apparmor.security.beta.kubernetes.io/[CONTAINER_NAME]' from the corresponding workloads.
  * When the workloads' type is Pod, you will need to recreate the Pod (make sure there are no annotations with the key 'container.apparmor.security.beta.kubernetes.io/[CONTAINER_NAME]' in the Pod).
* Uninstall vArmor using Helm.

## System Interface
### VarmorPolicy
* Namespace-scoped resource, consistent with the namespace of the protected object.
* Use vArmor by creating, updating, or deleting VarmorPolicy objects.
* The VarmorPolicy interface details can be found in [Interface Instructions](interface_instructions.md).
* The definition of VarmorPolicy can be found in [VarmorPolicy CRD](../config/crds/crd.varmor.org_varmorpolicies.yaml).
* Explanation of VarmorPolicy/Status:

  | Fields | Value | Interpretation |
  |--------|-------|----------------|
  |Phase|Pending|The ArmorProfile has been created, waiting for a response from the Agent component.
  |     |Protecting|Enforcing access control on the containers of the target workload
  |     |Modeling|Modeling behavior for the target application
  |     |Completed|Behavior modeling for the target application has been completed.
  |     |Error|Error occurred, please retrieve error information through the conditions fields.
  |Conditions|Type=Created<br>Status=True|The creation event of VarmorPolicy has been responded by the controller and processed successfully.
  |          |Type=Created<br>Status=False<br>Reason=XXX<br>Message=YYY|The creation event of VarmorPolicy has been responded to by the controller, but processing has failed. This includes the reason for the failure and error information.
  |          |Type=Updated<br>Status=True|The update event of VarmorPolicy has been responded to by the controller and processed successfully.
  |          |Type=Updated<br>Status=False<br>Reason=XXX<br>Message=YYY|The update event of VarmorPolicy has been responded to by the controller, but processing has failed. This includes the reason for the failure and error information.
  |Ready|True|The profile has been processed and loaded by all agents.
  |     |False|The profile has not yet been processed and loaded by all agents.
### ArmorProfile
* Namespace-scoped resource, consistent with the namespace of the protected object.
* As an internal interface, used by vArmor only.
* The definition of VarmorPolicy can be found in [ArmorProfile CRD](../config/crds/crd.varmor.org_armorprofiles.yaml).
* Explanation of ArmorProfile/Status:

  | Fields | Value | Interpretation |
  |--------|-------|----------------|
  |DesiredNumberLoaded|int|The desired number of agents for processing and responding
  |CurrentNumberLoaded|int|The number of agents that have already been processed and responded.
  |Conditions|type=Read<br>Status=False<br>NodeName=XXX<br>Message=YYY|The failed node and error information

## Example 1
The following policy enables sandbox with EnhanceProtect mode for deployments in the default namespace (with `sandbox.varmor.org/enable="true"` and `app=nginx` labels, and an `environment` label value of `dev` or `qa`). The sandbox rules used are as follows:

- Disable all privileged capabilities (those that can lead to escapes)
- Disable CAP_NET_RAW capability (Prohibit the use of the AF_PACKET protocol family to create sockets, preventing the construction of link-layer packets and activities like network sniffing.)
- Prohibit writing to the /etc directory
- Prohibit shell and its subprocesses from accessing the container's ServiceAccount information

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
## Example 2
The following policy enables sandbox with EnhanceProtect mode for pods in the test namespace (with `sandbox.varmor.org/enable="true"` and `app=custom-controller-pod` labels). The sandbox rules used are as follows:
- Disable all privileged capabilities
- Disable CAP_NET_RAW capability
- Prohibit writing to the /etc directory
- Prohibit shell and its subprocesses from accessing the container's ServiceAccount information
```
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: pod-policy
  namespace: test
spec:
  target:
    kind: Pod
    selector:
      matchLabels:
        app: custom-controller-pod
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
        - mitigate-host-ip-leak
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
