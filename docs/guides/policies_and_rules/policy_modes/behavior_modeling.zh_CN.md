# BehaviorModeling 模式

[English](behavior_modeling.md) | 简体中文

## 介绍

BehaviorModeling 模式是一个实验功能。您可以利用 BehaviorModeling 模式在指定时间范围内收集并处理目标工作负载的行为，对其进行行为建模。一旦建模结束，vArmor 会生成一个 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对象，用来保存目标工作负载的行为模型。

行为模型可以被用于分析哪些内置规则能够被用于加固目标应用，或者指导用户对工作负载的安全上下文进行权限最小化。

## 前置条件

vArmor 利用 BPF 技术和 Linux 审计系统来捕获目标应用的行为。前置条件如下所示：

1. containerd v1.6.0 及以上版本

2. 系统需支持 BTF (BPF Type Format)

    一般来说，当节点存在 `/sys/kernel/btf/vmlinux` 文件时，意味着系统支持 BTF。

3. vArmor 启用了此特性
   * 通过 `--set behaviorModeling.enabled=true` 选项开启 BehaviorModeling 特性。

   * [可选] 使用 `--set "agent.args={--auditLogPaths=FILE_PATH|FILE_PATH}"` 选项来指定系统审计日志或搜索顺序。

    *注意：* 
    * *vArmor 顺序检查系统审计日志是否存在，并通过监控第一个有效的文件来获取 AppArmor 和 Seccomp 的审计事件，从而用于违规审计和行为建模功能。当您使用 **auditd** 时，AppArmor 和 Seccomp 的审计事件会默认保存在 `/var/log/audit/audit.log` 文件中。否则，他们通常会被保存在 `/var/log/kern.log` 文件中。*

    * *启用 BehaviorModeling 特性时，**varmor-agent** 需要如下所示的追加资源。另外，**varmor-classifier** 组件也会被部署，用于识别路径中的随机字符串。*

      ```yaml
      resources:
        limits:
          cpu: 2
          memory: 2Gi
        requests:
          cpu: 500m
          memory: 500Mi
      ```

## 使用说明

### 基本用法
使用 BehaviorModeling 功能的基本步骤如下所示。

**1. 创建 BehaviorModeling 模式的策略**

您可以通过 `.spec.policy.modelingOptions.duration` 字段设置建模时长，并在建模完成前按需调整。您还可以通过 `.spec.updateExistingWorkloads` 字段设置是否对符合条件的目标工作负载进行滚动重启（仅支持 Deployment, DaemonSet, StatefulSet 类型的目标工作负载），从而立即开始行为建模。

```yaml
apiVersion: crd.varmor.org/v1beta1
kind: VarmorPolicy
metadata:
  name: demo-4
  namespace: demo
spec:
  # Perform a rolling update on existing workloads.
  # It's disabled by default.
  updateExistingWorkloads: true
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: demo-4
  policy:
    enforcer: AppArmorSeccomp
    # mode: DefenseInDepth
    mode: BehaviorModeling
    modelingOptions:
      # The duration in minutes to modeling
      duration: 3
```

**2. 创建符合条件的目标工作负载**

如果 `updateExistingWorkloads=true` 且目标工作负载的类型不为 Pod，那么您可以跳过此步骤。否则您应当创建新的符合条件的工作负载。

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-4
  namespace: demo
  labels:
    app: demo-4
    # This label is required with target workloads. 
    # You can disable the feature with --set 'manager.args={--webhookMatchLabel=}'
    sandbox.varmor.org/enable: "true"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: demo-4
  template:
    metadata:
      labels:
        app: demo-4
      annotations:
        # Use these annotation to explicitly disable the protection for the container named c0.
        # It always takes precedence over the '.spec.target.containers' field of VarmorPolicy 
        # or VarmorClusterPolicy object.
        container.apparmor.security.beta.varmor.org/c0: unconfined
        container.seccomp.security.beta.varmor.org/c0: unconfined
    spec:
      shareProcessNamespace: true
      containers:
      - name: c0
        image: curlimages/curl:7.87.0
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent
      - name: c1
        image: debian:10
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent
```

**3. 更新建模时长（按需）**

您可以根据需要，通过更新策略的 `.spec.policy.modelingOptions.duration` 字段来修改建模时长。例如将其修改为 1 从而提前结束建模。

```bash
kubectl patch vpol -n demo demo-4 --type='json' -p='[{"op": "replace", "path": "/spec/policy/modelingOptions/duration", "value":1}]'
```

**4. 等待建模完成**

```bash
$ kubectl get vpol -n demo
NAME     ENFORCER          MODE               TARGET-KIND   TARGET-NAME   TARGET-SELECTOR                    PROFILE-NAME         READY   STATUS     AGE
demo-4   AppArmorSeccomp   BehaviorModeling   Deployment                  {"matchLabels":{"app":"demo-4"}}   varmor-demo-demo-4   true    Modeling   2s

$ kubectl get vpol -n demo
NAME     ENFORCER          MODE               TARGET-KIND   TARGET-NAME   TARGET-SELECTOR                    PROFILE-NAME         READY   STATUS     AGE
demo-4   AppArmorSeccomp   BehaviorModeling   Deployment                  {"matchLabels":{"app":"demo-4"}}   varmor-demo-demo-4   true    Completed  30m
```

建模完成后，agent 会对在节点上采集到的（目标工作负载的）行为数据进行预处理，然后将其发送到 manager。而 manager 将对所有节点采集的数据进行分析，并将其保存在对应命名空间的 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对象的 `.data.dynamicResult` 字段中。
  
manager 处理完所有节点的行为数据后，它会以白名单方式（Deny-by-Default）为目标工作负载生成 AppArmor 或 Seccomp Profile，并保存在 ArmorProfileModel 对象的 `.data.profile.content` 和 `.data.profile.seccompContent` 字段中。
  
当数据量过大导致无法保存在 CRD 对象中时，manager 会将其保存在本地。您可以通过 ArmorProfileModel 对象的 `.storageType` 字段判断行为数据和 Profile 的存储形式。

```bash
$ kubectl get ArmorProfileModel -A
NAMESPACE   NAME                         STORAGE-TYPE   DESIRED   COMPLETED   READY   AGE
demo        varmor-cluster-demo-demo-4   CRDInternal    2         2           true    23h  
```

### 注意事项

* 目标工作负载需要拥有 `sandbox.varmor.org/enable="true"` 标签。您可以通过 [设置 Webhook 的匹配标签](../../../getting_started/installation.zh_CN.md#设置-webhook-的匹配标签) 配置选项关闭此特性。
* 不支持将 BehaviorModeling 模式的策略切换为其他模式，反之亦然。您需要删除策略后重新创建策略才可切换。
* 建模完成后，不支持修改策略的建模时长。您需要删除策略后重新创建策略才可以重新开始建模，但已有的行为数据会被保留。
* 使用 **BPF enforcer** 进行行为建模期间，尽量不要使用 `kubectl exec` 在容器中执行交互式命令，否则会采集到额外的行为数据。

### 数据持久化

建模结果会被 manager 保存到 ArmorProfileModel 对象中。

当行为数据过大时，manager 会将其持久化到本次磁盘，并将 `storageType` 字段设置为 `LocalDisk`。

默认情况下，manager 使用存储空间为 **500Mi** 的 `emptyDir` 卷来存储建模结果。您可以通过 `--set manager.behaviorModeling.usePersistentVolume=true` 选项启用使用持久化卷存储建模结果。启用持久卷前，请确保 manager 所在命名空间中已创建了名为 **varmor-manager-apmdata-pvc** 的 PVC。

### 数据导出与导入

您可以将目标负载的行为数据和 Profiles 导出用于其他目的。例如：使用[策略顾问](../../policy_advisor.md)分析哪些内置规则能够被用于加固目标应用，基于行为数据指导用户对工作负载的安全上下文进行权限最小化等。您还可以将导出的数据导入到其他集群中进行使用。

不同存储类型的 ArmorProfileModel 对象导出与导入方法不同：

  * **CRDInternal**

    - 直接使用 kubectl 导出

      ```bash
      kubectl get ArmorProfileModel -n demo varmor-demo-demo-4 -o json > varmor-demo-demo-4.json
      ```
    
    - 直接使用 kubectl 导入

      ```bash
      kubectl apply -f varmor-demo-demo-4.json
      ```

  * **LocalDisk**

    - 将本地端口 8080 转发到集群 `varmor-status-svc` Service 的 8080 端口

      ```bash
      kubectl port-forward -n varmor service/varmor-status-svc 8080:8080
      ```

    - 获取具有 armorprofilemodels 资源读写权限的 ServiceAccount token。这里使用 varmor-manager 的 ServiceAccount token。

      ```bash
      token=$(kubectl create token varmor-manager -n varmor)
      ```

    - 访问 `/apis/crd.varmor.org/v1beta1/namespaces/{namespace}/armorprofilemodels/{name}` 接口导出数据
    
      ```bash
      curl -k -X GET \
        -H "Authorization: Bearer $token" \
        https://localhost:8080/apis/crd.varmor.org/v1beta1/namespaces/demo/armorprofilemodels/varmor-demo-demo-4 > varmor-demo-demo-4.json
      ```
    
    - 访问 `/apis/crd.varmor.org/v1beta1/namespaces/{namespace}/armorprofilemodels/{name}` 接口导入数据

      如果集群的命名空间中已经有同名的 ArmorProfileModel 对象，那么行为数据会被合并，Profiles 会被覆盖。

      ```bash
      curl -k \
          -X POST https://localhost:8080/apis/crd.varmor.org/v1beta1/namespaces/demo/armorprofilemodels/varmor-demo-demo-4 \
          -H "Authorization: Bearer $token" \
          -H "Accept: application/json" \
          -H "Content-Type: application/json" \
          -d @varmor-demo-demo-4.json
      ```

## 示例

### 1. 部署目标工作负载

分别在 defalut 和 demo 命名空间创建目标工作负载。

```yaml
cat << EOF | kubectl create -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-4
  namespace: default
  labels:
    app: demo-4
    # This label is required with target workloads. 
    # You can disable the feature with --set 'manager.args={--webhookMatchLabel=}'
    sandbox.varmor.org/enable: "true"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: demo-4
  template:
    metadata:
      labels:
        app: demo-4
    spec:
      containers:
      - name: c0
        image: debian:10
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent
EOF
```

```yaml
cat << EOF | kubectl create -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-4
  namespace: demo
  labels:
    app: demo-4
    # This label is required with target workloads. 
    # You can disable the feature with --set 'manager.args={--webhookMatchLabel=}'
    sandbox.varmor.org/enable: "true"
spec:
  replicas: 2
  selector:
    matchLabels:
      app: demo-4
  template:
    metadata:
      labels:
        app: demo-4
      annotations:
        # Use these annotation to explicitly disable the protection for the container named c0.
        # It always takes precedence over the '.spec.target.containers' field of VarmorPolicy 
        # or VarmorClusterPolicy object.
        container.apparmor.security.beta.varmor.org/c0: unconfined
        container.seccomp.security.beta.varmor.org/c0: unconfined
    spec:
      shareProcessNamespace: true
      containers:
      - name: c0
        image: curlimages/curl:7.87.0
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent
      - name: c1
        image: debian:10
        command: ["/bin/sh", "-c", "sleep infinity"]
        imagePullPolicy: IfNotPresent
EOF
```

### 2. 创建策略进行建模

创建一个使用 BehaviorModeling 模式的策略。您可以通过 `.spec.policy.modelingOptions.duration` 字段来设置建模时长。

一旦策略创建成功，目标工作负载会被自动更新。您也可以在部署工作负载前创建策略。

```yaml
cat << EOF | kubectl create -f -
apiVersion: crd.varmor.org/v1beta1
kind: VarmorClusterPolicy
metadata:
  name: demo-4
spec:
  # Perform a rolling update on existing workloads.
  # It's disabled by default.
  updateExistingWorkloads: true
  target:
    kind: Deployment
    selector:
      matchLabels:
        app: demo-4
  policy:
    enforcer: AppArmorSeccomp
    # mode: DefenseInDepth
    mode: BehaviorModeling
    modelingOptions:
      # 30 minutes
      duration: 30
EOF
```

### 3. 检查状态

检查策略对象，如果一切正常，策略会就绪并运行在 `Modeling` 状态下。

```bash
$ kubectl get vcpol demo-4
NAME     ENFORCER          MODE               TARGET-KIND   TARGET-NAME   TARGET-SELECTOR                    PROFILE-NAME                   READY   STATUS     AGE
demo-4   AppArmorSeccomp   BehaviorModeling   Deployment                  {"matchLabels":{"app":"demo-4"}}   varmor-cluster-varmor-demo-4   true    Modeling   2s
```

检查目标工作负载，如果在目标工作负载部署后创建策略，那么工作负载将被更新，并进行滚动重启。

```bash
$ kubectl get Pods -A -l app=demo-4
NAMESPACE   NAME                      READY   STATUS              RESTARTS   AGE
default     demo-4-6b98965dc-5xfqn    1/1     Running             0          49s
default     demo-4-6b98965dc-kmpbn    1/1     Terminating         0          50s
default     demo-4-b4d56646c-b82hw    0/1     ContainerCreating   0          1s
default     demo-4-b4d56646c-bdk56    1/1     Running             0          3s
demo        demo-4-5f4d94f7d9-5st8f   2/2     Running             0          3s
demo        demo-4-5f4d94f7d9-8k6r6   0/2     ContainerCreating   0          1s
demo        demo-4-9b8848dbc-84qwf    2/2     Running             0          49s
demo        demo-4-9b8848dbc-bs5jr    2/2     Terminating         0          50s
```

### 4. 模拟行为

当工作负载全部完成滚动更新后，运行以下命令。注意，在运行以下命令前请确保没有 Pod 处于 *Terminating* 状态，以防在错误的容器内执行了命令。

```bash
$ pod_name=$(kubectl get Pods -n default -l app=demo-4 -o jsonpath='{.items[0].metadata.name}')
$ kubectl exec -n default $pod_name -c c0 -it -- cat /etc/shadow
$ kubectl exec -n default $pod_name -c c0 -it -- bash -c "unshare -Un id"

$ pod_name=$(kubectl get Pods -n demo -l app=demo-4 -o jsonpath='{.items[1].metadata.name}')
$ kubectl exec -n demo $pod_name -c c0 -it -- bash -c "echo $pod_name/c0 > /root/c0"
$ kubectl exec -n demo $pod_name -c c0 -it -- cat /root/c0

$ kubectl exec -n demo $pod_name -c c1 -it -- bash -c "echo $pod_name/c1 > /root/c1"
$ kubectl exec -n demo $pod_name -c c1 -it -- cat /root/c1
```

### 5. 停止建模

调整建模时长，并等待 **VarmorClusterPolicy** 对象的状态切换成 `Completed`。

```bash
$ kubectl patch vcpol demo-4 --type='json' -p='[{"op": "replace", "path": "/spec/policy/modelingOptions/duration", "value":1}]'

$ kubectl get vcpol demo-4
NAME     ENFORCER          MODE               TARGET-KIND   TARGET-NAME   TARGET-SELECTOR                    PROFILE-NAME                   READY   STATUS      AGE
demo-4   AppArmorSeccomp   BehaviorModeling   Deployment                  {"matchLabels":{"app":"demo-4"}}   varmor-cluster-varmor-demo-4   true    Completed   3m32s
```

### 6. 检查结果

目标工作负载的所有行为数据均会被处理，并保存在与 **ArmorProfile** 对象相同命名空间中的 **ArmorProfileMode** 对象里。

您可以使用下面的命令进行查看。

```bash
$ profile_name=$(kubectl get vcpol demo-4 -o jsonpath='{.status.profileName}')
$ kubectl get ArmorProfileModel -n varmor $profile_name -o yaml
```

vArmor 还会基于行为数据生成默认拦截的 AppArmor 和 Seccomp profile。

您可以使用下面的命令输出 AppArmor profile。

```bash
$ kubectl get ArmorProfileModel -n varmor varmor-cluster-varmor-demo-4 -o jsonpath='{.data.profile.content}'

## == Managed by vArmor == ##

abi <abi/3.0>,
#include <tunables/global>

profile varmor-cluster-varmor-demo-4 flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  # ---- EXEC ----
  /usr/bin/id ix,
  /usr/bin/sleep ix,
  /usr/bin/unshare ix,

  # ---- FILE ----
  owner /dev/tty rw,
  owner /etc/group r,
  owner /etc/ld.so.cache r,
  owner /etc/nsswitch.conf r,
  owner /etc/passwd r,
  owner /etc/shadow r,
  owner /proc/filesystems r,
  owner /proc/sys/kernel/ngroups_max r,
  owner /root/c1 rw,
  owner /usr/bin/id r,
  owner /usr/bin/sleep r,
  owner /usr/bin/unshare r,
  owner /usr/lib/x86_64-linux-gnu/** mr,

  # ---- CAPABILITY ----
  capability sys_admin,

  # ---- NETWORK ----
  network,

  # ---- PTRACE ----
  ## suppress ptrace denials when using 'docker ps' or using 'ps' inside a container
  ptrace (trace,read,tracedby,readby) peer=varmor-cluster-varmor-demo-4,

  # ---- SIGNAL ----
  ## host (privileged) processes may send signals to container processes.
  signal (receive) peer=unconfined,
  ## container processes may send signals amongst themselves.
  signal (send,receive) peer=varmor-cluster-varmor-demo-4,

  # ---- ADDITIONAL ----
  umount,

}

```

您可以使用下面的命令输出 Seccomp profile。

```bash
$ kubectl get ArmorProfileModel -n varmor varmor-cluster-varmor-demo-4 -o jsonpath='{.data.profile.seccompContent}' | jq
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": [
        "open",
        "openat",
        "openat2",
        "close",
        "read",
        "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": [
        "fcntl",
        "epoll_ctl",
        "fstatfs",
        "getdents64",
        "chdir",
        "capget",
        "prctl",
        "mmap",
        "newfstatat",
        "fstat",
        "futex",
        "setgroups",
        "setgid",
        "setuid",
        "getcwd",
        "rt_sigreturn",
        "capset",
        "getppid",
        "faccessat2",
        "getpid",
        "execve",
        "brk",
        "arch_prctl",
        "access",
        "pread64",
        "mprotect",
        "set_tid_address",
        "set_robust_list",
        "rseq",
        "prlimit64",
        "munmap",
        "getuid",
        "getgid",
        "rt_sigaction",
        "geteuid",
        "getrandom",
        "getegid",
        "rt_sigprocmask",
        "vfork",
        "wait4",
        "pause",
        "fadvise64",
        "exit_group",
        "ioctl",
        "sysinfo",
        "uname",
        "socket",
        "connect",
        "lseek",
        "getpgrp",
        "getpeername",
        "unshare",
        "statfs",
        "getgroups",
        "dup2"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

您可能已经注意到，vArmor 生成的 AppArmor profile 中不包含针对 `/root/c0` 文件的读写授权。这是因为在 `demo/demo-4` deployment 中显式地声明了 `container.apparmor.security.beta.varmor.org/c0: unconfined` 注解，这将通知 vArmor 不为其 `c0` 容器设置任何安全策略，也不会对其进行行为建模。
