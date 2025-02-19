# BehaviorModeling 模式

[English](behavior_modeling.md) | 简体中文

## 介绍

BehaviorModeling 模式是一个实验功能。您可以利用 BehaviorModeling 模式在指定时间范围内收集并处理目标工作负载的行为，对其进行行为建模。一旦建模结束，vArmor 会生成一个 [ArmorProfileModel](https://github.com/bytedance/vArmor/blob/main/apis/varmor/v1beta1/armorprofilemodel_types.go) 对象，用来保存目标工作负载的行为模型。

行为模型可以被用于分析哪些内置规则能够被用于加固目标应用，或者指导用户对工作负载的安全上下文进行权限最小化。

当前只有 AppArmor 和 Seccomp enforcer 支持 BehaviorModeling 模式。

## 前置条件

vArmor 当前利用一个内置的 BPF tracer 和 Linux 审计系统来捕获目标应用的行为。

BehaviorModeling 模式的前置条件如下所示：

1. containerd v1.6.0 及以上版本
2. 系统需支持 BTF (BPF Type Format)
3. vArmor 启用了此模式
   * 通过 `--set behaviorModeling.enabled=true` 选项开启 BehaviorModeling 特性。

   * [可选]使用 `--set "agent.args={--auditLogPaths=FILE_PATH|FILE_PATH}"` 选项来指定系统审计日志或搜索顺序。

    ```
    helm upgrade varmor varmor-0.6.3.tgz \
        --namespace varmor --create-namespace \
        --set image.registry="elkeid-cn-beijing.cr.volces.com" \
        --set behaviorModeling.enabled=true
    ```

    
    *注意：* 
    * *vArmor 顺序检查对应的审计日志是否存在，并通过监控第一个有效的文件来获取 AppArmor 和 Seccomp 的审计事件，从而用于违规审计和行为建模功能。当您使用 **auditd** 时，AppArmor 和 Seccomp 的审计事件会默认保存在 `/var/log/audit/audit.log` 文件中。否则，他们通常会被保存在 `/var/log/kern.log` 文件中。*

    * *启用 BehaviorModeling 特性时，**varmor-agent** 需要如下所示的追加资源。另外，**varmor-classifier** 组件也会被部署，用于识别路径中的随机字符串。*

      ```
      resources:
        limits:
          cpu: 2
          memory: 2Gi
        requests:
          cpu: 500m
          memory: 500Mi
      ```

## 示例

### 1. 部署目标工作负载

```yaml
cat << EOF | kubectl create -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-4
  namespace: default
  labels:
    app: demo-4
    // highlight-start
    # This label is required with target workloads. 
    # You can disable the feature with --set 'manager.args={--webhookMatchLabel=}'
    sandbox.varmor.org/enable: "true"
    // highlight-end
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
    // highlight-start
    # This label is required with target workloads. 
    # You can disable the feature with --set 'manager.args={--webhookMatchLabel=}'
    sandbox.varmor.org/enable: "true"
    // highlight-end
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
        // highlight-start
        # Use these annotation to explicitly disable the protection for the container named c0.
        # It always takes precedence over the '.spec.target.containers' field of VarmorPolicy 
        # or VarmorClusterPolicy object.
        container.apparmor.security.beta.varmor.org/c0: unconfined
        container.seccomp.security.beta.varmor.org/c0: unconfined
        // highlight-end
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
    # Switching the mode from BehaviorModeling to others is prohibited, and vice versa.
    # You need recraete the policy to switch the mode from BehaviorModeling to DefenseInDepth.
    # mode: DefenseInDepth
    mode: BehaviorModeling
    modelingOptions:
      // highlight-start
      # 30 minutes
      duration: 30
      // highlight-end
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
$ kubectl get ArmorProfileModel -n varmor varmor-cluster-varmor-demo-4 -o jsonpath='{.data.profile.content}' | base64 -d

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
$ kubectl get ArmorProfileModel -n varmor varmor-cluster-varmor-demo-4 -o jsonpath='{.data.profile.seccompContent}' | base64 -d | jq
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
