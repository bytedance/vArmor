# Policy Advisor

[English](policy_advisor.md) | 简体中文

*欢迎体验在线版[策略顾问](https://www.varmor.org/zh-cn/policy-advisor)。*

此功能可协助您使用内置策略生成以一个策略模版，您可以基于此模版来构造最终的策略。建议您尽可能多地提供目标工作负载的上下文信息、行为数据，从而使生成的模版更加精准。

请使用 `-f FEATURES` 和 `-c CAPABILITIES` 参数来指定上下文信息。其中，`-f FEATURES` 参数用于显式地描述应用的特性，`-c CAPABILITIES` 参数用于显式地描述应用所需的能力。行为数据则通过 `-m BEHAVIOR_DATA` 参数传递，您可以使用 **[BehaviorModeling 模式](policies_and_rules/policy_modes/behavior_modeling.zh_CN.md)** 为目标应用生成 ArmorProfileModel 然后将其导出。


## 示例

使用内置规则，为需要 sys_admin,net_admin,kill 能力，且共享 PID 命名空间的容器生成策略模版。

`policy-advisor.py AppArmor,BPF -f share-containers-pid-ns -c sys_admin,net_admin,kill`

使用行为数据过滤掉与之冲突的内置规则，从而使策略模版更加精准。

`policy-advisor.py AppArmor,BPF -f share-containers-pid-ns -c sys_admin,net_admin,kill -m data.json`


## 用法

```
policy-advisor.py [-h] [-f FEATURES] [-c CAPABILITIES]
                  [-m BEHAVIOR_DATA] [-d]
                  enforcers

positional arguments:
  enforcers          The enforcers supported by the environment.
                     Available Values: AppArmor, BPF, Seccomp (they should be combined with commas.)
                     For Example: "AppArmor,BPF,Seccomp"

optional arguments:
  -h, --help         show this help message and exit
  -f FEATURES        The features of the target application and its container. Providing as comprehensive features as
                     possible helps generate more precise policy templates.

                     Available Values (they should be combined with commas.):
                       * privileged-container: The target application runs in a privileged container.
                       * mount-sth: The target application needs to execute some mount operations in the container.
                       * umount-sth: The target application needs to execute some umount operations in the container.
                       * share-containers-pid-ns: The target container shares the PID namespace with sidecar containers.
                       * share-host-pid-ns: The target container shares the PID namespace with host.
                       * dind: The target application will create a docker in docker container.
                       * require-sa: The target application needs to interact with API Server.
                       * bind-privileged-socket-port: The target application needs to listen on a socket port less than 1024.
                       * load-bpf: The target application needs to load eBPF programs in the container.
                     For Example: "privileged-container,require-sa,bind-privileged-socket-port"

  -c CAPABILITIES    The capabilities required by the target application and its containers. Providing the capabilities
                     needed for the application explicitly helps generate more precise policy templates. For example,
                     before Linux 5.8, loading BPF programs requires sys_admin capability. Since Linux 5.8, loading BPF
                     programs requires sys_admin or bpf capabilities. If your application needs to load BPF
                     programs, please add both sys_admin and bpf, that is "sys_admin,bpf". See CAPABILITIES(7).

                     Available Values: CAPABILITIES(7) without 'CAP_' prefix (they should be combined with commas).
                     For Example: "sys_admin,net_admin,sys_module"

  -m BEHAVIOR_DATA   The behavior data is a JSON file that includes an ArmorProfileModel object.
                     You can export the behavior data with kubectl command, such as: 
                     kubectl get ArmorProfileModel -n {NAMESPACE} {NAME} -o json > data.json

  -d                 Print debug information.
```