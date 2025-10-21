---
slug: /guides/policy_advisor
sidebar_position: 3
description: Generate a policy template with policy advisor.
---

# Policy Advisor
This program can help you generate a [`policy`](../getting_started/interface_specification.md#varmorpolicyspec--varmorclusterpolicyspec) template in the **EnhanceProtect** mode with built-in rules. The template can be a good start to craft the final policy. You can provide the context information and the behavior data of the target application to make the template more precise. 

Please use the `-f FEATURES` and `-c CAPABILITIES` arguments to specify the context information. The `-f FEATURES` argument used to describe the application features. The `-c CAPABILITIES` argument used to describe the capabilities required by application explicitly. The behavior data is passed by the `-m BEHAVIOR_DATA` argument. It's an ArmorProfileModel object that is generated with the **[BehaviorModeling mode](policies_and_rules/policy_modes/behavior_modeling.md)**.


## Use cases
Generate a policy template that runs in EnhanceProtect mode with built-in rules supported by AppArmor and BPF enforcers.

`policy-advisor.py AppArmor,BPF -f share-containers-pid-ns -c sys_admin,net_admin,kill`

Filter out the conflicted built-in rules with behavior data to make the policy template more precise.

`policy-advisor.py AppArmor,BPF -f share-containers-pid-ns -c sys_admin,net_admin,kill -m data.json`


## Usage
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
