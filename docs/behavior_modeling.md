# The BehaviorModeling Mode [Experimental]

## Introduction
The **BehaviorModeling** and **DefenseInDepth** modes are experimental features. You can utilize the **BehaviorModeling** mode to gather behavior data of the target workloads over a specified duration. Once the modeling is completed, vArmor will generate an `ArmorProfileModel` object to store the model of the target workloads. vArmor currently leverages a built-in BPF tracer and the logging system (currently rsyslog) to capture application behavior.

Subsequently, you can create a policy with the **DefenseInDepth** mode to harden the target workload. vArmor will employ the model stored in the `ArmorProfileModel` object to enforce mandatory access control on the target. The model generated by the **BehaviorModeling** mode can also be used to analyze which built-in rules can be applied to harden the target application.

## Requirements
* BTF (BPF Type Format) must be enabled. 
* rsyslog must be enabled, and auditd must be disabled. 
* Execute the following commands on each node of cluster to setting rsyslog.
    ```
    cat >/etc/rsyslog.d/varmor.conf<<EOF
    \$ModLoad omuxsock
    \$OMUxSockSocket /var/run/varmor/audit/omuxsock.sock

    kern.* :omuxsock:;
    EOF
    ```
    ```
    systemctl restart rsyslog.service
    ```
* Enable the **BehaviorModeling** feature with `--set behaviorModeling.enabled=true`
    
    *Note: The BehaviorModeling feature in vArmor agent requires additional resources.*
    ```
    resources:
      limits:
        cpu: 2
        memory: 2Gi
      requests:
        cpu: 500m
        memory: 500Mi
    ```

