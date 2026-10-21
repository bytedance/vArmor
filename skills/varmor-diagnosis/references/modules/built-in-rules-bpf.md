# BPF built-in rule implementation

This guide maps the BPF implementation of the vArmor v0.9.2 EnhanceProtect reference rule set; deployed versions may add rules. Declaring a rule does not prove enforcement: verify the BPF enforcer, node capabilities such as BPF LSM/BTF, Profile load/attach, and target-node processing results.

Correlate agent load/attach logs, BPF audit, AP file/process/network/mount rules, and node kernel capabilities. `allowViolations/auditViolations` affect denial/auditing, not which enforcer implements a rule.

## 1. BPF rule mapping

| Rule category | Rule IDs | Implementation |
|---|---|---|
| Privileged escape and mounts | `disallow-write-core-pattern`, `disallow-write-release-agent` | Restricts core_pattern and release_agent writes, respectively. |
| Privileged escape and mounts | `disallow-mount-securityfs`, `disallow-mount-procfs`, `disallow-mount-cgroupfs`, `disallow-mount-disk-device`, `disallow-mount`, `disallow-umount` | Generates BPF mount restrictions. Additional new-mount restrictions are usually needed only with `enhanceProtect.privileged=true`; proc/cgroup also restrict dangerous remounts/unmounts. |
| Privileged escape and mounts | `disallow-debug-disk-device` | Restricts reads/writes to dynamically identified disk devices. |
| Capabilities and kernel attack surface | `disallow-insmod`, `disallow-load-bpf-prog`, `disallow-abuse-user-ns` | Restricts `CAP_SYS_MODULE`, `CAP_SYS_ADMIN`/`CAP_BPF`, and `CAP_SYS_ADMIN`, respectively. |
| Capabilities and kernel attack surface | `disable-cap-all`, `disable-cap-all-except-net-bind-service`, `disable-cap-privileged`, `disable-cap-*` | Generates capability-bitmap restrictions. |
| Proc/ptrace | `disallow-access-procfs-root`, `disallow-access-kallsyms` | Restricts ptrace read and `/proc/kallsyms` reads, respectively. |
| Information disclosure | `mitigate-sa-leak`, `mitigate-disk-device-number-leak`, `mitigate-overlayfs-leak`, `mitigate-host-ip-leak` | Implemented through BPF file-path rules. |
| Information disclosure | `disallow-access-k8s-sensitive-files` | Restricts reads of Kubernetes configuration, `~/.kube/config`, and Secret-volume paths. The current optimization task form does not offer this rule, but recognize it when diagnosing existing policies. |
| Metadata network | `block-access-to-metadata-service`, `block-access-to-aws-metadata-service`, `block-access-to-volc-metadata-service`, `block-access-to-alibaba-metadata-service`, `block-access-to-oci-metadata-service` | Generates connect restrictions to the corresponding metadata IPs. |
| Files and commands | `disable-write-etc` | Generates BPF file read/write restrictions. |
| Files and commands | `disable-busybox`, `disable-shell`, `disable-wget`, `disable-curl`, `disable-chmod`, `disable-su-sudo` | Restricts execution at corresponding paths; `shell` covers sh/bash/dash. |
| Network and runtime | `disable-network`, `disable-inet`/`disable-ipv4`, `disable-inet6`/`disable-ipv6`, `disable-unix-domain-socket`, `disable-icmp`, `disable-tcp`, `disable-udp` | Generates socket-create or protocol restrictions. |
| Network and runtime | `block-access-to-kube-apiserver`, `ingress-nightmare-mitigation` | Requires service egress control and Kubernetes Service/Endpoint resolution. If the Service is absent or capability disabled, inspect generation logs and AP content. |
| Network and runtime | `block-access-to-container-runtime` | Restricts reads/writes to containerd, Docker, and CRI-O sockets. |
| Vulnerability mitigation | `cgroups-lxcfs-escape-mitigation`, `runc-override-mitigation` | Restricts writes to critical cgroup files and `runc`, respectively. |

## 2. Rules not implemented by BPF

The current BPF generator has no equivalent hook implementation for `disallow-create-user-ns`, `disallow-load-all-bpf-prog`, `disallow-load-bpf-via-setsockopt`, `disallow-userfaultfd-creation`, `dirty-pipe-mitigation`, `disable-chmod-x-bit`, or `disable-chmod-s-bit`; inspect the Seccomp Profile.

Built-in rules with `attackProtectionRules.targets` do not generate BPF restrictions. Executable-specific restrictions are implemented only by AppArmor child profiles.
