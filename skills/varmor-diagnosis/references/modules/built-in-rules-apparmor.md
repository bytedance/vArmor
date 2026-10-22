# AppArmor built-in rule implementation

This guide maps the AppArmor implementation of the vArmor v0.9.2 EnhanceProtect reference rule set; deployed versions may add rules. Declaring a rule does not prove enforcement: verify AppArmor is enabled, the Profile is generated and loaded, and the Pod references it.

Correlate AppArmor audit profile, operation, name/path, denied_mask, and action with AP and node-agent load status. `allowViolations/auditViolations` affect denial/auditing, not which enforcer implements a rule.

## 1. AppArmor rule mapping

| Rule category | Rule IDs | Implementation |
|---|---|---|
| Privileged escape and mounts | `disallow-write-core-pattern` | Denies writes to `/proc/sys/kernel/core_pattern`. |
| Privileged escape and mounts | `disallow-mount-securityfs`, `disallow-mount-procfs`, `disallow-mount-cgroupfs`, `disallow-mount`, `disallow-umount` | Restricts the corresponding filesystem/mount operations; `procfs/cgroupfs` also restrict dangerous bind/rbind/move/remount combinations. |
| Privileged escape and mounts | `disallow-write-release-agent`, `disallow-debug-disk-device`, `disallow-mount-disk-device` | Restricts cgroup `release_agent` writes, reads/writes to dynamically identified disk devices, and mounting those devices, respectively. |
| Capabilities and kernel attack surface | `disallow-insmod`, `disallow-load-bpf-prog`, `disallow-abuse-user-ns` | Restricts `CAP_SYS_MODULE`, `CAP_SYS_ADMIN`/`CAP_BPF`, and `CAP_SYS_ADMIN`, respectively. |
| Capabilities and kernel attack surface | `disable-cap-all`, `disable-cap-all-except-net-bind-service`, `disable-cap-privileged`, `disable-cap-*` | Generates capability restrictions; in `disable-cap-*`, `*` is a concrete capability name, such as `disable-cap-net-raw`. |
| Proc/ptrace | `disallow-access-procfs-root`, `disallow-access-kallsyms` | Restricts ptrace read and `/proc/kallsyms` reads, respectively. |
| Information disclosure | `mitigate-sa-leak`, `mitigate-disk-device-number-leak`, `mitigate-overlayfs-leak`, `mitigate-host-ip-leak` | Restricts reads of ServiceAccount files, `partitions/mountinfo`, `mounts/mountinfo`, and `/proc/*/net/arp`, respectively. |
| Files and commands | `disable-write-etc` | Restricts writes to `/etc`. |
| Files and commands | `disable-busybox`, `disable-shell`, `disable-wget`, `disable-curl`, `disable-chmod`, `disable-su-sudo` | Restricts the corresponding executables; `shell` covers sh/bash/dash. Actual symlink and BusyBox applet paths in the image affect matching. |
| Network and runtime | `disable-network`, `disable-inet`/`disable-ipv4`, `disable-inet6`/`disable-ipv6`, `disable-unix-domain-socket`, `disable-icmp`, `disable-tcp`, `disable-udp` | Restricts AppArmor network families, types, or protocols. |
| Network and runtime | `block-access-to-container-runtime` | Restricts reads/writes to containerd, Docker, and CRI-O sockets. |
| Vulnerability mitigation | `cgroups-lxcfs-escape-mitigation`, `runc-override-mitigation` | Restricts writes to critical cgroup files and `runc`, respectively. |

## 2. Rules not implemented by AppArmor

`disallow-create-user-ns`, `disallow-load-all-bpf-prog`, `disallow-load-bpf-via-setsockopt`, `disallow-userfaultfd-creation`, `dirty-pipe-mitigation`, `disable-chmod-x-bit`, and `disable-chmod-s-bit` are not implemented by AppArmor built-in rules; inspect the Seccomp Profile.

Only AppArmor supports `attackProtectionRules.targets`: it creates child profiles for the specified executables. Verify the parent-to-child execution transition and actual executable path.
