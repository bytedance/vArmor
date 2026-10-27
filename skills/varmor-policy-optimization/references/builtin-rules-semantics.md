# Built-in Rule Semantics Reference

Use this reference to understand and validate built-in rules already present in user policies. Each entry lists **purpose** and **disruption risk**; do not infer semantics from names alone
or expand a policy merely because this reference was read. All rule choices must follow user input and confirmation.

Rules fall into three categories. Listed enforcers are the actual enforcement layers (some rules appear in one list but are executed by another
enforcer).

Disruption examples refer to containers actually covered by the policy. `target.containers` selects application containers, excluding initContainers and ephemeralContainers; do not assume those are protected by the same rules.

## Version boundaries

- Catalog `catalogProvenance` records the source material; it does not require an exactly matching cluster version.
- Official `v0.10.1` through `v0.10.5` AppArmor/BPF/Seccomp built-in rule implementation files are identical and considered verified
  compatible. Comparison dates, upstream paths, and per-version-group SHA-256 values are recorded in catalog
  `builtInRuleCompatibility.verificationEvidence`.
- The `v0.10.6` release candidate is also verified identical at the revision recorded in catalog
  `builtInRuleCompatibility.releaseCandidateVerification`. This is candidate verification; recheck the final release tag before claiming tag verification.
- `v0.10.0` lacks only `copy-fail-mitigation`; do not block other built-in rules when the policy does not use it.
- Mark other or unrecognized versions `unknown`; request verification only for built-in rules actually used rather than declaring the entire policy
  incompatible. For NetworkProxy feature and log versions, see
  [violation-log.md](violation-log.md).

## 1. hardeningRules (system hardening)

| Rule | Purpose | Disruption risk | enforcer |
|---|---|---|---|
| disallow-write-core-pattern | Prevent writes to `/proc/sys/kernel/core_pattern` (a common escape path) | Low; rarely needed by ordinary applications | AppArmor/BPF |
| disallow-mount-securityfs | Prevent securityfs mounts | Low; rarely needed by ordinary applications | AppArmor/BPF |
| disallow-mount-procfs | Prevent new procfs mounts/remounts | May affect startup logic or targeted sidecar containers that require mounts | AppArmor/BPF |
| disallow-write-release-agent | Prevent writes to cgroup release_agent | Low; not used by ordinary applications | AppArmor/BPF |
| disallow-mount-cgroupfs | Prevent new cgroupfs mounts/remounts | Affects components that manually mount cgroups | AppArmor/BPF |
| disallow-debug-disk-device | Prevent reads/writes to dynamically identified host disk devices | May affect storage/disk plugins | AppArmor/BPF |
| disallow-mount-disk-device | Prevent host disk-device mounts | Affects storage components | AppArmor/BPF |
| disallow-mount | Prevent mount operations | Affects mount operations in targeted containers; the AppArmor/BPF default baseline already includes mount restrictions when privileged=false | AppArmor/BPF |
| disallow-umount | Prevent umount | Affects components requiring unmounts | AppArmor/BPF |
| disallow-insmod | Disable CAP_SYS_MODULE | Blocks components loading kernel modules, including some network/storage plugins | AppArmor/BPF |
| disallow-load-bpf-prog | Prevent privileged eBPF loading (preserving socket/cgroup types) | Affects eBPF-dependent networking/observability components | AppArmor/BPF |
| disallow-access-procfs-root | Prevent ptrace read (used to access `/proc/<pid>/root`) | Affects debugging, cross-container diagnosis, and sidecars sharing PID namespaces | AppArmor/BPF |
| disallow-access-kallsyms | Prevent reads of `/proc/kallsyms` | Affects performance/diagnostic tools and tracers reading symbols | AppArmor/BPF |
| disallow-abuse-user-ns | Disable CAP_SYS_ADMIN obtained through user namespaces | Affects rootless/sandbox components requiring user namespaces | AppArmor/BPF |
| disallow-create-user-ns | Prevent user namespace creation | Affects rootless/isolation components | **Seccomp** |
| disallow-load-all-bpf-prog | Prevent all eBPF loading | Affects any eBPF-dependent component | **Seccomp** |
| disallow-load-bpf-via-setsockopt | Prevent cBPF loading through setsockopt | Affects components using legacy socket filters | **Seccomp** |
| disallow-userfaultfd-creation | Prevent the userfaultfd syscall | May affect legitimate userspace paging, memory management, or VM migration; an event is not by itself evidence of exploitation | **Seccomp** |

Capability rules (also selected under hardening, AppArmor/BPF):

| Rule | Purpose / risk |
|---|---|
| disable-cap-all | Disable all capabilities, including runtime-default capabilities; operations requiring any capability may be blocked or logged according to observation settings |
| disable-cap-all-except-net-bind-service | Retain only NET_BIND_SERVICE (ports <1024); operations requiring other capabilities trigger logs |
| disable-cap-privileged | Disable the privileged capability set while retaining container-runtime default capabilities |

> `disable-cap-[CAP]` is a **rule-family placeholder, not a rule ID accepted in CRDs**. To disable one capability,
> choose a concrete ID from the catalog capability rule set (such as `disable-cap-net-raw`). Attribute only when that capability audit
> event exists, not from file/mount operations; never write the literal `disable-cap-[CAP]` into a policy.

## 2. attackProtectionRules (attack protection)

| Rule | Purpose | Disruption risk | enforcer |
|---|---|---|---|
| mitigate-sa-leak | Prevent reads of ServiceAccount token/CA/namespace | **Blocks workloads requiring apiserver access, such as operators, client-go, Kubernetes probes, and leader election**; a common disruption | AppArmor/BPF |
| mitigate-disk-device-number-leak | Prevent reads of `/proc/partitions` and mountinfo | Affects `mount`/`df` and libraries reading mountinfo | AppArmor/BPF |
| mitigate-overlayfs-leak | Prevent reads of mounts/mountinfo | Same as above; affects mount commands | AppArmor/BPF |
| mitigate-host-ip-leak | Prevent ARP-table reads | Affects network diagnostics and components reading `/proc/net/arp` | AppArmor/BPF |
| disable-write-etc | Prevent writes to `/etc` | **Blocks applications writing resolv/hosts, configuration, or certificates under `/etc` at runtime**; a common disruption | AppArmor/BPF |
| disable-access-passwd | Prevent reads/writes of `/etc/passwd` | Affects NSS/user management requiring passwd reads | AppArmor/BPF |
| disable-access-shadow | Prevent access to `/etc/shadow` | Generally low | AppArmor/BPF |
| disable-access-ssh-dir | Prevent access to `.ssh` | Affects components requiring SSH/keys | AppArmor/BPF |
| disable-write-skills | Prevent writes to skills directories | Affects applications writing those directories | **AppArmor only** |
| disable-busybox | Prevent busybox execution | **Blocks alpine/busybox images and runtime busybox debugging**; a common disruption | AppArmor/BPF |
| disable-shell | Prevent sh/bash/dash execution | Blocks shell startup scripts and exec shells; symlinks often point to busybox | AppArmor/BPF |
| disable-wget | Prevent wget execution | Blocks startup configuration downloads/health checks using wget | AppArmor/BPF |
| disable-curl | Prevent curl execution | Blocks startup configuration downloads/health checks using curl | AppArmor/BPF |
| disable-chmod | Prevent chmod program execution | Blocks chmod in startup scripts | AppArmor/BPF |
| disable-chmod-x-bit | Prevent setting executable bits | Blocks runtime chmod +x, such as download-and-execute flows | **Seccomp** |
| disable-chmod-s-bit | Prevent setting SUID/SGID | Generally low | **Seccomp** |
| disable-su-sudo | Prevent su/sudo execution | Affects privilege-escalation scripts | AppArmor/BPF |
| disable-network | Prevent all networking | **Blocks every networked service**; most restrictive, suitable only for fully offline computation | AppArmor/BPF |
| disable-inet | Prevent IPv4 | Affects only IPv4; pure IPv6 is unaffected | AppArmor/BPF |
| disable-ipv4 | Prevent IPv4 | Same as above (alias semantics; use catalog IDs) | AppArmor/BPF |
| disable-inet6 | Prevent IPv6 | Affects only IPv6 | AppArmor/BPF |
| disable-ipv6 | Prevent IPv6 | Same as above | AppArmor/BPF |
| disable-unix-domain-socket | Prevent UDS | **Affects applications using UDS extensively for local interprocess communication** | AppArmor/BPF |
| disable-icmp | Prevent ICMP | Affects ping/ICMP health checks | AppArmor/BPF |
| disable-tcp | Prevent TCP | Blocks TCP services | AppArmor/BPF |
| disable-udp | Prevent UDP | Blocks UDP services | AppArmor/BPF |
| block-access-to-kube-apiserver | Prevent kube-apiserver connections | **Blocks workloads requiring apiserver access** | **BPF only** |
| block-access-to-container-runtime | Prevent access to docker/containerd/crio.sock | Affects CI/daemon components requiring container-runtime sockets | AppArmor/BPF |
| block-access-to-metadata-service | Block common cloud metadata IPs | Affects applications retrieving credentials/regions from metadata | **BPF only** |
| block-access-to-aws-metadata-service | Block AWS metadata IP | Affects applications reading AWS metadata | **BPF only** |
| block-access-to-volc-metadata-service | Block Volcengine metadata IP | Affects applications reading Volcengine metadata | **BPF only** |
| block-access-to-alibaba-metadata-service | Block Alibaba Cloud metadata IP | Affects applications reading Alibaba Cloud metadata | **BPF only** |
| block-access-to-oci-metadata-service | Block OCI metadata IP | Affects applications reading OCI metadata | **BPF only** |

Attribution boundaries: `disallow-access-procfs-root` matches only ptrace read; `disable-shell/busybox/curl/wget/chmod`
matches only execution of the corresponding executable, not mere `getattr/open/read`. Do not expand these few explicit boundaries
into an incomplete universal event-signature table; leave cases not determinable from official implementations to the model and retain unmatched results.

## 3. vulMitigationRules (vulnerability mitigation; temporary patches)

| Rule | Purpose | Disruption risk | enforcer |
|---|---|---|---|
| cgroups-lxcfs-escape-mitigation | Prevent writes to cgroup files such as release_agent/devices.allow | Affects components managing cgroups manually | AppArmor/BPF |
| runc-override-mitigation | Prevent writes to `/**/runc` | Generally low | AppArmor/BPF |
| dirty-pipe-mitigation | Prevent splice | Affects zero-copy/forwarding programs using splice extensively | **Seccomp** |
| ingress-nightmare-mitigation | Prevent access to ingress-nginx admission service | Generally low | **BPF only** |
| copy-fail-mitigation | Prevent AF_ALG sockets | Generally low | AppArmor/BPF |

## Usage discipline

- Helping select rules means choosing within user-approved scope based on **whether target behavior needs the protected object**.
  If application impact is uncertain, prefer retaining the rule for observation and checking violation logs rather than deleting immediately.
- Capability rules require capability audit events; do not infer them from file/network operations.
- This table explains rule behavior and possible disruption; it does not replace deterministic rule-ID validation.
