---
name: varmor-vuln-policy-generator-en
description: "vArmor Vulnerability Mitigation Policy Generator. Use this skill when a user provides 0day/Nday vulnerability information (CVE IDs, PoC/Exp code, vulnerability analysis articles, GitHub repos, etc.) and asks to: (1) analyze whether the vulnerability can be exploited in container environments or used for container escape, (2) generate vArmor mitigation policies, (3) evaluate whether vArmor can defend against the vulnerability. Applicable to any security vulnerability mitigation policy generation scenario, including but not limited to: Linux kernel vulnerabilities (LPE/container escape), application-layer vulnerabilities (RCE/information leakage/cluster takeover, e.g., IngressNightmare), supply chain vulnerabilities, middleware vulnerabilities, etc. Even if the user doesn't explicitly mention vArmor, this skill should be triggered whenever the request involves container security hardening, vulnerability mitigation policy, or runtime protection rule generation."
---

# vArmor Vulnerability Mitigation Policy Generator

## Overview

This skill rapidly accomplishes the following when a new vulnerability (0day/Nday) emerges:
1. In-depth analysis of the vulnerability's root cause and exploitation techniques
2. Assessment of vulnerability exploitation scenarios (container escape, in-container RCE, cluster takeover, information leakage, etc.)
3. Generation of vArmor mitigation policy templates
4. Evaluation of potential business impact with multiple options for user selection

## Applicable Vulnerability Types

This skill covers the following vulnerability types:

| Vulnerability Type | Typical Cases | vArmor Defense Dimension |
|-------------------|---------------|--------------------------|
| Kernel LPE → Container Escape | Dirty Pipe, Copy Fail, Dirty Frag | Syscall restriction, socket protocol family restriction, namespace restriction |
| Application RCE → Cluster Takeover | IngressNightmare (CVE-2025-1974) | Network access control (restrict access to sensitive Services/ports) |
| Container Runtime Escape | CVE-2019-5736 (runc) | File write restriction |
| Application Arbitrary File R/W | Various web app vulnerabilities | File access control |
| Info Leakage / Credential Theft | ServiceAccount token abuse | File read restriction, network egress restriction |
| Supply Chain / Dependency Vulns | Log4Shell etc. | Network egress restriction, process execution restriction |

## Workflow

Execute the following steps in order — none may be skipped:

### Step 1: Information Gathering and Analysis

1. **Collect user-provided vulnerability information**: CVE IDs, PoC/Exp code, vulnerability analysis articles, GitHub repository links, technical blogs, etc.

2. **Proactively search for supplementary information**: Use search tools and web fetching to gather additional vulnerability details, including but not limited to:
   - Affected software version range (kernel versions, application versions, etc.)
   - Prerequisites for exploitation (required syscalls, kernel modules, privileges, network access)
   - Critical path of exploitation (every key step in the trigger chain)
   - Existing mitigation solutions and patch status
   - Whether multiple exploit variants exist

3. **In-depth root cause analysis**, focusing on different aspects by vulnerability type:

   **Kernel vulnerabilities** focus on:
   - System call sequence required to trigger the vulnerability
   - Involved kernel subsystems and modules
   - Minimum privilege set required by the attacker
   - Whether a race condition is required
   - Write/modify primitive capabilities (arbitrary write, limited write, conditional write)

   **Application-layer vulnerabilities** focus on:
   - Network access required to trigger the vulnerability (which Services, ports, protocols)
   - What operations can be performed after exploitation (RCE, arbitrary file R/W, info leakage)
   - Role and permissions of affected containers/Pods (sensitive RBAC permissions, host path mounts)
   - Attacker's initial position (in-cluster Pod, external network, adjacent namespace)

### Step 2: Vulnerability Exploitation Scenario Assessment

Analyze the vulnerability's exploitability and threat model in container/Kubernetes environments. Select the corresponding analysis framework based on vulnerability type:

#### A. Kernel Vulnerability → Container Escape Assessment

1. **Page-cache class vulnerabilities** (e.g., Dirty Pipe, Copy Fail, Dirty Frag):
   - Page cache is shared host-wide
   - Container image layers (overlay fs) share page-cache pages across containers
   - Privileged DaemonSets may execute corrupted binaries

2. **Namespace/cgroup escape class vulnerabilities**:
   - Whether the container's namespace isolation can be bypassed
   - Cgroup-related escape paths

3. **Kernel object out-of-bounds access class vulnerabilities**:
   - Whether kernel objects can be accessed across namespaces
   - Whether the host filesystem can be modified

#### B. Application-Layer Vulnerability → In-Container Exploitation / Cluster Takeover Assessment

1. **RCE class vulnerabilities** (e.g., IngressNightmare):
   - Whether attackers can trigger the vulnerability from the network (which Service/port needs to be accessed)
   - Container permissions of affected components (RBAC roles, mounted Secrets, network permissions)
   - Impact scope after successful exploitation (single container RCE → read Secrets → cluster takeover)

2. **Information leakage class vulnerabilities**:
   - Whether ServiceAccount tokens, credentials in environment variables can be read
   - Whether internal cluster APIs can be accessed

3. **Supply chain / dependency vulnerabilities** (e.g., Log4Shell):
   - Whether external network connections can be initiated (reverse shell, payload download)
   - Whether unexpected binaries can be executed

#### C. Container Runtime Vulnerabilities

1. **Container escape class** (e.g., CVE-2019-5736 runc override):
   - Whether the host's runtime binary can be overwritten
   - Whether specific container configuration is required

#### Assessment Conclusion

The assessment conclusion must clearly state:
- **Threat type**: Container escape / In-container RCE / Cluster takeover / Information leakage / Lateral movement
- Specific attack path and prerequisites
- Impact scope (which K8s environments/workloads are affected)

#### Per-Variant In-Container Exploitability Rating

For vulnerabilities with multiple variants or exploit paths, each variant **must** be individually assessed for practical exploitability in container environments — do not treat them equally. Assessment dimensions:

1. **Prerequisite satisfiability**: Are the variant's prerequisites met by default in typical container environments?
   - Is the required kernel module loaded by default? Can unprivileged users trigger autoload?
   - Is the required kernel config the default in mainstream distributions?
   - Are additional privileges/capabilities required? Does the container have them by default?
   - Are there dependencies on specific filesystem mounts, device access, etc.?

2. **Exploitation stability and cost**:
   - Deterministic exploitation (success guaranteed on every trigger) vs probabilistic (requires brute-force/race condition)
   - If brute-force is needed, how large is the search space? What's the expected number of attempts?
   - Are there timing window constraints or specific sequencing requirements?
   - Does the exploitation produce noticeable system anomalies (crashes, log noise)?

3. **Practicality conclusion** (tiered):
   - **High**: Prerequisites met by default, deterministic exploitation, directly usable for container escape/attack
   - **Medium**: Prerequisites partially met or some brute-forcing needed, feasible in practice but at higher cost
   - **Low**: Prerequisites are demanding or brute-force space is enormous, exploitable only under special configurations
   - **Theoretical only**: Exploit chain is practically infeasible in real container environments, but the theoretical path exists

4. **Defense priority recommendation**: Combined assessment of practicality + defense cost
   - High practicality → Must defend
   - Medium/Low practicality but zero defense cost (no business impact) → Recommended ("free insurance")
   - Low practicality and defense has business impact → Optional, user decides based on security requirements

Example (Dirty Frag):
| Variant | Prerequisite Satisfiability | Exploitation Stability | Practicality | Defense Priority |
|---------|---------------------------|----------------------|--------------|-----------------|
| ESP | High (unprivileged user ns available by default) | Deterministic 4-byte controlled write | **High** | Must defend |
| RxRPC | Low (depends on af_rxrpc.ko module being loaded, may autoload) | Requires brute-force, shellcode injection theoretically N×2^56 attempts | **Low** | Recommended (blocking AF_RXRPC has zero business impact) |

### Step 3: Read vArmor Documentation

**Must** retrieve the latest vArmor policy syntax and rule information from the following links:

1. **Policy API Type Definitions** (precise field structures and types — must reference when writing custom rules):
   - Top-level policy structure + EnhanceProtect definition: https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/common.go
   - BPF rule definitions (file rules, network rules, process rules, mount rules, etc.): https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/bpf.go
   - AppArmor rule definitions: https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/apparmor.go
   - Seccomp rule definitions: https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/seccomp.go

   These Go type definition files are the authoritative reference for policy YAML. Each field has comments explaining its meaning, available values, and mutual exclusivity. **When writing custom rules, you must strictly follow the field names and structural hierarchy defined in these types — never fabricate fields.**

2. **Built-in Rules** (prefer built-in rules to avoid reinventing the wheel):
   - Container Hardening: https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/hardening
   - Attack Protection: https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/attack_protection
   - Vulnerability Mitigation: https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/vulnerability_mitigation

3. **Custom Rule Writing Guide**:
   - vArmor Custom Rules documentation: https://www.varmor.org/docs/v0.10/guides/policies_and_rules/custom_rules
   - AppArmor Syntax Reference: https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html
   (Always consult the syntax documentation when writing AppArmor custom rules to ensure correctness)

### Step 4: Exploit Path and Defense Point Analysis

This is the core step for policy design — analyzing each exploit path step by step.

#### 4.1 Map Exploit Paths

For each variant/exploit path, list the complete step chain from the attacker's initial state to successful exploitation. For example:

```
Variant A exploit path:
  Step 1: Create XX socket → Step 2: Call splice() → Step 3: Trigger kernel path → Step 4: Page-cache write
  
Variant B exploit path:
  Step 1: unshare(USER) → Step 2: Register SA → Step 3: splice() → Step 4: Page-cache write
```

#### 4.2 Identify Defense Points on Each Path

For each step on each exploit path, analyze blockability from the following dimensions:

**Syscall dimension** (Seccomp enforcer):
- Whether specific syscalls can be blocked (e.g., splice, unshare)
- Whether argument filtering can be used for precise matching (e.g., socket's domain argument)

**Network protocol / socket dimension** (AppArmor/BPF enforcer):
- Whether specific protocol family socket creation can be blocked (AF_ALG, AF_RXRPC, etc.)
- Whether access to specific Services/IPs/ports can be restricted (BPF enforcer egress rules)

**File access dimension** (AppArmor/BPF enforcer):
- Whether read/write access to specific files/paths can be restricted (e.g., deny write to /**/runc)
- Whether the scope of executable files can be restricted

**Process execution dimension** (AppArmor/BPF enforcer):
- Whether executable binaries within containers can be restricted
- Whether specific process network behavior can be blocked

For each possible blocking point, analyze:
- **Can it be blocked by vArmor** (which enforcer can block it)
- **Advantages of blocking this step**: Is it precise? Is the operation unique to the exploit?
- **Disadvantages/risks of blocking this step**: Will it impact normal business? Can it be bypassed?
- **Impact scope assessment**: Which normal applications use this syscall/interface/network path?

#### 4.3 Select Optimal Defense Points

Selection principles (in priority order):
1. **Precision**: Prefer operations unique to the exploit (e.g., specific protocol family sockets) over generic operations (e.g., read/write)
2. **Non-bypassable**: Prefer steps in the exploit chain that cannot be substituted
3. **Minimal impact**: Prefer blocking points with the least impact on normal business
4. **Coverage**: If a single rule can block multiple variants without business impact, prefer it

### Step 5: Policy Design and Multi-Option Output

Based on Step 4 analysis, design multiple tiers of mitigation options:

#### Option Tiering Principles

- **Option 1: Minimal Impact**
  - Block only vulnerability-specific exploit vectors that don't affect normal business
  - Must cover all variants (each variant has at least one blocking point covered)
  - If all blocking points for a variant would impact business, note that this variant is not covered by this option

- **Option 2: Enhanced Protection**
  - Add defense-in-depth rules on top of Option 1
  - May affect a small number of special applications, but provides more comprehensive protection for most workloads
  - Each variant should have redundant defense points

- **Option 3: Maximum Protection** (only provide when needed)
  - Strictest restrictions, may impact some business operations
  - Suitable for high-security environments (multi-tenant clusters, environments running untrusted code)
  - Must clearly label affected application types

If a single rule can cover all variants with no business impact, it can be consolidated into a single option with explanation.

### Step 6: Generate Policy Template

#### Output Format Requirements

Output must contain two parts: **Vulnerability Analysis Report** and **Policy Templates**.

#### Vulnerability Analysis Report Format

```markdown
## Vulnerability Analysis Report

### Vulnerability Overview
- CVE ID / Vulnerability Name
- Affected scope (kernel versions, distributions)
- Vulnerability type and severity
- Patch status

### Root Cause Analysis (describe each variant separately)

#### Variant X: <variant name>
- Root cause (including critical code paths)
- Exploitation technique
- Required prerequisites (privileges, kernel modules, syscalls)
- Write primitive capabilities (write size, location controllability, value controllability)

### Exploit Path and Defense Point Analysis

#### Variant X Exploit Path
| Step | Operation | Involved Syscalls/Interfaces | Can vArmor Block | Enforcer | Blocking Advantages | Blocking Disadvantages/Risks | Business Impact |
|------|-----------|------------------------------|-----------------|----------|--------------------|-----------------------------|----------------|

### Container Escape Assessment
- Conclusion: Whether it can be used for container escape
- Escape path description
- Prerequisites
- Affected K8s environments

### Per-Variant In-Container Exploitability Rating
| Variant | Prerequisite Satisfiability | Exploitation Stability | Practicality (High/Medium/Low/Theoretical) | Defense Priority |
|---------|---------------------------|----------------------|-------------------------------------------|-----------------|

### Mitigation Feasibility Summary
- Can vArmor mitigate: Yes / No / Partially
- Recommended defense point selection with rationale
- Explanation of cases that cannot be blocked (if any)
```

#### Policy Template Format

Policy templates are organized as follows, listing rules for each exploit variant/vector separately, categorized by enforcer type:

```yaml
# ============================================================
# Option 1: Minimal Impact
# Covered variants: <list covered variants>
# Overall impact: <one-line summary>
# ============================================================
policy:
  enforcer: <AppArmor|BPF|Seccomp or combination, e.g., AppArmorBPFSeccomp>
  mode: EnhanceProtect
  enhanceProtect:
    # --- Block <vulnerability name> <variant name> exploit vector ---
    # Blocking mechanism: <which step in the exploit chain is blocked, and why it works>
    # Potential impact: <possible business impact, specific to affected application types>
    # Impact level: <no impact / very few apps affected / some apps affected>
    
    hardeningRules:
      # For AppArmor/BPF enforcer
      <built-in rule name>
      # For Seccomp enforcer
      <built-in rule name>

    # For AppArmor enforcer
    appArmorRawRules:
    - rules: |
        <AppArmor rule>,

    # For BPF enforcer
    bpfRawRules:
      <BPF rule structure>

    # For Seccomp enforcer
    syscallRawRules:
    - names:
      - <syscall name>
      action: SCMP_ACT_ERRNO
      args:
      - index: <argument index>
        value: <argument value>
        op: <comparison operator>

# ============================================================
# Option 2: Enhanced Protection
# Additional rules on top of Option 1: <overview>
# Additional impact: <one-line summary of new impact>
# ============================================================
# ... (same format as above)
```

#### Policy Template Supplementary Notes

Every policy option must include:

1. **Coverage statement**: Which variants this option covers, whether any variants are uncovered
2. **Rule explanation**: Blocking mechanism for each rule (as comments), specifying which step in the exploit chain is blocked
3. **Potential impact assessment** (evaluate each rule individually):
   - What normal operations this rule may affect
   - What types of containerized applications may be impacted
   - Impact severity (no impact / very few apps affected / some apps affected / many apps affected)
   - Symptoms when affected (process errors, feature degradation, or complete unavailability)
4. **Option selection guidance**: Help users choose the appropriate option based on their environment
5. **Usage reminder**: Remind users to select rules corresponding to their actual enforcer deployment, not use all of them

### Step 7: Alternative Mitigation Recommendations

Regardless of whether vArmor can mitigate, provide additional mitigation recommendations (as supplements or alternatives):

- **Kernel level**: Patch upgrade recommendations, kernel module disabling (modprobe blacklist), kernel boot parameter adjustments
- **Kubernetes level**: Pod scheduling policies, image layer isolation, privileged DaemonSet least-privilege hardening
- **Network level**: Network policy restrictions
- **Other tools**: Complementary use of other runtime security tools

If vArmor cannot effectively mitigate (e.g., the syscall that needs to be blocked is essential for most containers), emphasize the importance of these alternative approaches.

## Reference Cases

### Case 1: Copy Fail (CVE-2026-31431)

**Vulnerability characteristics**: 4-byte arbitrary page-cache write via AF_ALG socket + splice().

**Exploit path analysis**:
```
Step 1: socket(AF_ALG) → Create AEAD socket
Step 2: bind() → Bind authencesn algorithm
Step 3: splice(file → pipe → AF_ALG socket) → Pin page-cache page
Step 4: recv() → Trigger in-place crypto 4-byte STORE
```

**Defense point selection**:
| Step | Blocking Method | Advantages | Disadvantages | Business Impact |
|------|----------------|------------|---------------|----------------|
| Step 1: socket(AF_ALG) | Block AF_ALG socket | Precise, exploit-specific | None | Most containers unaffected |
| Step 3: splice() | Disable splice | Complete block | Affects nginx/kafka etc. | Many apps affected |

**Optimal choice**: Block AF_ALG socket (precise, no impact)

**Policy**:
```yaml
policy:
  enforcer: AppArmorBPF
  mode: EnhanceProtect
  enhanceProtect:
    # Block AF_ALG socket creation (AF_ALG: userspace interface to kernel crypto API)
    # Blocking mechanism: Copy Fail relies on AF_ALG AEAD socket to trigger in-place crypto write
    # Potential impact: Most containerized apps don't use AF_ALG, typically no impact
    # Impact level: No impact (only very rare apps with explicit afalg engine in OpenSSL affected)
    # For AppArmor enforcer
    appArmorRawRules:
    - rules: |
        audit deny network alg,
    # For BPF enforcer
    bpfRawRules:
      network:
        sockets:
        - qualifiers: ["audit", "deny"]
          domains: ["alg"]
```

vArmor later added the built-in rule `copy-fail-mitigation`, which can be used directly:
```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    vulMitigationRules:
    - copy-fail-mitigation
```

### Case 2: Dirty Frag

**Vulnerability characteristics**: Two variants — ESP variant requires user namespace (CAP_NET_ADMIN), RxRPC variant requires AF_RXRPC socket.

**Exploit path analysis**:

ESP variant:
```
Step 1: unshare(CLONE_NEWUSER|CLONE_NEWNET) → Obtain CAP_NET_ADMIN
Step 2: XFRM_MSG_NEWSA via netlink → Register SA (controls seq_hi value)
Step 3: splice(file → pipe → UDP socket) → Pin page-cache page into skb frag
Step 4: loopback → udp_rcv → xfrm_input → esp_input → skip_cow → 4-byte STORE
```

RxRPC variant:
```
Step 1: socket(AF_RXRPC) → Create RxRPC socket
Step 2: add_key("rxrpc", ...) → Register token with session_key
Step 3: RxRPC handshake + splice(file → pipe → UDP server → client)
Step 4: rxkad_verify_packet_1 → in-place pcbc(fcrypt) decrypt → 8-byte STORE
```

**Defense point selection**:
| Variant | Step | Blocking Method | Advantages | Disadvantages | Business Impact |
|---------|------|----------------|------------|---------------|----------------|
| ESP | Step 1 | Block unshare user ns | Precise, cuts off privilege source | Very few apps need this | Very few affected |
| ESP | Step 3 | Disable splice | Complete block | Large impact | Many apps affected |
| RxRPC | Step 1 | Block AF_RXRPC | Precise, exploit-specific | None | No impact |
| RxRPC | Step 2 | Restrict add_key | May false positive | Keyring ops are common | Some apps affected |

**Policy**:
```yaml
# ============================================================
# Option 1: Minimal Impact
# Covered variants: ESP + RxRPC (all covered)
# Overall impact: Most containers unaffected
# ============================================================
policy:
  enforcer: AppArmorBPFSeccomp
  mode: EnhanceProtect
  enhanceProtect:
    # --- Block Dirty Frag ESP variant exploit vector ---
    # Blocking mechanism: ESP variant requires unshare(CLONE_NEWUSER) to obtain CAP_NET_ADMIN for XFRM SA registration
    # Potential impact: Very few apps that need to create user namespaces inside containers (some test frameworks, nested container runtimes)
    # Impact level: Very few apps affected
    hardeningRules:
      # For AppArmor/BPF enforcer
      disallow-abuse-user-ns
      # For Seccomp enforcer
      disallow-create-user-ns

    # --- Block Dirty Frag RxRPC variant exploit vector ---
    # Blocking mechanism: RxRPC variant needs AF_RXRPC socket to establish connection and trigger in-place decrypt in rxkad_verify_packet_1
    # Potential impact: Most containerized apps don't use AF_RXRPC (Andrew File System dedicated protocol), typically no impact
    # Impact level: No impact
    # For AppArmor enforcer
    appArmorRawRules:
    - rules: |
        audit deny network rxrpc,
    # For BPF enforcer
    bpfRawRules:
      network:
        sockets:
        - qualifiers: ["audit", "deny"]
          domains: ["rxrpc"]
    # For Seccomp enforcer
    syscallRawRules:
    - names:
      - socket
      action: SCMP_ACT_ERRNO
      args:
      - index: 0
        value: 33
        op: SCMP_CMP_EQ
```

### Case 3: IngressNightmare (CVE-2025-1974)

**Vulnerability characteristics**: Unauthenticated RCE in the ingress-nginx admission controller. An attacker from any Pod within the cluster can remotely execute code, obtain all cluster Secrets, and take over the cluster.

**Vulnerability type**: Application-layer RCE → Cluster Takeover

**Exploit path analysis**:
```
Step 1: Attacker obtains a Pod in the cluster (any namespace)
Step 2: Access ingress-nginx-controller-admission Service from Pod network (port 443)
Step 3: Send malicious AdmissionReview request, injecting nginx configuration directives
Step 4: Trigger nginx reload, exploiting injected config to execute arbitrary code
Step 5: Obtain RCE within the ingress-nginx controller Pod
Step 6: Read mounted ServiceAccount token and cluster Secrets → Cluster takeover
```

**Defense point selection**:
| Step | Blocking Method | Advantages | Disadvantages | Business Impact |
|------|----------------|------------|---------------|----------------|
| Step 2: Network access to admission Service | BPF enforcer restricts access to admission Service/port | Precisely blocks attack entry point | Only BPF enforcer supports this | Normal Ingress creation unaffected (initiated by API Server, not through Pod network) |
| Step 4: nginx reload | Restrict nginx process execution | May affect normal operation | Would break ingress functionality | Severe impact |
| Step 6: Read Secret files | Restrict file reads | Defense in depth | Doesn't prevent RCE itself | May affect normal functionality |

**Optimal choice**: Block Pod network access to ingress-nginx-controller-admission Service (precise, doesn't affect normal traffic)

**Policy**:
```yaml
# Using vArmor built-in rule (recommended)
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    vulMitigationRules:
    - ingress-nightmare-mitigation
```

**Built-in rule description**:
- The `ingress-nightmare-mitigation` rule prohibits container processes from accessing the ingress-nginx-controller-admission Service and its endpoints in the ingress-nginx and kube-system namespaces
- Only BPF enforcer is supported (requires network access control capabilities)
- If ingress-nginx is deployed in other namespaces, custom rules are needed

**Custom rule example** (when ingress-nginx is deployed in a custom namespace):
```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    # Blocking mechanism: Block Pod network from directly accessing ingress-nginx admission webhook Service
    # Potential impact: Normal Ingress resource creation/updates are unaffected (kube-apiserver initiates admission webhook calls)
    # Impact level: No impact (only blocks Pods from directly accessing admission Service, does not affect normal Ingress traffic)
    bpfRawRules:
      network:
        egress:
          toServices:
          - qualifiers: ["audit", "deny"]
            namespace: "custom-namespace"
            name: ingress-nginx-controller-admission
```

**Key notes**:
- This vulnerability is NOT a container escape, but achieves cluster takeover via network RCE
- vArmor's defense approach is to cut off the attack network path, rather than restricting syscalls
- This demonstrates the unique advantage of the BPF enforcer in network access control

## Deployment Guidance: Observe Mode and Enforce Mode

After generating the policy template, recommend users follow a phased rollout to avoid impacting business. Users should decide on a case-by-case basis whether an observe phase is needed and how long to observe — for rules with confirmed zero business impact (e.g., blocking AF_RXRPC), they can go straight to enforce mode; for rules that may affect some applications, an observation period is recommended before switching:

### Phase 1: Observe Mode (verify rules don't conflict with business)

Deploy in observe mode first — only log violations without actually blocking:

- **Built-in rules**: Enable both `auditViolations: true` and `allowViolations: true` so rules only audit without blocking

```yaml
policy:
  enforcer: AppArmorBPF
  mode: EnhanceProtect
  enhanceProtect:
    auditViolations: true
    allowViolations: true
    hardeningRules:
      - disallow-abuse-user-ns
```

- **Custom rules (AppArmor enforcer)**: Use only `audit` qualifier (without `deny`) — log only, no blocking

```yaml
appArmorRawRules:
- rules: |
    audit network rxrpc,
```

- **Custom rules (BPF enforcer)**: Use only `audit` qualifier (without `deny`) — log only, no blocking

```yaml
bpfRawRules:
  network:
    sockets:
    - qualifiers: ["audit"]
      domains: ["rxrpc"]
```

- **Custom rules (Seccomp enforcer)**: Seccomp does not support observe-only mode (no audit-only action). It can only block directly. Recommend validating in a staging environment before production deployment.

During the observation period, check `/var/log/varmor/violations.log` for any business-triggered violation records.

### Phase 2: Enforce & Audit Mode (switch after confirming no conflicts)

After confirming no business conflicts during the observation period, switch to enforcement mode:

- **Built-in rules**: Keep `auditViolations: true`, remove `allowViolations: true` (or set to false)

```yaml
policy:
  enforcer: AppArmorBPF
  mode: EnhanceProtect
  enhanceProtect:
    auditViolations: true
    hardeningRules:
      - disallow-abuse-user-ns
```

- **Custom rules (AppArmor / BPF enforcer)**: Use `audit deny` combination — both block and log

```yaml
# AppArmor
appArmorRawRules:
- rules: |
    audit deny network rxrpc,

# BPF
bpfRawRules:
  network:
    sockets:
    - qualifiers: ["audit", "deny"]
      domains: ["rxrpc"]
```

When generating policy templates, the output should include both observe mode and enforce mode configuration examples to facilitate phased deployment.

## Important Notes

1. **Prefer built-in rules**: If vArmor already has a corresponding built-in rule (e.g., `copy-fail-mitigation`, `dirty-pipe-mitigation`, `ingress-nightmare-mitigation`), prefer using the built-in rule over custom rules.
2. **Syntax accuracy**: AppArmor custom rules must end with a comma; Seccomp rules' args field must use correct comparison operators.
3. **Audit flag**: It is recommended to include the audit flag in deny rules to capture exploitation attempts in `/var/log/varmor/violations.log`.
4. **Multi-enforcer clarification**: When the template lists rules for AppArmor/BPF/Seccomp simultaneously, comments must explain that users should select rules corresponding to their deployed enforcer, not use all of them.
5. **Honest impact assessment**: Business impact of rules must be stated honestly — better to over-communicate potential impact so users can make informed decisions than to hide potential issues.
6. **Complete variant coverage**: When outputting multiple options, explicitly state which variants each option covers. If a variant cannot be covered in a specific option (because blocking would severely impact business), explicitly state this and provide alternative recommendations.
7. **Phased rollout**: Policy output must remind users that they can use observe mode to validate first, and switch to enforcement mode only after confirming no conflicts.
