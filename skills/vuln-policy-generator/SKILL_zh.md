---
name: varmor-vuln-policy-generator
description: "vArmor 漏洞缓解策略生成器。当用户提供 0day/Nday 漏洞信息（CVE 编号、PoC/Exp 代码、漏洞分析文章、GitHub 仓库等）并要求：(1) 分析漏洞能否用于容器逃逸或在容器内被利用，(2) 生成 vArmor 防护策略，(3) 评估能否使用 vArmor 进行防御——时使用本 Skill。适用于任何安全漏洞的防护策略生成场景，包括但不限于：Linux 内核漏洞（LPE/容器逃逸）、应用层漏洞（RCE/信息泄露/集群接管，如 IngressNightmare）、供应链漏洞、中间件漏洞等。即使用户没有明确提到 vArmor，只要涉及容器安全加固、漏洞缓解策略、运行时防护规则生成，都应优先使用本 Skill。"
---

# vArmor 漏洞缓解策略生成器

## 概述

本 Skill 用于在新漏洞（0day/Nday）出现时，快速完成以下工作：
1. 深入分析漏洞原理和利用手法
2. 判断漏洞的利用场景（容器逃逸、容器内 RCE、集群接管、信息泄露等）
3. 生成 vArmor 缓解策略模版
4. 评估策略对业务的潜在影响并提供多种方案供用户选择

## 适用漏洞类型

本 Skill 覆盖以下漏洞类型：

| 漏洞类型 | 典型案例 | vArmor 防御维度 |
|---------|---------|----------------|
| 内核 LPE → 容器逃逸 | Dirty Pipe, Copy Fail, Dirty Frag | syscall 限制、socket 协议族限制、namespace 限制 |
| 应用层 RCE → 集群接管 | IngressNightmare (CVE-2025-1974) | 网络访问控制（限制对敏感 Service/端口的访问） |
| 容器运行时逃逸 | CVE-2019-5736 (runc) | 文件写入限制 |
| 应用层任意文件读写 | 各类 Web 应用漏洞 | 文件访问控制 |
| 信息泄露/凭证窃取 | ServiceAccount token 滥用 | 文件读取限制、网络外连限制 |
| 供应链/依赖漏洞 | Log4Shell 等 | 网络外连限制、进程执行限制 |

## 工作流程

按照以下步骤执行，每一步都不可省略：

### 第一步：信息收集与分析

1. **收集用户提供的漏洞信息**：CVE 编号、PoC/Exp 代码、漏洞分析文章、GitHub 仓库链接、技术 blog 等。

2. **主动检索补充信息**：使用搜索工具和网页抓取获取更多漏洞细节，包括但不限于：
   - 漏洞影响的软件版本范围（内核版本、应用版本等）
   - 漏洞利用所需的前置条件（需要哪些系统调用、哪些内核模块、哪些权限、哪些网络访问）
   - 漏洞利用的关键路径（触发链中的每一个关键步骤）
   - 已有的缓解方案和补丁状态
   - 是否存在多个利用变体

3. **深入分析漏洞原理**，根据漏洞类型关注不同重点：

   **内核漏洞**关注：
   - 漏洞触发所需的系统调用序列
   - 涉及的内核子系统和模块
   - 攻击者需要的最小权限集
   - 是否需要竞态条件（race condition）
   - 写入/修改原语的能力（任意写、有限写、条件写）

   **应用层漏洞**关注：
   - 触发漏洞需要的网络访问（访问哪些 Service、端口、协议）
   - 漏洞利用后能执行什么操作（RCE、任意文件读写、信息泄露）
   - 受影响的容器/Pod 的角色和权限（是否有敏感 RBAC 权限、是否挂载了 host path）
   - 攻击者的初始位置（集群内 Pod、外部网络、相邻 namespace）

### 第二步：漏洞利用场景评估

分析漏洞在容器/Kubernetes 环境中的利用可能性和威胁模型。根据漏洞类型选择对应的分析框架：

#### A. 内核漏洞 → 容器逃逸评估

1. **page-cache 类漏洞**（如 Dirty Pipe、Copy Fail、Dirty Frag）：
   - page-cache 在宿主机范围内共享
   - 容器镜像层（overlay fs）的 page-cache 页面跨容器共享
   - 特权 DaemonSet 可能执行被污染的二进制

2. **namespace/cgroup 逃逸类漏洞**：
   - 容器的 namespace 隔离是否可被绕过
   - cgroup 相关的逃逸路径

3. **内核对象越界访问类漏洞**：
   - 是否可以跨 namespace 访问内核对象
   - 是否可以修改宿主机文件系统

#### B. 应用层漏洞 → 容器内利用/集群接管评估

1. **RCE 类漏洞**（如 IngressNightmare）：
   - 攻击者能否从网络触发漏洞（需要访问哪个 Service/端口）
   - 受影响组件的容器权限（RBAC 角色、挂载的 Secret、网络权限）
   - 利用成功后的影响范围（单容器内 RCE → 读取 Secret → 集群接管）

2. **信息泄露类漏洞**：
   - 能否读取 ServiceAccount token、环境变量中的凭证
   - 能否访问集群内部 API

3. **供应链/依赖漏洞**（如 Log4Shell）：
   - 能否发起外部网络连接（反弹 shell、下载 payload）
   - 能否执行非预期的二进制

#### C. 容器运行时漏洞

1. **容器逃逸类**（如 CVE-2019-5736 runc override）：
   - 是否可以覆写宿主机上的运行时二进制
   - 是否需要特定的容器配置

#### 评估结论

评估结论应明确说明：
- **威胁类型**：容器逃逸 / 容器内 RCE / 集群接管 / 信息泄露 / 横向移动
- 具体的攻击路径和前置条件
- 影响范围（哪些 K8s 环境/工作负载受影响）

#### 各变体/利用路径的容器内利用可行性评级

对于存在多个变体或利用路径的漏洞，**必须**对每个变体单独评估其在容器环境中的实际可利用性，而非平等对待。评估维度如下：

1. **前置条件可满足性**：该变体的前置条件在典型容器环境中是否默认满足？
   - 所需内核模块是否默认加载？是否可被非特权用户 autoload？
   - 所需内核配置是否为主流发行版默认配置？
   - 是否需要额外权限/capabilities？容器默认是否具备？
   - 是否依赖特定文件系统挂载、设备访问等？

2. **利用稳定性与成本**：
   - 确定性利用（每次触发必然成功）vs 概率性利用（需要爆破/竞态）
   - 如果需要爆破，爆破空间多大？预期尝试次数是多少？
   - 是否存在时间窗口限制或需要特定时序配合？
   - 利用过程是否会产生明显的系统异常（如大量 crash、日志噪音）

3. **实用性结论**（分级）：
   - **高**：前置条件默认满足，确定性利用，直接可用于容器逃逸/攻击
   - **中**：前置条件部分满足或需要一定爆破，实际攻击中可行但成本较高
   - **低**：前置条件苛刻或爆破空间极大，仅在特殊配置下可利用
   - **仅理论**：利用链在实际容器环境中几乎不可行，但理论上路径存在

4. **防御优先级建议**：综合实用性和防御成本给出建议
   - 高实用性 → 必须防御
   - 中/低实用性但防御成本为零（无业务影响）→ 建议防御（"免费的保险"）
   - 低实用性且防御有业务影响 → 可选防御，由用户根据安全需求决定

示例（Dirty Frag）：
| 变体 | 前置条件可满足性 | 利用稳定性 | 实用性 | 防御优先级 |
|------|----------------|-----------|--------|-----------|
| ESP | 高（unprivileged user ns 默认可用） | 确定性 4 字节可控写 | **高** | 必须防御 |
| RxRPC | 低（依赖 af_rxrpc.ko 模块加载，可能可 autoload） | 需爆破，shellcode 注入理论爆破 N×2^56 | **低** | 建议防御（阻止 AF_RXRPC 无业务影响） |

### 第三步：阅读 vArmor 文档

**必须**从以下链接获取最新的 vArmor 策略语法和规则信息：

1. **策略 API 类型定义**（精确的字段结构和类型，编写自定义规则时必须参考）：
   - 顶层策略结构 + EnhanceProtect 定义：https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/common.go
   - BPF 规则定义（文件规则、网络规则、进程规则、挂载规则等）：https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/bpf.go
   - AppArmor 规则定义：https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/apparmor.go
   - Seccomp 规则定义：https://raw.githubusercontent.com/bytedance/vArmor/release-0.10/apis/varmor/v1beta1/seccomp.go

   这些 Go 类型定义文件是策略 YAML 的权威参考，每个字段都有注释说明含义、可选值和互斥关系。**编写自定义规则时，必须严格按照这些类型定义中的字段名和结构层级来编写 YAML，不可臆造字段。**

2. **内置规则**（优先使用内置规则，避免重复造轮子）：
   - 容器加固：https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/hardening
   - 攻击防护：https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/attack_protection
   - 漏洞缓解：https://www.varmor.org/docs/v0.10/guides/policies_and_rules/built_in_rules/vulnerability_mitigation

3. **自定义规则编写指引**：
   - vArmor 自定义规则文档：https://www.varmor.org/docs/v0.10/guides/policies_and_rules/custom_rules
   - AppArmor 语法参考：https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html
   （编写 AppArmor 自定义规则时务必参考语法文档，确保规则语法正确）

### 第四步：利用路径与防御点分析

这是策略设计的核心步骤，需要对漏洞的每条利用路径进行逐步分析。

#### 4.1 绘制利用路径图

对于漏洞的每个变体/利用路径，列出从攻击者初始状态到最终利用成功的完整步骤链。例如：

```
变体 A 利用路径：
  步骤 1: 创建 XX 套接字 → 步骤 2: 调用 splice() → 步骤 3: 触发内核路径 → 步骤 4: page-cache 写入
  
变体 B 利用路径：
  步骤 1: unshare(USER) → 步骤 2: 注册 SA → 步骤 3: splice() → 步骤 4: page-cache 写入
```

#### 4.2 识别每条路径上的防御点

对每条利用路径上的每个步骤，从以下维度分析可阻断性：

**系统调用维度**（Seccomp enforcer）：
- 是否可以阻断特定系统调用（如 splice、unshare）
- 是否可以通过参数过滤精确匹配（如 socket 的 domain 参数）

**网络协议/套接字维度**（AppArmor/BPF enforcer）：
- 是否可以阻止特定协议族的套接字创建（AF_ALG、AF_RXRPC 等）
- 是否可以限制对特定 Service/IP/端口的网络访问（BPF enforcer 的 egress 规则）

**文件访问维度**（AppArmor/BPF enforcer）：
- 是否可以限制对特定文件/路径的读写（如禁止写入 /**/runc）
- 是否可以限制可执行文件的范围

**进程执行维度**（AppArmor/BPF enforcer）：
- 是否可以限制容器内可执行的二进制
- 是否可以阻止特定进程的网络行为

对每个可能的阻断点，分析：
- **是否可以被 vArmor 阻断**（哪种 enforcer 可以阻断）
- **阻断该步骤的优点**：是否精准、是否为漏洞特有的操作
- **阻断该步骤的缺点/风险**：是否会影响正常业务、是否容易被绕过
- **影响范围评估**：哪些正常应用会使用该系统调用/接口/网络路径

#### 4.3 选择最优防御点

选择原则（按优先级排序）：
1. **精准性**：优先选择漏洞利用特有的操作（如特定协议族套接字），而非通用操作（如 read/write）
2. **不可绕过**：优先选择利用链中无法替代的步骤
3. **最小影响**：优先选择对正常业务影响最小的阻断点
4. **覆盖性**：如果一条规则能同时阻断多个变体，且无业务影响，优先使用

### 第五步：策略设计与多方案输出

基于第四步的分析，设计多档缓解方案：

#### 方案分级原则

- **方案一：最小影响方案**
  - 仅阻断漏洞特有的、不影响正常业务的利用向量
  - 必须覆盖所有变体（每个变体至少有一个阻断点被覆盖）
  - 如果某个变体的所有阻断点都会影响业务，需在说明中指出该变体未被此方案覆盖

- **方案二：加强防护方案**
  - 在方案一基础上增加深度防御规则
  - 可能对少量特殊应用产生影响，但为大多数工作负载提供更完善的保护
  - 每个变体都要有冗余防御点

- **方案三：最大防护方案**（仅在需要时提供）
  - 最严格的限制，可能影响部分业务
  - 适用于高安全要求的环境（如多租户集群、运行不可信代码的环境）
  - 需明确标注受影响的应用类型

如果一条规则可以同时覆盖所有变体且无业务影响，可以合并为单一方案并说明。

### 第六步：生成策略模版

#### 输出格式要求

输出应包含两部分：**漏洞分析报告** 和 **策略模版**。

#### 漏洞分析报告格式

```markdown
## 漏洞分析报告

### 漏洞概述
- CVE 编号 / 漏洞名称
- 影响范围（内核版本、发行版）
- 漏洞类型和严重程度
- 补丁状态

### 漏洞原理（每个变体分别描述）

#### 变体 X：<变体名称>
- 根因分析（含关键代码路径）
- 利用手法
- 所需前置条件（权限、内核模块、系统调用）
- 写入原语能力（写入大小、位置可控性、值可控性）

### 利用路径与防御点分析

#### 变体 X 利用路径
| 步骤 | 操作 | 涉及的系统调用/接口 | 可否被 vArmor 阻断 | 阻断的 enforcer | 阻断优点 | 阻断缺点/风险 | 业务影响评估 |
|------|------|-------------------|-------------------|----------------|---------|-------------|------------|

### 容器逃逸评估
- 结论：能否用于容器逃逸
- 逃逸路径描述
- 前置条件
- 受影响的 K8s 环境

### 各变体容器内利用可行性评级
| 变体 | 前置条件可满足性 | 利用稳定性 | 实用性（高/中/低/仅理论） | 防御优先级 |
|------|----------------|-----------|-------------------------|-----------|

### 缓解可行性总结
- vArmor 能否缓解：是/否/部分
- 推荐的防御点选择及理由
- 无法阻断的情况说明（如有）
```

#### 策略模版格式

策略模版按以下格式组织，为每个利用变体/利用向量分别列出规则，并按 enforcer 类型分类：

```yaml
# ============================================================
# 方案一：最小影响方案
# 覆盖变体：<列出覆盖的变体>
# 总体影响：<一句话总结>
# ============================================================
policy:
  enforcer: <AppArmor|BPF|Seccomp 或组合，如 AppArmorBPFSeccomp>
  mode: EnhanceProtect
  enhanceProtect:
    # --- 阻断 <漏洞名称> <变体名称> 的利用向量 ---
    # 阻断原理：<阻断了利用链中的哪个步骤，为什么有效>
    # 潜在影响：<对业务可能的影响，具体到受影响的应用类型>
    # 影响程度：<无影响 / 极少数应用受影响 / 部分应用受影响>
    
    hardeningRules:
      # For AppArmor/BPF enforcer
      <内置规则名称>
      # For Seccomp enforcer
      <内置规则名称>

    # For AppArmor enforcer
    appArmorRawRules:
    - rules: |
        <AppArmor 规则>,

    # For BPF enforcer
    bpfRawRules:
      <BPF 规则结构>

    # For Seccomp enforcer
    syscallRawRules:
    - names:
      - <系统调用名>
      action: SCMP_ACT_ERRNO
      args:
      - index: <参数索引>
        value: <参数值>
        op: <比较操作符>

# ============================================================
# 方案二：加强防护方案
# 在方案一基础上增加的规则：<概述>
# 新增影响：<一句话总结新增的影响>
# ============================================================
# ... (同上格式)
```

#### 策略模版附加说明

每个策略方案必须附带：

1. **覆盖范围说明**：该方案覆盖了哪些变体，是否有未覆盖的变体
2. **规则说明**：每条规则的阻断原理（注释形式），阻断了利用链中的具体哪个步骤
3. **潜在影响评估**（每条规则单独评估）：
   - 该规则会影响哪些正常操作
   - 哪些类型的容器化应用可能受影响
   - 影响的严重程度（无影响 / 极少数应用受影响 / 部分应用受影响 / 大量应用受影响）
   - 受影响时的表现（进程报错、功能降级、还是完全不可用）
4. **方案选择建议**：帮助用户根据自身环境选择合适的方案
5. **使用提醒**：提醒用户根据实际使用的 enforcer 选择对应的规则，而非全部使用

### 第七步：其他维度缓解建议

无论 vArmor 能否缓解，都应给出其他维度的缓解建议（作为补充或替代方案）：

- **内核层面**：补丁升级建议、内核模块禁用（modprobe blacklist）、内核启动参数调整
- **Kubernetes 层面**：Pod 调度策略、镜像层隔离、特权 DaemonSet 最小权限化
- **网络层面**：网络策略限制
- **其他工具**：其他运行时安全工具的配合使用

如果 vArmor 无法有效缓解（例如需要阻断的系统调用是大多数容器必需的），需要特别强调这些替代方案的重要性。

## 参考案例

### 案例 1：Copy Fail (CVE-2026-31431)

**漏洞特征**：通过 AF_ALG 套接字 + splice() 实现 page-cache 4 字节任意写。

**利用路径分析**：
```
步骤 1: socket(AF_ALG) → 创建 AEAD 套接字
步骤 2: bind() → 绑定 authencesn 算法
步骤 3: splice(file → pipe → AF_ALG socket) → 钉入 page-cache 页
步骤 4: recv() → 触发 in-place crypto 的 4 字节 STORE
```

**防御点选择**：
| 步骤 | 阻断方式 | 优点 | 缺点 | 业务影响 |
|------|---------|------|------|---------|
| 步骤 1: socket(AF_ALG) | 阻止 AF_ALG 套接字 | 精准，漏洞特有 | 无 | 绝大多数容器无影响 |
| 步骤 3: splice() | 禁用 splice | 完全阻断 | 影响 nginx/kafka 等 | 大量应用受影响 |

**最优选择**：阻止 AF_ALG 套接字（精准、无影响）

**策略**：
```yaml
policy:
  enforcer: AppArmorBPF
  mode: EnhanceProtect
  enhanceProtect:
    # 阻止创建 AF_ALG 套接字（AF_ALG: 内核加密 API 的用户空间接口）
    # 阻断原理：Copy Fail 依赖 AF_ALG AEAD 套接字触发 in-place crypto 写入
    # 潜在影响：绝大多数容器化应用不使用 AF_ALG，通常无影响
    # 影响程度：无影响（仅极少数显式配置 afalg engine 的 OpenSSL 应用受影响）
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

后续 vArmor 增加了内置规则 `copy-fail-mitigation`，可直接使用：
```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    vulMitigationRules:
    - copy-fail-mitigation
```

### 案例 2：Dirty Frag

**漏洞特征**：两个变体——ESP 变体需要 user namespace (CAP_NET_ADMIN)，RxRPC 变体需要 AF_RXRPC 套接字。

**利用路径分析**：

变体 ESP：
```
步骤 1: unshare(CLONE_NEWUSER|CLONE_NEWNET) → 获取 CAP_NET_ADMIN
步骤 2: XFRM_MSG_NEWSA via netlink → 注册 SA（控制 seq_hi 值）
步骤 3: splice(file → pipe → UDP socket) → 钉入 page-cache 页到 skb frag
步骤 4: loopback → udp_rcv → xfrm_input → esp_input → skip_cow → 4 字节 STORE
```

变体 RxRPC：
```
步骤 1: socket(AF_RXRPC) → 创建 RxRPC 套接字
步骤 2: add_key("rxrpc", ...) → 注册包含 session_key 的 token
步骤 3: RxRPC 握手 + splice(file → pipe → UDP server → client)
步骤 4: rxkad_verify_packet_1 → in-place pcbc(fcrypt) decrypt → 8 字节 STORE
```

**防御点选择**：
| 变体 | 步骤 | 阻断方式 | 优点 | 缺点 | 业务影响 |
|------|------|---------|------|------|---------|
| ESP | 步骤 1 | 禁止 unshare user ns | 精准，切断权限来源 | 极少数应用需要 | 极少数受影响 |
| ESP | 步骤 3 | 禁用 splice | 完全阻断 | 影响面大 | 大量应用受影响 |
| RxRPC | 步骤 1 | 禁止 AF_RXRPC | 精准，漏洞特有 | 无 | 无影响 |
| RxRPC | 步骤 2 | 限制 add_key | 可能误伤 | keyring 操作常见 | 部分应用受影响 |

**策略**：
```yaml
# ============================================================
# 方案一：最小影响方案
# 覆盖变体：ESP + RxRPC（全部覆盖）
# 总体影响：绝大多数容器无影响
# ============================================================
policy:
  enforcer: AppArmorBPFSeccomp
  mode: EnhanceProtect
  enhanceProtect:
    # --- 阻断 Dirty Frag 漏洞 ESP 变体的利用向量 ---
    # 阻断原理：ESP 变体需要通过 unshare(CLONE_NEWUSER) 在新 namespace 中获取 CAP_NET_ADMIN 来注册 XFRM SA
    # 潜在影响：极少数需要在容器内创建 user namespace 的应用受影响（如某些测试框架、嵌套容器运行时）
    # 影响程度：极少数应用受影响
    hardeningRules:
      # For AppArmor/BPF enforcer
      disallow-abuse-user-ns
      # For Seccomp enforcer
      disallow-create-user-ns

    # --- 阻断 Dirty Frag 漏洞 RxRPC 变体的利用向量 ---
    # 阻断原理：RxRPC 变体需要创建 AF_RXRPC 套接字来建立连接并触发 rxkad_verify_packet_1 中的 in-place decrypt
    # 潜在影响：绝大多数容器化应用不使用 AF_RXRPC（Andrew File System 专用协议），通常无影响
    # 影响程度：无影响
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

### 案例 3：IngressNightmare (CVE-2025-1974)

**漏洞特征**：Ingress-nginx 准入控制器（admission controller）存在未认证 RCE 漏洞，攻击者从集群内任意 Pod 可远程执行代码，获取集群所有 Secret 并接管集群。

**漏洞类型**：应用层 RCE → 集群接管

**利用路径分析**：
```
步骤 1: 攻击者在集群内获取一个 Pod（任意 namespace）
步骤 2: 从 Pod 网络访问 ingress-nginx-controller-admission Service（端口 443）
步骤 3: 发送恶意 AdmissionReview 请求，注入 nginx 配置指令
步骤 4: 触发 nginx 重载，利用注入的配置执行任意代码
步骤 5: 在 ingress-nginx controller Pod 内获得 RCE
步骤 6: 读取 controller 挂载的 ServiceAccount token 和集群 Secret → 集群接管
```

**防御点选择**：
| 步骤 | 阻断方式 | 优点 | 缺点 | 业务影响 |
|------|---------|------|------|---------|
| 步骤 2: 网络访问 admission Service | BPF enforcer 限制对 admission Service/端口的访问 | 精准阻断攻击入口 | 仅 BPF enforcer 支持 | 正常 Ingress 创建不受影响（由 API Server 发起，不经过 Pod 网络） |
| 步骤 4: nginx 重载 | 限制 nginx 进程执行 | 可能影响正常运行 | 会破坏 ingress 功能 | 严重影响 |
| 步骤 6: 读取 Secret 文件 | 限制文件读取 | 深度防御 | 不阻止 RCE 本身 | 可能影响正常功能 |

**最优选择**：阻止 Pod 网络对 ingress-nginx-controller-admission Service 的访问（精准、不影响正常流量）

**策略**：
```yaml
# 使用 vArmor 内置规则（推荐）
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    vulMitigationRules:
    - ingress-nightmare-mitigation
```

**内置规则说明**：
- `ingress-nightmare-mitigation` 规则禁止容器进程访问 ingress-nginx 和 kube-system namespace 中的 ingress-nginx-controller-admission Service 及其 endpoints
- 仅 BPF enforcer 支持（需要网络访问控制能力）
- 如果 ingress-nginx 部署在其他 namespace，需使用自定义规则

**自定义规则示例**（ingress-nginx 部署在自定义 namespace 时）：
```yaml
policy:
  enforcer: BPF
  mode: EnhanceProtect
  enhanceProtect:
    # 阻断原理：阻止 Pod 网络直接访问 ingress-nginx admission webhook Service
    # 潜在影响：正常的 Ingress 资源创建/更新不受影响（由 kube-apiserver 发起 admission webhook 调用）
    # 影响程度：无影响（仅阻止 Pod 直接访问 admission Service，不影响正常 Ingress 流量）
    bpfRawRules:
      network:
        egress:
          toServices:
          - qualifiers: ["audit", "deny"]
            namespace: "custom-namespace"
            name: ingress-nginx-controller-admission
```

**关键说明**：
- 该漏洞不是容器逃逸，而是通过网络 RCE 实现集群接管
- vArmor 的防御思路是切断攻击网络路径，而非限制系统调用
- 这体现了 BPF enforcer 在网络访问控制方面的独特优势

## 上线建议：观察模式与拦截模式

策略生成后，建议用户按照以下流程上线，避免规则误伤业务：

### 阶段一：观察模式（验证规则是否与业务冲突）

先以观察模式部署，仅记录违规行为而不实际拦截：

- **内置规则**：同时开启 `auditViolations: true` 和 `allowViolations: true`，使规则仅审计不拦截

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

- **自定义规则（AppArmor enforcer）**：仅使用 `audit` qualifier（不加 `deny`），只记录不拦截

```yaml
appArmorRawRules:
- rules: |
    audit network rxrpc,
```

- **自定义规则（BPF enforcer）**：仅使用 `audit` qualifier（不加 `deny`），只记录不拦截

```yaml
bpfRawRules:
  network:
    sockets:
    - qualifiers: ["audit"]
      domains: ["rxrpc"]
```

- **自定义规则（Seccomp enforcer）**：Seccomp 不支持纯观察模式（无 audit-only 动作），只能直接拦截。建议在灰度环境先验证后再上线。

观察期间，检查 `/var/log/varmor/violations.log` 中是否有业务触发的违规记录。

### 阶段二：拦截 & 审计模式（确认无冲突后切换）

观察期确认无业务冲突后，切换到拦截模式：

- **内置规则**：保持 `auditViolations: true`，移除 `allowViolations: true`（或设为 false）

```yaml
policy:
  enforcer: AppArmorBPF
  mode: EnhanceProtect
  enhanceProtect:
    auditViolations: true
    hardeningRules:
      - disallow-abuse-user-ns
```

- **自定义规则（AppArmor / BPF enforcer）**：使用 `audit deny` 组合，既拦截又记录

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

生成策略模版时，输出中应同时给出观察模式和拦截模式的配置示例，方便用户分阶段部署。

## 重要注意事项

1. **内置规则优先**：如果 vArmor 已有对应的内置规则（如 `copy-fail-mitigation`、`dirty-pipe-mitigation`），优先使用内置规则而非自定义规则。
2. **语法准确性**：AppArmor 自定义规则必须以逗号结尾；Seccomp 规则的 args 字段必须使用正确的比较操作符。
3. **audit 标记**：建议在 deny 规则中加入 audit 标记，便于在 `/var/log/varmor/violations.log` 中捕获利用尝试。
4. **多 enforcer 说明**：模版中同时列出 AppArmor/BPF/Seccomp 的规则时，必须注释说明用户应根据实际部署的 enforcer 选择对应的规则，而非全部使用。
5. **影响评估诚实**：对规则可能产生的业务影响必须如实说明，宁可多说影响让用户做出知情决策，也不要隐瞒潜在问题。
6. **变体覆盖完整**：多方案输出时，必须明确说明每个方案覆盖了哪些变体。如果某个变体在特定方案中无法被覆盖（因为阻断会严重影响业务），必须显式说明并提供替代建议。
7. **分阶段上线**：策略输出中必须提醒用户可使用观察模式先行验证，确认无冲突后再切换到拦截模式。
