# 自定义规则
[English](custom_rules.md) | 简体中文

vArmor 支持用户基于 enforcer 的语法，在 EhanceProtect 模式的 [VarmorPolicy](../../getting_started/usage_instructions.zh_CN.md#varmorpolicy) 或 [VarmorClusterPolicy](../../getting_started/usage_instructions.zh_CN.md#varmorclusterpolicy) 对象中自定义访问控制规则。

注：BPF enforcer 支持的语法在持续开发中。

## AppArmor enforcer

AppArmor enforcer 支持用户根据 AppArmor 的语法定制策略。

请参见此[文档](https://manpages.ubuntu.com/manpages/jammy/man5/apparmor.d.5.html)在 [`.spec.policy.enhanceProtect.appArmorRawRules`](../../getting_started/interface_specification.zh_CN.md) 字段中设置自定义规则。请确保每条规则以 ',' 结尾。

## Seccomp enforcer

Seccomp enforcer 支持用户根据 OCI 规范的语法定制策略。

请参见此[文档](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp)在 [`.spec.policy.enhanceProtect.syscallRawRules`](../../getting_started/interface_specification.zh_CN.md) 字段中设置自定义的系统调用规则。

## BPF enforcer

BPF enforcer 支持用户根据语法定制策略。每类规则的数量上限为 50 条。每个节点支持最多对 100 个容器开启沙箱。

请参考以下语法在 [`.spec.policy.enhanceProtect.bpfRawRules`](../../getting_started/interface_specification.zh_CN.md#bpfrawrules) 中设置自定义规则。

### 文件权限定义

  | 权限 | 缩写 | 隐含权限 | 备注 |
  |-----|-----|---------|-----|
  |read|r|-<br />rename<br />hard link|禁止读<br />禁止利用 rename **oldpath** newpath 绕过 oldpath 的读限制<br />禁止利用 ln **TARGET** LINK_NAME 绕过 TARGET 的读限制
  |write|w|-<br />append<br />rename<br />hard link<br />symbol link<br />chmod<br />chown|禁止写<br />禁止利用 O_APPEND flag 绕过 map_file_to_perms() 实现追加写操作<br />禁止利用 rename oldpath **newpath** 绕过 newpath 的写限制<br />禁止利用 ln TARGET **LINK_NAME** 绕过 LINK_NAME 的写限制<br />禁止利用创建软链接（符号链接）绕过目标文件的写限制<br />WIP<br />WIP
  |exec|x|-|禁止执行
  |append|a|-|禁止追加写

* **文件路径匹配**

  BPF enfocer 支持根据路径 Pattern 对文件进行匹配，并支持两种匹配模式（精确匹配、通配匹配），匹配 Pattern 的最大长度限制为 64 字节。

  |通配符|语法|样例|备注|
  |-----|---|---|----|
  |*|- 仅用于匹配叶子结点的文件名<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 *，且不支持 \*\* 和 * 一起出现|- fi\* 代表匹配任意以 fi 开头的文件名<br />- *le 代表匹配任意以 le 结尾的文件名<br />- *.log 代表匹配任意以 .log 结尾的文件名|此通配符的行为可能会在后续版本中发生改变|
  |\**|- 在多级目录中，匹配零个、一个、多个字符<br />- 匹配 dot 文件，但不匹配 . 和 .. 文件<br />- 仅支持单个 \*\*，且不支持 ** 和 * 一起出现|- /tmp/\*\*/33 代表匹配任意以 /tmp 开头，且以 /33 结尾的文件，包含 /tmp/33<br />- /tmp/\*\* 代表匹配任意以 /tmp 开头的文件、目录<br />- /tm** 代表匹配任意以 /tm 开头的文件、目录<br />- /t**/33 代表匹配任意以 /t 开头，以 /33 结尾的文件、目录
  
### 网络地址匹配
* 当前 vArmor 支持对指定的 IP 地址、IP 地址块（CIDR 块）、端口进行外联访问控制
* 当指定了 IP 地址、IP 地址块，但未指定端口时，默认对所有端口生效
* 具体请参见 [NetworkEgressRule](../../getting_started/interface_specification.zh_CN.md#networkegressrule)
