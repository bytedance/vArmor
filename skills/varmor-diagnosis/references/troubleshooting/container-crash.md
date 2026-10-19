# Container Crash / CrashLoopBackOff 诊断路标

## 入口信号

容器反复重启、非零退出、SIGSYS、Permission denied、Operation not permitted、Bad system call，或 NetworkProxy sidecar/initContainer 异常。

## 证据分流

1. 看 lastState、退出码/信号、事件和崩溃前日志；
2. 关联 Pod 使用的 Profile、策略模式和 enforcer；
3. 关联节点状态和内核日志，判断是容器级拒绝还是节点级异常；
4. 用审计事件的 profileName、Pod UID、nodeName、action 和时间确认处置；
5. 若临时进入观察模式或 AlwaysAllow，只作为受控二分验证，说明安全风险和回滚条件。

## 典型信号

- `Permission denied`/`EACCES`：优先检查 AppArmor/BPF 文件、能力、挂载和路径规则；
- `SIGSYS`/`Bad system call`：优先检查 Seccomp syscall 规则；
- `EPERM`：可能来自 BPF、Seccomp、能力、NetworkProxy 或业务自身，不能单独定性；
- 节点 NotReady、重启、kernel BUG/Oops/Call Trace：优先按节点/BPF 内核问题处理；
- NetworkProxy sidecar/init 失败或应用 TLS 错误：检查代理注入、证书、端口、重定向和 MITM 配置。

## Enforcer 归因顺序

先区分业务容器、initContainer 和 NetworkProxy sidecar，再关联各自的 Profile、enforcer、节点加载状态和审计事件。错误码只能作为线索；没有 Profile、Pod UID、时间和 action 的闭合证据，不直接判定为 vArmor 拦截。

## 结论边界

只有在 Profile、enforcer、时间和审计/日志证据闭合时，才能判定 vArmor 拦截；否则保留业务、runtime、节点或其他安全机制作为未排除项。
