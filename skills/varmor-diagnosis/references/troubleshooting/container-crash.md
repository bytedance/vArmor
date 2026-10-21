# Container Crash / CrashLoopBackOff diagnosis guide

## Entry signals

Repeated container restarts, nonzero exit, SIGSYS, Permission denied, Operation not permitted, Bad system call, or NetworkProxy sidecar/initContainer failures.

## Evidence routing

1. Inspect lastState, exit code/signal, events, and logs immediately before the crash;
2. Correlate the Pod's Profile, policy mode, and enforcer;
3. Correlate node status and kernel logs to distinguish container denials from node failures;
4. Confirm disposition with audit profileName, Pod UID, nodeName, action, and time;
5. If temporarily switching to observation or AlwaysAllow is proposed, treat it as a controlled isolation experiment and explain security risks and rollback conditions.

## Typical signals

- `Permission denied`/`EACCES`: prioritize AppArmor/BPF file, capability, mount, and path rules;
- `SIGSYS`/`Bad system call`: prioritize Seccomp syscall rules;
- `EPERM`: may originate from BPF, Seccomp, capabilities, NetworkProxy, or the application; insufficient for attribution alone;
- Node NotReady, reboots, kernel BUG/Oops/Call Trace: prioritize node/BPF kernel issues;
- NetworkProxy sidecar/init failure or application TLS errors: inspect proxy injection, certificates, ports, redirection, and MITM.

## Enforcer attribution order

First distinguish application container, initContainer, and NetworkProxy sidecar, then correlate each one's Profile, enforcer, node loading, and audit events. Error codes are clues only; do not conclude vArmor denied an operation without correlated Profile, Pod UID, time, and action evidence.

## Conclusion boundaries

Attribute denial to vArmor only with correlated Profile, enforcer, time, and audit/log evidence. Otherwise retain application, runtime, node, or other security mechanisms as unexcluded possibilities.
