# Pod Pending / ContainerCreating 诊断路标

## 入口信号

Pod 处于 Pending 或 ContainerCreating，事件/状态涉及 Profile、AppArmor、Seccomp、NetworkProxy、Secret、sidecar、initContainer 或证书。

## 先排除通用 Kubernetes 原因

如果没有 vArmor Profile/注入/代理相关证据，优先走调度、镜像、资源、PVC、节点污点、CNI 等通用路径，不要强行归因 vArmor。

## vArmor 路径

1. Pod 是否被调度，目标节点是谁；
2. Pod 是否有 AppArmor/Seccomp/BPF/NetworkProxy 注入痕迹；
3. 策略是否仍存在，`profileName` 是否对应 AP；
4. AP 是否包含目标节点失败条件；
5. 节点 agent、Profile 加载、kubelet/runtime 是否健康；
6. 若 NetworkProxy，检查 init、sidecar、Secret/证书、资源和端口。

## 典型场景

- **Profile not found**：策略/AP 存在但节点资源未落地，或 Pod 引用旧/错误 Profile；
- **策略删除后仍引用**：Workload PodTemplate、裸 Pod 或旧 Pod 残留 annotation/SecurityContext；
- **NetworkProxy init/sidecar 失败**：常见于重定向能力、Secret/证书、资源、端口或代理 readiness；
- **Pod 已在旧模板创建**：策略更新或 Webhook 恢复不会自动修改旧 Pod。

修复建议应先确认对象归属和影响范围，避免直接删除业务 Pod 或放宽策略。
