# varmor-classifier 与 BehaviorModeling

## 角色

classifier 是行为建模场景的辅助 DaemonSet，不是普通 EnhanceProtect/RuntimeDefault/AlwaysAllow 防护的必需组件。它帮助处理节点采集的行为数据，尤其是路径中的随机元素；manager 再汇总跨节点数据并生成 APM/Profile。

## 建模链路

```text
目标 Workload 行为 → agent/audit/BPF 采集 → classifier 归一化/上报 → manager 汇总、建模、持久化 → ArmorProfileModel → 后续分析或 DefenseInDepth
```

任一段失败都可能表现为“建模没有数据”，但根因不同。

## 前置条件

重点核对 containerd、BTF、审计日志来源、BehaviorModeling 开关、agent/classifier 资源和节点覆盖。行为数据过大时，APM 可能使用本地磁盘而不是 CRD 内部存储，需结合 `storageType` 判断可见性。

## 典型故障

- **classifier 不存在**：只有在行为建模功能启用时才是异常；
- **未覆盖节点**：该节点行为不会进入完整模型；
- **Running 但无数据**：区分采集能力、审计来源、classifier 上报、manager 接收和持久化；
- **建模一直未完成**：结合策略 phase、duration、目标 Pod 是否重新进入建模、APM desired/completed/ready 和 manager 日志；
- **完成后切换失败**：BehaviorModeling 与其他模式存在生命周期限制，以策略 status 和当前版本校验结果为准。

行为建模只描述“观察到的行为”，不证明行为完整，也不自动等于安全许可清单。

## 建议方向（仅建议）

先确认采集链和数据完整性，再考虑用模型生成或调整防护 Profile。不要把“建模完成”直接当作“策略已经启用”，也不要未经确认用观察数据替代最小权限审查。
