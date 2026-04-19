---
sidebar_position: 2
description: 基于行为模型保护工作负载。
---

# DefenseInDepth 模式

## 介绍

基于 “默认拒绝”（Deny-by-Default）安全模型的强制访问控制（MAC）策略能显著提升安全性，但制定兼具安全性和兼容性的配置文件是关键挑战——既不影响应用的正常运行，又能起到深度防护效果。

DefenseInDepth 模式是 vArmor 的一个实验功能，它力图结合多种技术（行为建模、违规审计、大语言模型辅助分析与处理等），为您提供一种低门槛、高易用的微服务强制访问控制配置文件生成与管理解决方案。

当前只有 AppArmor 和 Seccomp enforcer 支持 DefenseInDepth 模式。

## 核心能力

当前，DefenseInDepth 模式支持使用两种类型的配置文件来防护目标。

* 通过 BehaviorModeling 模式生成的配置文件
* 自定义的配置文件

并且还提供了观察模式和自定义规则叠加等特性，从而允许您进行策略试运行与动态调优。

## 使用场景

* 为容器化微服务构建白名单安全配置文件
* 提供自定义安全配置文件管理能力
* 结合审计日志持续优化安全配置文件

具体操作详见[接口说明](../../../getting_started/interface_specification.md#defenseindepth)，并参考项目仓库中的示例。
