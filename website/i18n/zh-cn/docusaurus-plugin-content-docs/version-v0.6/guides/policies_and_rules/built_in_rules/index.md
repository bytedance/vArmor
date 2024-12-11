---
slug: /guides/policies_and_rules/built_in_rules
sidebar_position: 2
---

# 内置规则

**vArmor** 支持使用内置规则来定义 **EnhanceProtect** 模式的策略对象 [VarmorPolicy](../../getting_started/usage_instructions.md#varmorpolicy) 或 [VarmorClusterPolicy](../../getting_started/usage_instructions.md#varmorclusterpolicy)，当前支持的内置规则及其分类展示在如下子页面中。你也可以尝试使用 [策略顾问](guides/policy_advisor.md) 来生成策略模版，从而帮助创建最终的防护策略。

注意：<br />- 不同 enforcer 所支持的内置策略与语法仍旧处于开发中。<br />- 不同 enforcer 所能支持的规则和语法会有所区别。例如 AppArmor enforcer 暂不支持细粒度的网络访问控制，BPF 不支持对指定的可执行程序进行访问控制等。<br />

import DocCardList from '@theme/DocCardList';

<DocCardList />