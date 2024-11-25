---
slug: /guides/policies_and_rules/built_in_rules
sidebar_position: 2
---


# The Built-in Rules

vArmor supports defining [VarmorPolicy](../../getting_started/usage_instructions.md#varmorpolicy) or [VarmorClusterPolicy](../../getting_started/usage_instructions.md#varmorclusterpolicy) objects using built-in rules in **EnhanceProtect mode**. The currently supported built-in rules and categories are shown in the following pages. You can also try using the [policy advisor](guides/policy_advisor.md) to generate a policy template with built-in rules.

Note:<br />- The built-in rules supported by different enforcers are still under development.<br />- There are some limitations in the rules and syntax supported by different enforcers. For example, the AppArmor enforcer does not support fine-grained network access control, and BPF does not support access control for specified executables.<br />

import DocCardList from '@theme/DocCardList';

<DocCardList />