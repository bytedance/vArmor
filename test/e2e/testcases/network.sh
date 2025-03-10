#!/bin/bash

# Copyright 2023 vArmor Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# 网络访问控制测试用例配置

# 测试名称
TEST_NAME="network-access-control"

# 测试描述
TEST_DESCRIPTION="测试BPF策略对网络连接的限制"

# 初始策略文件
POLICY_FILES="../examples/2-bpf/vpol-bpf-alwaysallow.yaml"

# 增强策略文件
ENHANCED_POLICY_FILES="../examples/2-bpf/vpol-bpf-enhance-curl.yaml"

# 工作负载文件
WORKLOAD_FILES="../examples/2-bpf/deploy.yaml"

# Pod选择器
POD_SELECTOR="app=demo-network"

# 容器名称
CONTAINER_NAME="c1"

# 初始命令 - 在AlwaysAllow模式下应该可以连接到外部网络
INITIAL_COMMAND="curl"

# 初始命令预期状态码 (0表示成功)
INITIAL_EXPECTED_STATUS=0

# 验证命令 - 在EnhanceProtect模式下应该无法连接到被限制的外部网络
VERIFY_COMMAND="curl"

# 验证命令预期状态码 (非0表示失败，预期被策略阻止)
VERIFY_EXPECTED_STATUS=1

# 测试后是否清理资源
CLEANUP_AFTER_TEST=true