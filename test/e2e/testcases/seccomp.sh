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

# Seccomp测试用例配置

# 测试名称
TEST_NAME="seccomp-syscall-protection"

# 测试描述
TEST_DESCRIPTION="测试Seccomp策略对系统调用的限制"

# 初始策略文件
POLICY_FILES="../examples/5-seccomp/vpol-seccomp-alwaysallow.yaml"

# 增强策略文件
ENHANCED_POLICY_FILES="../examples/5-seccomp/vpol-seccomp-enhance.yaml"

# 工作负载文件
WORKLOAD_FILES="../examples/5-seccomp/deploy-in-demo-ns.yaml"

# Pod选择器
POD_SELECTOR="app=demo-5"

# 容器名称
CONTAINER_NAME="c1"

# 初始命令 - 在AlwaysAllow模式下应该可以执行mount系统调用
INITIAL_COMMAND="unshare -m echo 'Testing mount syscall'"

# 初始命令预期状态码 (0表示成功)
INITIAL_EXPECTED_STATUS=0

# 验证命令 - 在EnhanceProtect模式下应该无法执行mount系统调用
VERIFY_COMMAND="unshare -m echo 'Testing mount syscall'"

# 验证命令预期状态码 (非0表示失败，预期被策略阻止)
VERIFY_EXPECTED_STATUS=1

# 测试后是否清理资源
CLEANUP_AFTER_TEST=true