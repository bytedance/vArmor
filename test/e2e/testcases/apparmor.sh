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

# AppArmor Test Case Configuration

# Test name
TEST_NAME="apparmor-sa-token-protection"

# Test description
TEST_DESCRIPTION="Testing AppArmor policy protection for ServiceAccount Token"

# Initial policy file
POLICY_FILES="../examples/1-apparmor/vpol-apparmor-alwaysallow.yaml"

# Enhanced policy file
ENHANCED_POLICY_FILES="../examples/1-apparmor/vpol-apparmor-enhance.yaml"

# Workload file
WORKLOAD_FILES="../examples/1-apparmor/deploy.yaml"

# Pod selector
POD_SELECTOR="app=demo-1"

# Container name
CONTAINER_NAME="c1"

# Initial command - Should be able to read SA Token in AlwaysAllow mode
INITIAL_COMMAND="cat /run/secrets/kubernetes.io/serviceaccount/token"

# Initial command expected status code (0 means success)
INITIAL_EXPECTED_STATUS=0

# Verification command - Should not be able to read SA Token in EnhanceProtect mode
VERIFY_COMMAND="cat /run/secrets/kubernetes.io/serviceaccount/token"

# 验证命令预期状态码 (非0表示失败，预期被策略阻止)
VERIFY_EXPECTED_STATUS=1

# Clean up resources after test
CLEANUP_AFTER_TEST=true