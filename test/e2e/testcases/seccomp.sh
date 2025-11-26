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

# Seccomp enforcement test case configuration

# Test name
TEST_NAME="seccomp-mount-syscall-protection"

# Test description
TEST_DESCRIPTION="Testing Seccomp enforcer for denying access to mount system calls"

# Namespace
NAMESPACE="demo"

# Policy name
POLICY_NAME="demo-4"

# Initial policy file
POLICY_FILES="../examples/4-seccomp/vpol-seccomp-alwaysallow.yaml"

# Enhanced policy file
ENHANCED_POLICY_FILES="../examples/4-seccomp/vpol-seccomp-enhance.yaml"

# Workload file
WORKLOAD_FILES="../examples/4-seccomp/deploy-in-demo-ns.yaml"

# Pod selector
POD_SELECTOR="app=demo-4"

# Container name
CONTAINER_NAME="c0"

# Initial command - Should be able to execute mount system call in AlwaysAllow mode
INITIAL_COMMAND="unshare -m echo 'Testing mount syscall'"

# Initial command expected status code (0 means success)
INITIAL_EXPECTED_STATUS=0

# Verification command - In EnhanceProtect mode, the mount system call should not be executable.
VERIFY_COMMAND="unshare -m echo 'Testing mount syscall'"

# Verification command expected status code (non-0 means failure, expected to be blocked by policy)
VERIFY_EXPECTED_STATUS=1

# Clean up resources after test
CLEANUP_AFTER_TEST=true