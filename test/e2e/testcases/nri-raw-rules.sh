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

# NRI raw rules test case configuration

# Test name (must contain "nri" to trigger NRI-specific test flow)
TEST_NAME="nri-raw-rules"

# Test description
TEST_DESCRIPTION="Testing NRI enforcer with raw Rego rules in nriRawRules"

# Namespace
NAMESPACE="demo"

# Policy name
POLICY_NAME="demo-7-raw"

# Initial policy file (AlwaysAllow mode)
POLICY_FILES="../examples/7-nri-enforcer/vpol-nri-raw-rules-alwaysallow.yaml"

# Enhanced policy file (EnhanceProtect mode with raw Rego rules)
ENHANCED_POLICY_FILES="../examples/7-nri-enforcer/vpol-nri-raw-rules.yaml"

# Workload file - same file used for both phases
WORKLOAD_FILES="../examples/7-nri-enforcer/deploy-raw-rules.yaml"

# Pod selector
POD_SELECTOR="app=demo-7-raw"

# Container name
CONTAINER_NAME="demo-container"

# Initial command - verifies Pod is working in AlwaysAllow mode
INITIAL_COMMAND="echo 'NRI raw rules test: Pod is running'"

# Initial command expected status code (0 means success)
INITIAL_EXPECTED_STATUS=0

# For NRI-specific test flow, these are not used but kept for compatibility
VERIFY_COMMAND="true"
VERIFY_EXPECTED_STATUS=0

# Clean up resources after test
CLEANUP_AFTER_TEST=true
