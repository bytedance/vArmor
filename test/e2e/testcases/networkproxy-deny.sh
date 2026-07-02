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

# NetworkProxy enforcer test case: MITM L7 path deny.
#
# What this proves:
#   After MITM decryption, the L7 RBAC rules deny /admin/* while allowing
#   GET /get. The single MITM-deny policy carries both an allow rule and a
#   deny rule, so the framework's two-phase exec (INITIAL warm-up then VERIFY)
#   exercises both sides with one policy.
#
# Single-phase policy model: policy applied before the workload (see the
# header-inject testcase for rationale), ENHANCED_POLICY_FILES empty.
#
# curl exit-code mapping:
#   The deny path returns HTTP 403; curl treats 403 as a successful transfer
#   (exit 0) UNLESS --fail is given, which turns >=400 into exit 22. The
#   framework asserts the exec exit code, so --fail is REQUIRED here.
#   '-k' is omitted so the injected CA bundle is validated too.

# Test name
TEST_NAME="networkproxy-mitm-path-deny"

# Test description
TEST_DESCRIPTION="Testing NetworkProxy MITM L7 path deny (postman-echo.com/admin -> 403)"

# Namespace
NAMESPACE="demo"

# Policy name
POLICY_NAME="e2e-networkproxy-mitm-deny"

# Initial policy file (full MITM deny policy; applied before the workload)
POLICY_FILES="manifests/networkproxy/vpol-mitm-deny.yaml"

# No enhanced/second policy: single-phase apply
ENHANCED_POLICY_FILES=""

# Workload file
WORKLOAD_FILES="manifests/networkproxy/deploy-mitm-deny.yaml"

# Pod selector
POD_SELECTOR="app=e2e-networkproxy-mitm-deny"

# Container name
CONTAINER_NAME="c0"

# Initial command - allowed path GET /get should succeed
INITIAL_COMMAND="curl -sSL --fail -o /dev/null https://postman-echo.com/get"

# Initial command expected status code (0 means allowed)
INITIAL_EXPECTED_STATUS=0

# Verification command - denied path /admin/login -> 403 -> curl --fail exits 22
VERIFY_COMMAND="curl -sSL --fail -o /dev/null https://postman-echo.com/admin/login"

# Verification expected status code (22 = curl HTTP error, request was blocked)
VERIFY_EXPECTED_STATUS=22

# Clean up resources after test
CLEANUP_AFTER_TEST=true
