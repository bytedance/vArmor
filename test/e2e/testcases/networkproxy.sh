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

# NetworkProxy enforcer test case: MITM header injection.
#
# What this proves:
#   The Envoy sidecar performs a full MITM round-trip: it decrypts the TLS
#   request with the injected vArmor CA, applies the headerMutation
#   (X-Request-Source: varmor-audit), re-encrypts and forwards upstream.
#   postman-echo.com/headers echoes back whatever headers it received, so seeing
#   "varmor-audit" in the response body proves decrypt + inject + forward all
#   work. This is the MITM-specific capability that the deny test cannot cover.
#
# Single-phase model:
#   The policy is applied BEFORE the workload (POLICY_FILES), so the mutating
#   webhook injects the sidecar and CA-bundle volumes at pod creation. There is
#   no policy switch, hence ENHANCED_POLICY_FILES is empty (the framework does
#   not wait for a pod rollout after applying ENHANCED_POLICY_FILES, which would
#   race the MITM volume mounts).
#
# Note: '-k' is intentionally omitted so curl validates the MITM leaf against
# the injected CA bundle (CURL_CA_BUNDLE), exercising CA injection too.

# Test name
TEST_NAME="networkproxy-mitm-header-inject"

# Test description
TEST_DESCRIPTION="Testing NetworkProxy MITM header mutation echoed by postman-echo.com/headers"

# Namespace
NAMESPACE="demo"

# Policy name
POLICY_NAME="e2e-networkproxy-mitm-audit"

# Initial policy file (the full MITM policy; applied before the workload)
POLICY_FILES="manifests/networkproxy/vpol-mitm-audit.yaml"

# No enhanced/second policy: single-phase apply (see header comment)
ENHANCED_POLICY_FILES=""

# Workload file
WORKLOAD_FILES="manifests/networkproxy/deploy-mitm-audit.yaml"

# Pod selector
POD_SELECTOR="app=e2e-networkproxy-mitm-audit"

# Container name
CONTAINER_NAME="c0"

# Initial command (warm-up; not asserted by the framework)
INITIAL_COMMAND="curl -sSL -o /dev/null https://postman-echo.com/headers"

# Initial command expected status code
INITIAL_EXPECTED_STATUS=0

# Verification command - the injected header must be echoed back by postman-echo
VERIFY_COMMAND='curl -sSL https://postman-echo.com/headers | grep -q "varmor-audit"'

# Verification expected status code (0 means grep found the injected header)
VERIFY_EXPECTED_STATUS=0

# Clean up resources after test
CLEANUP_AFTER_TEST=true
