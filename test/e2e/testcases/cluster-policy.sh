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

# Cluster-scoped policy (VarmorClusterPolicy) test case configuration

# Test name
TEST_NAME="cluster-policy-sa-token-protection"

# Test description
TEST_DESCRIPTION="Testing VarmorClusterPolicy (cluster-scoped) with the BPF enforcer for denying access to ServiceAccount Token"

# Policy kind. VarmorClusterPolicy is cluster-scoped (not namespaced), which
# tells the framework to wait for its readiness without the `-n` flag.
POLICY_KIND="VarmorClusterPolicy"

# Namespace (the cluster-scoped policy targets a workload that lives here)
NAMESPACE="demo"

# Policy name
POLICY_NAME="demo-cluster-policy"

# Initial policy file
POLICY_FILES="manifests/cluster-policy/vcpol-bpf-alwaysallow.yaml"

# Enhanced policy file
ENHANCED_POLICY_FILES="manifests/cluster-policy/vcpol-bpf-enhance.yaml"

# Workload file
WORKLOAD_FILES="manifests/cluster-policy/deploy.yaml"

# Pod selector
POD_SELECTOR="app=demo-cluster-policy"

# Container name (c0 is explicitly unconfined, so we enforce/verify on c1)
CONTAINER_NAME="c1"

# Initial command - Should be able to read SA Token in AlwaysAllow mode
INITIAL_COMMAND="cat /run/secrets/kubernetes.io/serviceaccount/token"

# Initial command expected status code (0 means success)
INITIAL_EXPECTED_STATUS=0

# Verification command - Should not be able to read SA Token in EnhanceProtect mode
VERIFY_COMMAND="cat /run/secrets/kubernetes.io/serviceaccount/token"

# Verification command expected status code (non-0 means failure, expected to be blocked by policy)
VERIFY_EXPECTED_STATUS=1

# Clean up resources after test
CLEANUP_AFTER_TEST=true
