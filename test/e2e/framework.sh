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

# vArmor E2E Test Framework
# This framework contains the following core components:
# 1. Test Case Loader: Loads test case configurations
# 2. Policy Applicator: Applies vArmor policies
# 3. Command Executor: Executes verification commands in containers
# 4. Result Validator: Verifies if policies are effective

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Global variables
TEST_DIR="$(dirname "$0")"
TEST_CASES_DIR="${TEST_DIR}/testcases"
RESULTS_DIR="${TEST_DIR}/results"
KUBECTL_CMD="k3s kubectl"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Retry configuration for transient operations (e.g. `kubectl apply`).
# Overridable from the environment so CI can tune them.
RETRY_TIMES="${RETRY_TIMES:-3}"
RETRY_INTERVAL="${RETRY_INTERVAL:-5}"

# Log functions
log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Retry an idempotent command up to RETRY_TIMES, sleeping RETRY_INTERVAL
# between attempts. Returns the exit status of the last attempt. Only use
# this for operations that are safe to repeat (e.g. `kubectl apply`), never
# for state-mutating one-shot commands.
retry() {
    local attempt=1
    local status=0
    while true; do
        "$@"
        status=$?
        if [ ${status} -eq 0 ]; then
            return 0
        fi
        if [ ${attempt} -ge ${RETRY_TIMES} ]; then
            log_error "Command failed after ${attempt} attempt(s): $*"
            return ${status}
        fi
        log_info "Attempt ${attempt}/${RETRY_TIMES} failed (status ${status}), retrying in ${RETRY_INTERVAL}s: $*"
        attempt=$((attempt+1))
        sleep ${RETRY_INTERVAL}
    done
}

# Wait for vArmor to be ready
wait_for_varmor_ready() {
    log_info "Waiting for vArmor to be ready..."
    
    ${KUBECTL_CMD} wait --for=condition=available deployment/varmor-manager -n varmor --timeout=60s
    if [ $? -ne 0 ]; then
        log_error "varmor-manager deployment is not available"
        return 1
    fi

    ${KUBECTL_CMD} wait --for=jsonpath='{.status.numberReady}'=1 ds -n varmor varmor-agent --timeout=120s
    if [ $? -ne 0 ]; then
        ${KUBECTL_CMD} get pods -n varmor -l app.kubernetes.io/component=varmor-agent
        log_info "---------" 
        name=$(${KUBECTL_CMD} get pods -n varmor -l app.kubernetes.io/component=varmor-agent -o jsonpath='{.items[0].metadata.name}')
        ${KUBECTL_CMD} describe pod -n varmor ${name}
        log_info "---------" 
        ${KUBECTL_CMD} logs -n varmor ${name}
        log_error "varmor-agent pods are not ready"
        return 1
    fi

    log_success "vArmor is ready"
    return 0
}

# Initialize test environment
init_test_env() {
    log_info "Initializing test environment"
    
    # Create results directory
    mkdir -p "${RESULTS_DIR}"
    
    # Clean up previous test results
    rm -f "${RESULTS_DIR}"/*.log
}

# Load test case
load_testcase() {
    local testcase_file=$1
    log_info "Loading test case: ${testcase_file}"
    
    # Check if test case file exists
    if [ ! -f "${testcase_file}" ]; then
        log_error "Test case file does not exist: ${testcase_file}"
        return 1
    fi
    
    # Reset per-testcase optional variables so that values set by a previously
    # sourced test case (e.g. POLICY_KIND from a cluster-scoped test) do not
    # leak into the next one when running with --all.
    unset POLICY_KIND

    # Load test case configuration
    source "${testcase_file}"
    
    # Verify if necessary variables are defined
    if [ -z "${TEST_NAME}" ] || [ -z "${POLICY_FILES}" ] || [ -z "${WORKLOAD_FILES}" ]; then
        log_error "Test case configuration is incomplete, please check: ${testcase_file}"
        return 1
    fi
    
    return 0
}

# Apply policy
apply_policy() {
    local policy_file=$1
    log_info "Applying the policy: ${policy_file}"
    
    # `kubectl apply` is idempotent, so retry it on transient failures
    # (network blips, apiserver 5xx, etc.) and fail if it never succeeds.
    retry ${KUBECTL_CMD} apply -f "${policy_file}"
    if [ $? -ne 0 ]; then
        log_error "Failed to apply the policy ${policy_file}."
        return 1
    fi
    
    # Wait for policy to take effect
    sleep 5
    
    # Verify if policy is ready
    log_info "Waiting for the policy to be ready..."

    # POLICY_KIND defaults to the namespaced VarmorPolicy. Cluster-scoped
    # policies (VarmorClusterPolicy) are not bound to a namespace, so they
    # must be waited on without the `-n` flag. `kubectl wait` already has its
    # own --timeout, so it is not retried.
    local policy_kind="${POLICY_KIND:-VarmorPolicy}"
    if [ "${policy_kind}" = "VarmorClusterPolicy" ]; then
        ${KUBECTL_CMD} wait --for=condition=Ready ${policy_kind} ${POLICY_NAME} --timeout=30s
    else
        ${KUBECTL_CMD} wait --for=condition=Ready ${policy_kind} -n ${NAMESPACE} ${POLICY_NAME} --timeout=30s
    fi
    if [ $? -ne 0 ]; then
        log_error "The policy ${POLICY_NAME} is not ready after 30s."
        return 1
    fi

    return 0
}

# Deploy workload
deploy_workload() {
    local workload_file=$1

    log_info "Deploying the workload: ${workload_file}"
    # `kubectl apply` is idempotent, so retry it on transient failures.
    retry ${KUBECTL_CMD} apply -f "${workload_file}"
    if [ $? -ne 0 ]; then
        log_error "Failed to deploy the workload ${workload_file}."
        return 1
    fi

    log_info "Waiting for the workload to be ready..."
    # Two-phase wait. `kubectl wait` fails immediately with
    # "no matching resources found" if the selector matches zero Pods at the
    # instant it runs. Right after `apply`, the Deployment exists but its Pod
    # may not have been created yet (the vArmor mutating webhook lengthens the
    # admission path), so poll until at least one Pod appears before waiting on
    # its readiness. This removes a race that surfaces intermittently and is
    # more pronounced on newer Kubernetes releases.
    local appeared=0
    for _ in $(seq 1 30); do
        if [ "$(${KUBECTL_CMD} get pod -l ${POD_SELECTOR} -n ${NAMESPACE} --no-headers 2>&1 | grep -c .)" -gt 0 ]; then
            appeared=1
            break
        fi
        sleep 2
    done
    if [ "${appeared}" -ne 1 ]; then
        log_error "No Pod matched selector ${POD_SELECTOR} in namespace ${NAMESPACE} after 60s."
        return 1
    fi

    # `kubectl wait` already has its own --timeout, so it is not retried.
    ${KUBECTL_CMD} wait --for=condition=Ready pod -l ${POD_SELECTOR} -n ${NAMESPACE} --timeout=60s
    if [ $? -ne 0 ]; then
        log_error "The workload is not ready after 60s."
        return 1
    fi
    return 0
}

# Execute command
execute_command() {
    local pod_name=$1
    local container=$2
    local command=$3
    local expected_result=$4
    
    log_info "Executing command in container ${container}: ${command}"
    
    # Execute command and capture output and exit status
    local output=""
    local status=0
    
    # Wrap in `sh -c` so commands using pipes, redirects or quoting
    # (e.g. `curl ... | grep -q ...`) are interpreted by a shell in the
    # container rather than exec'd as a single argv. Single commands such as
    # `cat <path>` behave identically, so this is backward compatible.
    output=$(${KUBECTL_CMD} exec -n ${NAMESPACE} ${pod_name} -c ${container} -- sh -c "${command}" 2>&1)
    status=$?
    
    # 在控制台输出命令执行结果
    echo -e "${YELLOW}Command Output:${NC}"
    echo "${output}"
    echo -e "${YELLOW}Exit Status:${NC} ${status}"
    
    # Record command execution results
    echo "Command: ${command}" >> "${RESULTS_DIR}/${TEST_NAME}.log"
    echo "Output: ${output}" >> "${RESULTS_DIR}/${TEST_NAME}.log"
    echo "Status code: ${status}" >> "${RESULTS_DIR}/${TEST_NAME}.log"
    return ${status}
}

# Verify result
verify_result() {
    local status=$1
    local expected_status=$2
    local test_name=$3
    
    if [ ${status} -eq ${expected_status} ]; then
        log_success "Test Passed: ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS+1))
        return 0
    else
        log_error "Test Failed: ${test_name}"
        log_error "Expected status: ${expected_status}, Actual status: ${status}"
        FAILED_TESTS=$((FAILED_TESTS+1))
        return 1
    fi
}

# Run a single test case
run_testcase() {
    log_info "---------------------------------------------"
    local testcase_file=$1
    TOTAL_TESTS=$((TOTAL_TESTS+1))
    
    # Load test case
    load_testcase "${testcase_file}" || return 1
    
    log_info "Test Name: ${TEST_NAME}"

    # Create test namespace
    ${KUBECTL_CMD} create namespace ${NAMESPACE} 2>/dev/null
    
    # Apply the initial policy. If any policy fails to become ready the test
    # environment is broken, so fail fast: a later `kubectl exec` against a
    # missing/not-ready container would also exit non-zero and could
    # accidentally match a VERIFY_EXPECTED_STATUS=1 case, yielding a false pass.
    for policy_file in ${POLICY_FILES}; do
        apply_policy "${policy_file}"
        if [ $? -ne 0 ]; then
            log_error "Test setup failed while applying policy ${policy_file}; marking test as failed."
            FAILED_TESTS=$((FAILED_TESTS+1))
            cleanup_testcase
            return 1
        fi
    done
    
    # Deploy workload. Same rationale: if the workload never becomes ready, do
    # not proceed to verification, otherwise a broken environment could be
    # reported as a pass.
    for workload_file in ${WORKLOAD_FILES}; do
        deploy_workload "${workload_file}"
        if [ $? -ne 0 ]; then
            log_error "Test setup failed while deploying workload ${workload_file}; marking test as failed."
            FAILED_TESTS=$((FAILED_TESTS+1))
            cleanup_testcase
            return 1
        fi
    done
    
    # Get Pod name
    POD_NAME=$(${KUBECTL_CMD} get pods -n ${NAMESPACE} -l ${POD_SELECTOR} -o jsonpath='{.items[0].metadata.name}')
    if [ -z "${POD_NAME}" ]; then
        log_error "Test setup failed: no pod found for selector ${POD_SELECTOR} in namespace ${NAMESPACE}; marking test as failed."
        FAILED_TESTS=$((FAILED_TESTS+1))
        cleanup_testcase
        return 1
    fi
    
    # Execute initial command and verify result
    execute_command "${POD_NAME}" "${CONTAINER_NAME}" "${INITIAL_COMMAND}" "${INITIAL_EXPECTED_STATUS}"
    initial_status=$?
    
    # Apply the enhanced policy
    for policy_file in ${ENHANCED_POLICY_FILES}; do
        apply_policy "${policy_file}"
        if [ $? -ne 0 ]; then
            log_error "Test setup failed while applying enhanced policy ${policy_file}; marking test as failed."
            FAILED_TESTS=$((FAILED_TESTS+1))
            cleanup_testcase
            return 1
        fi
    done

    # Execute verification command and verify result
    execute_command "${POD_NAME}" "${CONTAINER_NAME}" "${VERIFY_COMMAND}" "${VERIFY_EXPECTED_STATUS}"
    verify_status=$?
    echo "verify_status: ${verify_status}"

    # Verify final result
    verify_result ${verify_status} ${VERIFY_EXPECTED_STATUS} "${TEST_NAME}"
    
    # Clean up test resources
    cleanup_testcase
}

# Clean up the resources created by the current test case. Honours
# CLEANUP_AFTER_TEST and is safe to call from the setup fail-fast paths as
# well as from the normal end-of-test flow.
cleanup_testcase() {
    if [ "${CLEANUP_AFTER_TEST}" = "true" ]; then
        log_info "Cleaning up test resources"
        for policy_file in ${POLICY_FILES} ${ENHANCED_POLICY_FILES}; do
            ${KUBECTL_CMD} delete -f "${policy_file}" 2>/dev/null || true
        done
        
        for workload_file in ${WORKLOAD_FILES}; do
            ${KUBECTL_CMD} delete -f "${workload_file}" 2>/dev/null || true
        done
    fi
}

# Run all test cases
run_all_testcases() {
    log_info "Starting to run all test cases"
    
    # Find all test case files
    for testcase_file in "${TEST_CASES_DIR}"/*.sh; do
        run_testcase "${testcase_file}"
    done
    
    # Output test result summary
    log_info "========================= Summary ========================="
    log_info "Total tests: ${TOTAL_TESTS}"
    log_success "Passed tests: ${PASSED_TESTS}"
    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "Failed tests: ${FAILED_TESTS}"
    fi
    
    # Return test result
    if [ ${FAILED_TESTS} -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Show help information
show_help() {
    echo "vArmor E2E Test Framework"
    echo ""
    echo "Usage: $0 [options] [test_case_file]"
    echo ""
    echo "Options:"
    echo "  -h, --help                   Show help information"
    echo "  -a, --all                    Run all test cases"
    echo "  -c, --cleanup                Clean up resources after test"
    echo "  -n, --namespace              Specify test namespace (default: demo)"
    echo "  -k, --kubectl                Specify kubectl command (default: k3s kubectl)"
    echo "  -s, --skip-varmor-ready      Skip waiting for vArmor to be ready"
    echo ""
    echo "Examples:"
    echo "  $0 --all                     Run all test cases"
    echo "  $0 testcases/apparmor.sh     Run specific test case"
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -a|--all)
                RUN_ALL=true
                shift
                ;;
            -c|--cleanup)
                CLEANUP_AFTER_TEST=true
                shift
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -k |--kubectl)
                KUBECTL_CMD="$2"
                shift 2
                ;;
            -s|--skip-varmor-ready)
                SKIP_VARMOR_READY=true
                shift
                ;;
            *)
                TESTCASE_FILE="$1"
                shift
                ;;
        esac
    done
    
    # Set default values
    RUN_ALL=${RUN_ALL:-false}
    CLEANUP_AFTER_TEST=${CLEANUP_AFTER_TEST:-false}
    
    # Temporarily disable set -e to ensure that test failures do not cause the script to exit
    set +e

    if [ "${SKIP_VARMOR_READY}" != "true" ]; then
        # Wait for vArmor to be ready
        wait_for_varmor_ready || return 1
    fi

    # Initialize test environment
    init_test_env
    
    # Run tests
    if [ "${RUN_ALL}" = "true" ]; then
        run_all_testcases
        test_result=$?
    elif [ -n "${TESTCASE_FILE}" ]; then
        run_testcase "${TESTCASE_FILE}"
        test_result=$?
    else
        show_help
        exit 1
    fi
    
    # Re-enable set -e
    set -e
    
    # Exit according to the test results
    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "${FAILED_TESTS} test cases failed"
        exit 1
    else
        log_success "All test cases passed successfully"
        exit 0
    fi
}

# Execute main function
main "$@"
