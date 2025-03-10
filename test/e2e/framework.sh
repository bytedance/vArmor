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
NAMESPACE="demo"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

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

# Initialize test environment
init_test_env() {
    log_info "Initializing test environment"
    
    # Create test namespace
    ${KUBECTL_CMD} create namespace ${NAMESPACE} 2>/dev/null || true
    
    # Create results directory
    mkdir -p "${RESULTS_DIR}"
    
    # Clean up previous test results
    rm -f "${RESULTS_DIR}"/*.log
}

# Clean up test environment
cleanup_test_env() {
    log_info "Cleaning up test environment"
    
    # Delete all test resources
    ${KUBECTL_CMD} delete varmorpholicy --all -n ${NAMESPACE} 2>/dev/null || true
    ${KUBECTL_CMD} delete deployment --all -n ${NAMESPACE} 2>/dev/null || true
    
    # Wait for resource deletion to complete
    sleep 10
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
    log_info "Applying policy: ${policy_file}"
    
    ${KUBECTL_CMD} apply -f "${policy_file}"
    
    # Wait for policy to take effect
    log_info "Waiting for policy to take effect..."
    sleep 10
    
    # Check policy status
    log_info "Checking policy status..."
    ${KUBECTL_CMD} get VarmorPolicy -n ${NAMESPACE}
    ${KUBECTL_CMD} get ArmorProfile -n ${NAMESPACE}
    
    # Verify policy status
    log_info "Verifying if policy is running properly..."
    local policy_status=$(${KUBECTL_CMD} get VarmorPolicy -n ${NAMESPACE} -o jsonpath='{.items[*].status.phase}')
    local profile_status_all_num=$(${KUBECTL_CMD} get ArmorProfile -n ${NAMESPACE} -o jsonpath='{.items[*].status.currentNumberLoaded}')
    local profile_status_cur_num=$(${KUBECTL_CMD} get ArmorProfile -n ${NAMESPACE} -o jsonpath='{.items[*].status.desiredNumberLoaded}')
    if [[ -z "${policy_status}" ]]; then
        log_error "VarmorPolicy resource not found"
        return 1
    fi
    
    # if [[ -z "${profile_status}" ]]; then
    #     log_error "ArmorProfile resource not found"
    #     return 1
    # fi
    
    if [[ "${policy_status}" != *"Protecting"* ]]; then
        log_error "VarmorPolicy status abnormal: ${policy_status}"
        ${KUBECTL_CMD} get VarmorPolicy -n ${NAMESPACE} -o yaml
        ${KUBECTL_CMD} get ArmorProfile -n ${NAMESPACE} -o yaml
        for pod in $(kubectl -n varmor get pods -l app.kubernetes.io/component=varmor-agent -o name); do
            echo "Logs for Pod: ${pod}"
            kubectl -n varmor logs ${pod}
            kubectl -n varmor get ${pod} -o yaml
        done
        return 1
    fi
    if [[ "${profile_status_all_num}" != "${profile_status_cur_num}" ]]; then
        log_error "ArmorProfile status abnormal: ${profile_status}"
        return 1
    fi
    
    log_success "Policy verification passed, status normal"
}

# Deploy workload
deploy_workload() {
    local workload_file=$1
    log_info "Deploying workload: ${workload_file}"
    
    ${KUBECTL_CMD} apply -f "${workload_file}"
    
    # Wait for workload to be ready
    log_info "Waiting for workload to be ready..."
    sleep 10
    
    # Verify deployment status
    local deployment_name=$(${KUBECTL_CMD} get -f "${workload_file}" -o jsonpath='{.metadata.name}' 2>/dev/null)
    if [[ -n "${deployment_name}" ]]; then
        log_info "Checking if deployment ${deployment_name} is ready..."
        local max_retries=10
        local retry_count=0
        local ready=false
        
        while [[ ${retry_count} -lt ${max_retries} && ${ready} == false ]]; do
            local replicas=$(${KUBECTL_CMD} get deployment ${deployment_name} -n ${NAMESPACE} -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")
            local ready_replicas=$(${KUBECTL_CMD} get deployment ${deployment_name} -n ${NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
            
            if [[ "${ready_replicas}" == "${replicas}" && "${replicas}" != "0" ]]; then
                ready=true
                log_success "Deployment ${deployment_name} is ready"
            else
                log_info "Deployment not ready yet (${ready_replicas}/${replicas}), waiting..."
                sleep 10
                retry_count=$((retry_count+1))
            fi
        done
        
        if [[ ${ready} == false ]]; then
            log_error "Deployment ${deployment_name} failed to become ready within timeout"
            return 1
        fi
    else
        log_info "Resource is not a deployment, skipping readiness check"
    fi
    
    # Additional wait to ensure everything is stable
    sleep 20
    
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
    
    output=$(${KUBECTL_CMD} exec -n ${NAMESPACE} ${pod_name} -c ${container} -- ${command} 2>&1)
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
        log_success "Test passed: ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS+1))
        return 0
    else
        log_error "Test failed: ${test_name}"
        log_error "Expected status: ${expected_status}, Actual status: ${status}"
        FAILED_TESTS=$((FAILED_TESTS+1))
        return 1
    fi
}

# Run a single test case
run_testcase() {
    local testcase_file=$1
    TOTAL_TESTS=$((TOTAL_TESTS+1))
    
    # Load test case
    load_testcase "${testcase_file}" || return 1
    
    log_info "Starting test execution: ${TEST_NAME}"
    
    # Apply initial policy
    for policy_file in ${POLICY_FILES}; do
        apply_policy "${policy_file}"
    done
    
    # Deploy workload
    for workload_file in ${WORKLOAD_FILES}; do
        deploy_workload "${workload_file}"
    done
    
    # Get Pod name
    POD_NAME=$(${KUBECTL_CMD} get pods -n ${NAMESPACE} -l ${POD_SELECTOR} -o jsonpath='{.items[0].metadata.name}')
    
    # Execute initial command and verify result
    execute_command "${POD_NAME}" "${CONTAINER_NAME}" "${INITIAL_COMMAND}" "${INITIAL_EXPECTED_STATUS}"
    initial_status=$?
    
    # Apply enhanced policy
    for policy_file in ${ENHANCED_POLICY_FILES}; do
        apply_policy "${policy_file}"
    done
    
    # Wait for policy to take effect
    log_info "Waiting for enhanced policy to take effect..."
    sleep 10
    
    # Execute verification command and verify result
    execute_command "${POD_NAME}" "${CONTAINER_NAME}" "${VERIFY_COMMAND}" "${VERIFY_EXPECTED_STATUS}"
    verify_status=$?
    echo "verify_status: ${verify_status}"
    # Verify final result
    verify_result ${verify_status} ${VERIFY_EXPECTED_STATUS} "${TEST_NAME}"
    
    # Clean up test resources
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
    
    # Initialize test environment
    init_test_env
    
    # Find all test case files
    for testcase_file in "${TEST_CASES_DIR}"/*.sh; do
        run_testcase "${testcase_file}"
    done
    
    # Output test result summary
    log_info "Testing completed, result summary:"
    log_info "Total tests: ${TOTAL_TESTS}"
    log_success "Passed tests: ${PASSED_TESTS}"
    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "Failed tests: ${FAILED_TESTS}"
    fi

    
    # Clean up test environment
    cleanup_test_env
    
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
    echo "  -h, --help          Show help information"
    echo "  -a, --all           Run all test cases"
    echo "  -c, --cleanup       Clean up resources after test"
    echo "  -n, --namespace     Specify test namespace (default: demo)"
    echo "  -k, --kubectl       Specify kubectl command (default: k3s kubectl)"
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
            *)
                TESTCASE_FILE="$1"
                shift
                ;;
        esac
    done
    
    # Set default values
    RUN_ALL=${RUN_ALL:-false}
    CLEANUP_AFTER_TEST=${CLEANUP_AFTER_TEST:-false}
    
    # 临时禁用 set -e，确保测试失败不会导致脚本退出
    set +e
    
    # Run tests
    if [ "${RUN_ALL}" = "true" ]; then
        run_all_testcases
        test_result=$?
    elif [ -n "${TESTCASE_FILE}" ]; then
        init_test_env
        run_testcase "${TESTCASE_FILE}"
        test_result=$?
        cleanup_test_env
    else
        show_help
        exit 1
    fi
    
    # 重新启用 set -e
    set -e
    
    # 根据测试结果退出
    if [ ${FAILED_TESTS} -gt 0 ]; then
        log_error "测试完成，但有 ${FAILED_TESTS} 个测试用例失败"
        exit 1
    else
        log_success "所有测试用例均成功通过"
        exit 0
    fi
}

# Execute main function
main "$@"