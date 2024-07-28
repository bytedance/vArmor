#!/bin/bash

NAMESPACE="test"
POD_NAME="unixbench-pod"
CONFIG_DIR="./bench"
RESULTS_DIR="./unix_results"

create_pod() {
    local pod_file=$1
    kubectl apply -f ${CONFIG_DIR}/${pod_file} -n ${NAMESPACE}
    kubectl wait --for=condition=Ready pod/${POD_NAME} -n ${NAMESPACE} --timeout=600s
}

delete_pod() {
    kubectl delete pod ${POD_NAME} -n ${NAMESPACE}
}

run_unixbench_tests() {
    local policy_name=$1
    local result_file="${RESULTS_DIR}/${policy_name}_unixbench_test_results.txt"
    #echo "### UnixBench Test Results for Policy: ${policy_name} ###" | tee -a ${result_file}
    echo "### UnixBench Test run ###" | tee -a ${result_file}
    kubectl exec -n ${NAMESPACE} ${POD_NAME} -- /app/UnixBench/Run | tee -a ${result_file}
    echo "### Completed UnixBench Test run ###" | tee -a ${result_file}
    
}

apply_policy_and_test() {
    local policy_file=$1
    local pod_file=$2
    local policy_name=$3
    echo "Applying policy ${policy_file}..." | tee -a "${RESULTS_DIR}/${policy_name}_unixbench_test_results.txt"
    kubectl apply -f ${policy_file} -n ${NAMESPACE}

    create_pod ${pod_file}
    run_unixbench_tests ${policy_name}
    delete_pod

    echo "Deleting policy ${policy_file}..." | tee -a "${RESULTS_DIR}/${policy_name}_unixbench_test_results.txt"
    kubectl delete -f ${policy_file} -n ${NAMESPACE}
}

main() {
    mkdir -p ${RESULTS_DIR}
    kubectl create namespace ${NAMESPACE} || true

    create_pod "unixbench-dp.yaml"
    echo "### Starting initial tests ###" | tee -a "${RESULTS_DIR}/initial_unixbench_test_results.txt"
    run_unixbench_tests "initial"
    echo "### Completed initial tests ###" | tee -a "${RESULTS_DIR}/initial_unixbench_test_results.txt"
    delete_pod

    apply_policy_and_test "policy/apparmor-always.yaml" "unixbench-dp.yaml" "apparmor_always"
    apply_policy_and_test "policy/apparmor-default.yaml" "unixbench-dp.yaml" "apparmor_default"
    apply_policy_and_test "policy/apparmor-enhance.yaml" "unixbench-dp.yaml" "apparmor_enhance"

    apply_policy_and_test "policy/seccomp-default.yaml" "unixbench-dp-noapparmor.yaml" "seccomp_default"

    apply_policy_and_test "policy/bpf-always.yaml" "unixbench-dp-noapparmor.yaml" "bpf_always"
    apply_policy_and_test "policy/bpf-default.yaml" "unixbench-dp-noapparmor.yaml" "bpf_default"
    apply_policy_and_test "policy/bpf-enhance.yaml" "unixbench-dp-noapparmor.yaml" "bpf_enhance"

    kubectl delete namespace ${NAMESPACE}
}

main
