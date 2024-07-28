#!/bin/bash

NAMESPACE="test"
POD_NAME="phoronix-pod"
CONFIG_DIR="./bench"
RESULTS_DIR="./phoronix_results"
PTS_RESULTS_DIR="/results"
create_pod() {
    local pod_file=$1
    kubectl apply -f ${CONFIG_DIR}/${pod_file} -n ${NAMESPACE}
    kubectl wait --for=condition=Ready pod/${POD_NAME} -n ${NAMESPACE} --timeout=600s
}

delete_pod() {
    kubectl delete pod ${POD_NAME} -n ${NAMESPACE}
}

run_phoronix_tests() {
    local policy_name=$1
    local result_file="${RESULTS_DIR}/${policy_name}_phoronix_test_results.txt"
    echo "### Phoronix Test Suite Results for Policy: ${policy_name} ###" | tee -a ${result_file}
  	echo "### Phoronix Test run  ###" | tee -a ${result_file}
		kubectl cp bench/combine-test.xml $NAMESPACE/$POD_NAME:/etc/phoronix-test-suite.xml
        kubectl exec -n $NAMESPACE -it $POD_NAME -- bash -c "
    apt update&&apt install -y  mailagent pkg-config libmysqlclient-dev"| sed 's/\x1b\[[0-9;]*m//g' | tee -a ${result_file}
		kubectl exec -n $NAMESPACE -it $POD_NAME -- bash -c "
    phoronix-test-suite/phoronix-test-suite install  sysbench redis apache gimp
"| sed 's/\x1b\[[0-9;]*m//g' | tee -a ${result_file}
	# 	kubectl exec -n $NAMESPACE -it $POD_NAME -- bash -c "
    # phoronix-test-suite/phoronix-test-suite batch-run sysbench redis apache gimp
    	kubectl exec -n $NAMESPACE -it $POD_NAME -- bash -c "
    phoronix-test-suite/phoronix-test-suite batch-run sysbench redis apache gimp
"| sed 's/\x1b\[[0-9;]*m//g' | tee -a ${result_file}
		kubectl cp $NAMESPACE/$POD_NAME:$PTS_RESULTS_DIR $RESULTS_DIR
    echo "### Completed Phoronix Test run  ###" | tee -a ${result_file}
}

apply_policy_and_test() {
    local policy_file=$1
    local pod_file=$2
    local policy_name=$3
    echo "Applying policy ${policy_file}..." | tee -a "${RESULTS_DIR}/${policy_name}_phoronix_test_results.txt"
    kubectl apply -f ${policy_file} -n ${NAMESPACE}

    create_pod ${pod_file}
    run_phoronix_tests ${policy_name}
    delete_pod

    echo "Deleting policy ${policy_file}..." | tee -a "${RESULTS_DIR}/${policy_name}_phoronix_test_results.txt"
    kubectl delete -f ${policy_file} -n ${NAMESPACE}
}

main() {
    mkdir -p ${RESULTS_DIR}
    kubectl create namespace ${NAMESPACE} || true

    create_pod "phoronix-dp-noapparmor.yaml"
    echo "### Starting initial tests ###" | tee -a "${RESULTS_DIR}/initial_phoronix_test_results.txt"
    run_phoronix_tests "initial"
    echo "### Completed initial tests ###" | tee -a "${RESULTS_DIR}/initial_phoronix_test_results.txt"
    delete_pod

    apply_policy_and_test "policy/apparmor-always.yaml" "phoronix-dp.yaml" "apparmor_always"
    apply_policy_and_test "policy/apparmor-default.yaml" "phoronix-dp.yaml" "apparmor_default"
    apply_policy_and_test "policy/apparmor-enhance.yaml" "phoronix-dp.yaml" "apparmor_enhance"
     apply_policy_and_test "policy/seccomp-default.yaml" "phoronix-dp-noapparmor.yaml" "seccomp_default"

    apply_policy_and_test "policy/bpf-always.yaml" "phoronix-dp-noapparmor.yaml" "bpf_always"
    apply_policy_and_test "policy/bpf-default.yaml" "phoronix-dp-noapparmor.yaml" "bpf_default"
    apply_policy_and_test "policy/bpf-enhance.yaml" "phoronix-dp-noapparmor.yaml" "bpf_enhance"

    kubectl delete namespace ${NAMESPACE}
}

main
