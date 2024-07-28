#!/bin/bash

NAMESPACE="test"
POD_NAME="sysbench-pod"
CONFIG_DIR="./bench"
RESULTS_DIR="./sysbench_results"

create_pod() {
    local pod_file=$1
    kubectl apply -f ${CONFIG_DIR}/${pod_file} -n ${NAMESPACE}
    kubectl wait --for=condition=Ready pod/${POD_NAME} -n ${NAMESPACE} --timeout=60s
}

delete_pod() {
    kubectl delete pod ${POD_NAME} -n ${NAMESPACE}
}

run_sysbench_cpu() {
    local policy_name=$1
    for i in {1..10}; do
        echo "### CPU Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_cpu_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench cpu --cpu-max-prime=20000 --threads=2 run >> "${RESULTS_DIR}/${policy_name}_cpu_test.txt"
        echo "### Completed CPU Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_cpu_test.txt"
    done
}

run_sysbench_memory() {
    local policy_name=$1
    for i in {1..10}; do
        echo "### Memory Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_memory_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench memory --threads=2 run >> "${RESULTS_DIR}/${policy_name}_memory_test.txt"
        echo "### Completed Memory Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_memory_test.txt"
    done
}

run_sysbench_fileio() {
    local policy_name=$1
    for i in {1..10}; do
        echo "### File IO Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_fileio_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench fileio --file-test-mode=rndrw --threads=2 prepare
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench fileio --file-test-mode=rndrw --threads=2 run >> "${RESULTS_DIR}/${policy_name}_fileio_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench fileio --file-test-mode=rndrw --threads=2 cleanup
        echo "### Completed File IO Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_fileio_test.txt"
    done
}

run_sysbench_threads() {
    local policy_name=$1
    for i in {1..10}; do
        echo "### Threads Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_threads_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench threads --threads=2 run >> "${RESULTS_DIR}/${policy_name}_threads_test.txt"
        echo "### Completed Threads Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_threads_test.txt"
    done
}

run_sysbench_mutex() {
    local policy_name=$1
    for i in {1..10}; do
				echo "### Mutex Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_mutex_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench mutex --threads=2 run >> "${RESULTS_DIR}/${policy_name}_mutex_test.txt"
				echo "### Completed Mutex Test run #$i ###"| tee -a "${RESULTS_DIR}/${policy_name}_mutex_test.txt"
    done
}

run_sysbench_db() {
    local policy_name=$1
    for i in {1..10}; do
        echo "### DB Test run #$i ###"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench /usr/share/sysbench/tests/include/oltp_legacy/oltp.lua --db-driver=mysql --mysql-db=test --mysql-user=root --mysql-password=password --threads=2 prepare
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench /usr/share/sysbench/tests/include/oltp_legacy/oltp.lua --db-driver=mysql --mysql-db=test --mysql-user=root --mysql-password=password --threads=2 run >> "${RESULTS_DIR}/${policy_name}_db_test.txt"
        kubectl exec -n ${NAMESPACE} ${POD_NAME} -- sysbench /usr/share/sysbench/tests/include/oltp_legacy/oltp.lua --db-driver=mysql --mysql-db=test --mysql-user=root --mysql-password=password --threads=2 cleanup
        echo "### Completed DB Test run #$i ###"
    done
}

apply_policy_and_test() {
    local policy_file=$1
    local pod_file=$2
    local policy_name=$3
    echo "Applying policy ${policy_file}..."
    kubectl apply -f ${policy_file} -n ${NAMESPACE}
		sleep 10
		kubectl get VarmorPolicy -n test
		kubectl get ArmorProfile -n test
    create_pod ${pod_file}
    run_sysbench_cpu ${policy_name}
    run_sysbench_memory ${policy_name}
    run_sysbench_fileio ${policy_name}
    run_sysbench_threads ${policy_name}
    run_sysbench_mutex ${policy_name}
    #run_sysbench_db ${policy_name}
    delete_pod

    echo "Deleting policy ${policy_file}..."
    kubectl delete -f ${policy_file} -n ${NAMESPACE}
}

main() {
    mkdir -p ${RESULTS_DIR}
    kubectl create namespace ${NAMESPACE} || true

    create_pod "sysbench-dp.yaml"
    echo "### Starting initial tests ###"
    run_sysbench_cpu "initial"
    run_sysbench_memory "initial"
    run_sysbench_fileio "initial"
    run_sysbench_threads "initial"
    run_sysbench_mutex "initial"
    #run_sysbench_db "initial"
    echo "### Completed initial tests ###"
    delete_pod

    apply_policy_and_test "policy/apparmor-always.yaml" "sysbench-dp.yaml" "apparmor_always"
    apply_policy_and_test "policy/apparmor-default.yaml" "sysbench-dp.yaml" "apparmor_default"
    apply_policy_and_test "policy/apparmor-enhance.yaml" "sysbench-dp.yaml" "apparmor_enhance"

    apply_policy_and_test "policy/seccomp-default.yaml" "sysbench-dp-noapparmor.yaml" "seccomp_default"

    apply_policy_and_test "policy/bpf-always.yaml" "sysbench-dp-noapparmor.yaml" "bpf_always"
    apply_policy_and_test "policy/bpf-default.yaml" "sysbench-dp-noapparmor.yaml" "bpf_default"
    apply_policy_and_test "policy/bpf-enhance.yaml" "sysbench-dp-noapparmor.yaml" "bpf_enhance"

    kubectl delete namespace ${NAMESPACE}
}

main
