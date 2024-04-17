#!/bin/bash

set +e  # 允许脚本在命令失败时继续执行
sudo ctr images list
docker images
sudo k3s ctr images list
# AppArmor 测试流程
echo "AppArmor 测试开始"
sleep 60
k3s kubectl get pods -n varmor -o yaml
k3s kubectl create namespace demo
k3s kubectl create -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
echo "sleep 1 minute..."
sleep 60
k3s kubectl get VarmorPolicy -n demo
k3s kubectl get ArmorProfile -n demo
k3s kubectl create -f test/demo/1-apparmor/deploy.yaml

sleep 30

POD_NAME=$(kubectl get Pods -n demo -l app=demo-1 -o jsonpath='{.items[0].metadata.name}')
k3s kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token || true

k3s kubectl apply -f test/demo/1-apparmor/vpol-apparmor-enhance.yaml

sleep 30
echo "sleep 30 seconds..."

k3s kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token > /dev/null 2>&1
status=$?

if [ $status -ne 0 ]; then
  echo "AppArmor 测试成功"
else
  echo "AppArmor 测试失败"
fi

k3s kubectl delete -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
k3s kubectl delete -f test/demo/1-apparmor/deploy.yaml

# eBPF 测试流程
echo "eBPF 测试开始"
k3s kubectl create -f test/demo/2-bpf/vpol-bpf-alwaysallow.yaml
echo "sleep 1 minute..."
sleep 60
k3s kubectl get VarmorPolicy -n demo
k3s kubectl get ArmorProfile -n demo

k3s kubectl create -f test/demo/2-bpf/deploy.yaml

sleep 30

POD_NAME=$(k3s kubectl get Pods -n demo -l app=demo-2 -o jsonpath='{.items[0].metadata.name}')
k3s kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token || true

k3s kubectl apply -f test/demo/2-bpf/vpol-bpf-enhance.yaml

sleep 30
echo "sleep 30 seconds..."
k3s kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token > /dev/null 2>&1
status=$?

if [ $status -ne 0 ]; then
  echo "eBPF 测试成功"
else
  echo "eBPF 测试失败"
fi

k3s kubectl delete -f test/demo/2-bpf/vpol-bpf-alwaysallow.yaml
k3s kubectl delete -f test/demo/2-bpf/deploy.yaml
