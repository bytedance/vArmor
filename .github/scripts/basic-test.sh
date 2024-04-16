#!/bin/bash

set +e  # 允许脚本在命令失败时继续执行

# AppArmor 测试流程
echo "AppArmor 测试开始"
sleep 60
kubectl get pods -n varmor -o yaml
kubectl create namespace demo
kubectl create -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
echo "sleep 1 minute..."
sleep 60
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo
kubectl create -f test/demo/1-apparmor/deploy.yaml

sleep 30

POD_NAME=$(kubectl get Pods -n demo -l app=demo-1 -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token || true

kubectl apply -f test/demo/1-apparmor/vpol-apparmor-enhance.yaml

sleep 30
echo "sleep 30 seconds..."

kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token || true

if [ $? -ne 0 ]; then
  echo "AppArmor 测试成功"
else
  echo "AppArmor 测试失败"
fi

kubectl delete -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
kubectl delete -f test/demo/1-apparmor/deploy.yaml

# eBPF 测试流程
echo "eBPF 测试开始"
kubectl create -f test/demo/2-bpf/vpol-bpf-alwaysallow.yaml
echo "sleep 1 minute..."
sleep 60
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo

kubectl create -f test/demo/2-bpf/deploy.yaml

sleep 30

POD_NAME=$(kubectl get Pods -n demo -l app=demo-2 -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token || true

kubectl apply -f test/demo/2-bpf/vpol-bpf-enhance.yaml

sleep 30
echo "sleep 30 seconds..."
kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token || true

if [ $? -ne 0 ]; then
  echo "eBPF 测试成功"
else
  echo "eBPF 测试失败"
fi

kubectl delete -f test/demo/2-bpf/vpol-bpf-alwaysallow.yaml
kubectl delete -f test/demo/2-bpf/deploy.yaml
