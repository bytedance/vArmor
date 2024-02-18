#!/bin/bash
kubectl create namespace demo
kubectl create -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo
echo "sleep 1 minute..."
sleep 60
kubectl create -f test/demo/1-apparmor/deploy.yaml

POD_NAME=$(kubectl get Pods -n demo -l app=demo-1 -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

kubectl apply -f test/demo/1-apparmor/vpol-apparmor-enhance.yaml

sleep 5

kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

if [ $? -ne 0 ]; then
  echo "apparmor basic validate success"
else
  echo "apparmor basic validate error!"
  exit 1
fi
kubectl delete -f test/demo/1-apparmor/vpol-apparmor-alwaysallow.yaml
kubectl delete -f test/demo/1-apparmor/deploy.yaml

# start ebpf basic test
kubectl create -f test/demo/2-bpf/vpol-bpf-alwaysallow.yaml
kubectl get VarmorPolicy -n demo
kubectl get ArmorProfile -n demo

kubectl create -f test/demo/2-bpf/deploy.yaml

POD_NAME=$(kubectl get Pods -n demo -l app=demo-2 -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

kubectl apply -f test/demo/2-bpf/vpol-bpf-enhance.yaml

sleep 5

kubectl exec -n demo $POD_NAME -c c1 -- cat /run/secrets/kubernetes.io/serviceaccount/token

if [ $? -ne 0 ]; then
  echo "apparmor basic validate success"
else
  echo "apparmor basic validate error!"
  exit 1
fi
kubectl delete -f test/demo/2-bpf/vpol-bpf-alwaysallow.yaml
kubectl delete -f test/demo/2-bpf/deploy.yaml