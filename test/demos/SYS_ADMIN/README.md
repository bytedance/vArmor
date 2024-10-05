# Demonstration Process

## 1. Set up a testing environment.
```
kubectl create -f test/demo/vulnerability-mitigation/SYS_ADMIN/sys-admin-app.yaml
```

## 2. Remount procfs then modify the core_pattern in the container.
```
pod_name=$(kubectl get Pods -n demo -l app=sys-admin-app -o jsonpath='{.items[0].metadata.name}') && echo $pod_name
kubectl exec -n demo $pod_name -it -- /bin/sh
cat /proc/sys/kernel/core_pattern
echo 1 > /proc/sys/kernel/core_pattern
mkdir /tmp/proc && mount -t proc tmpproc /tmp/proc
echo 1 > /tmp/proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern
umount /tmp/proc

umount /proc/sys
echo 2 > /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern
```

## 3. Update the policy
```
kubectl create -f test/demo/vulnerability-mitigation/SYS_ADMIN/hardening-policy.yaml
```

## 4. Repeat step 2

![image](SYS_ADMIN.gif)