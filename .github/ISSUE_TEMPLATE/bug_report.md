---
name: Bug report
about: Create a report to help us improve
title: "[BUG]"
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**Environment Information**
Please use the below commands to retrieve the necessary information.
```
# Access to cluster and retrieve the versions
kubectl get Nodes -o wide && kubectl version
# Login to the node and check the enabled LSM
cat /sys/kernel/security/lsm
```
- vArmor: [e.g. v0.5.6]
- Kubernetes: [e.g. v1.25.15]
- contained: [e.g. containerd://1.7.5-1]
- OS: [e.g. Ubuntu 22.04.3 LTS]
- Kernel: [e.g. 5.15.0-1051-azure]
- LSM status: [e.g. lockdown,capability,landlock,yama,apparmor,bpf]

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Additional context**
Add any other context about the problem here.
