---
slug: /guides/development
sidebar_position: 4
description: 如何设置本地开发环境。
---

# 本地开发
### 步骤 1. 编译二进制
```
// You must rebuild everything if the CRDs or eBPF code were modified
make build

// Build the binary only when the Golang code has been modified
make local
```

### 步骤 2. 安装所需的 CRD、资源等
```
./scripts/deploy_resources.sh test
```

### 步骤 3. 分别在本地运行 manager 和 agent
```
sudo ./bin/vArmor -kubeconfig=./varmor-manager.kubeconfig -v 3
sudo ./bin/vArmor -agent -kubeconfig=./varmor-agent.kubeconfig -v 3
```
