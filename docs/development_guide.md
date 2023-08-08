# Development Guide
### Step 1. Build the binary
```
// You must rebuild everything if the CRDs or eBPF code were modified
make build

// Build the binary only when the Golang code has been modified
make local
```

### Step 2. Install the necessary CRDs, resources etc.
```
./scripts/deploy_resources.sh test
```

### Step 3. Run manager and agent locally
```
sudo ./bin/vArmor -kubeconfig=./varmor-manager.kubeconfig -v 3
sudo ./bin/vArmor -agent -kubeconfig=./varmor-agent.kubeconfig -v 3
```
