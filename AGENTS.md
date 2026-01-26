# vArmor Agent Development Guide

This file provides essential information for agentic coding tools working on the vArmor codebase.

## Build, Lint, and Test Commands

### Building
- `make build` - Full build including manifests, code generation, eBPF compilation, and binary
- `make local` - Build local binary only (faster for development)
- `make manifests` - Generate CRD manifests
- `make generate` - Generate DeepCopy and other boilerplate code
- `make build-ebpf` - Generate eBPF code and libraries
- `make copy-ebpf` - Copy compiled eBPF artifacts to pkg directories

### Development Workflow
1. **Build the binary**:
   - `make build` - Rebuild everything if CRDs or eBPF code were modified
   - `make local` - Build binary only when Go code was modified
2. **Install necessary CRDs, resources, etc.**:
   - `./scripts/deploy_resources.sh test`
3. **Run manager and agent locally**:
   - `sudo ./bin/vArmor -kubeconfig=./varmor-manager.kubeconfig -v 3`
   - `sudo ./bin/vArmor -agent -kubeconfig=./varmor-agent.kubeconfig -v 3`

### Linting and Formatting
- `make fmt` - Format code with `go fmt` and `goimports -w ./`
- `make vet` - Run `go vet ./...` for static analysis

### Testing
- `make test` - Run full test suite (includes manifests, generate, fmt, vet, test-unit)
- `make test-unit` - Run unit tests with coverage profile
- **Run single test**: `go test ./path/to/package -run TestFunctionName`
- **Run tests in package**: `go test ./path/to/package`
- **Run tests with verbose output**: `go test -v ./path/to/package`

## Code Style Guidelines

### File Structure and Licensing
- All source files must begin with Apache 2.0 license header
- Use standard copyright format: `// Copyright 202X vArmor Authors`
- Package comments should describe the package's purpose: `// Package <name> implements...`

### Import Organization
- Group imports in three sections: standard library, third-party, internal packages
- Use blank lines between groups
- Keep imports sorted alphabetically within groups
- Use descriptive aliases for internal packages (e.g., `varmor "github.com/bytedance/vArmor/apis/varmor/v1beta"`)

### Naming Conventions
- **Packages**: Lowercase, single word (e.g., `policy`, `audit`, `utils`)
- **Exported types**: PascalCase (e.g., `PolicyController`, `Auditor`, `ContainerInfo`)
- **Exported functions**: PascalCase (e.g., `NewPolicyController`, `ValidateAddPolicy`)
- **Unexported functions**: camelCase (e.g., `syncHandler`, `processEvent`)
- **Constants**: PascalCase for exported, camelCase for package-level
- **Variables**: camelCase, use descriptive names (e.g., `kubeClient`, `vpInformer`)

### Type Definitions
- Use explicit types with clear purposes
- Struct fields should have JSON/YAML tags for serialization
- Use pointer types for optional struct fields
- Define custom types for domain concepts (e.g., `EgressInfo`, `BpfEvent`)

### Error Handling
- Always return errors explicitly, never ignore them
- Use `fmt.Errorf` with descriptive error messages
- Wrap errors with context using `fmt.Errorf("context: %w", err)`
- Check for nil before dereferencing pointers
- Use k8s errors package for Kubernetes-specific errors: `k8errors.IsNotFound(err)`

### Logging
- Use `logr.Logger` for structured logging throughout the codebase
- Pass logger as struct field for consistency
- Use log levels appropriately: `log.Info()`, `log.Error()`, `log.Debug()`
- For audit logging, use `zerolog.Logger` (e.g., in pkg/auditor)

### Testing Patterns
- Use `github.com/stretchr/testify/assert` for assertions
- Test function naming: `Test<FunctionName>_<Scenario>` (e.g., `TestValidateAddPolicy_ValidVarmorPolicy`)
- Table-driven tests for multiple scenarios
- Use t.Run() for subtests with descriptive names
- Test both success and failure cases
- Mock Kubernetes clients using fake clientset from `pkg/client/clientset/versioned/fake`

### Kubernetes Patterns
- Follow controller-runtime patterns for controllers
- Use informers and listers for efficient caching
- Use workqueue for rate-limited reconciliation
- Implement proper finalizers for resource cleanup
- Use metav1.ObjectMeta for metadata fields
- Handle resource versioning for optimistic concurrency

### Concurrency
- Use `sync.RWMutex` for protecting shared data structures
- Use channels for communication between goroutines
- Buffered channels with reasonable sizes (e.g., `make(chan T, 100)`)
- Use `sync/atomic` for simple counters and flags
- Always close channels when done to prevent goroutine leaks

### eBPF Integration
- eBPF code is in `vArmor-ebpf/` directory (separate repo)
- Compiled eBPF artifacts are copied to `pkg/processtracer/` and `pkg/lsm/bpfenforcer/`
- Use `github.com/cilium/ebpf` for eBPF program management
- Map operations should handle errors gracefully

### Constants and Configuration
- Define package-level constants for magic numbers and strings
- Use descriptive names for constants (e.g., `maxRetries`, `logDirectory`)
- Configuration should be loaded from command-line flags or environment variables

### Comment Guidelines
- Exported functions must have godoc comments
- Use present tense: "ValidateAddPolicy validates..." not "Validates..."
- Include parameter and return value descriptions
- Keep comments concise and accurate
- Avoid commenting obvious code; comment "why" not "what"

## Project-Specific Notes

### Policy Modes
- **AlwaysAllow**: No mandatory access control rules are imposed on container
- **RuntimeDefault**: Basic protection provided by using the default profile of containerd (cri-containerd.apparmor.d and seccomp_default)
- **EnhanceProtect**: 
  - Predefined Built-in Rules ready to use out of the box
  - Tailor protection policies to specific requirements via customizable interfaces
  - Support Alarm-Only and Alarm-Interception modes for monitoring and auditing
  - Generate AppArmor/BPF profiles based on RuntimeDefault or AlwaysAllow modes
- **BehaviorModeling** (Experimental):
  - Uses BPF and audit technologies to perform behavior modeling across workloads
  - Behavior models are stored in the corresponding ArmorProfileModel object
  - Only supported by AppArmor and Seccomp enforcers
- **DefenseInDepth** (Experimental):
  - Provide Deny-by-Default protection via the behavior model or custom profiles
  - Provide custom rule interfaces and alarm-only mode to develop and manage profiles
  - BPF enforcer support is under development (🏗️)

### Enforcers
- **AppArmor**: File access control, process execution control
- **BPF**: LSM hooks for syscall filtering, network access control, ptrace control, mount control
- **Seccomp**: Syscall filtering
- **Combinations** (can use individually or in combination):
  - AppArmorBPF
  - AppArmorSeccomp
  - BPFSeccomp
  - AppArmorBPFSeccomp

### Built-in Rules Categories
- **Hardening**:
  - Securing Privileged Containers (procfs/cgroupfs protection, mount restrictions, capability management)
  - Disable Capabilities (disable all, disable privileged, disable specific capabilities)
  - Blocking Exploit Vectors (user namespace abuse, eBPF loading restrictions, userfaultfd)
- **Attack Protection**:
  - Mitigating Information Leakage (SA token, disk device numbers, overlayfs paths, host IP, metadata service)
  - Disable Sensitive Operations (writing to /etc, shell creation, wget/curl/chmod/su-sudo execution)
  - Others (network restrictions, kube-apiserver access, container runtime socket access)
- **Vulnerability Mitigation**:
  - cgroups & lxcfs escape mitigation
  - runc override mitigation (CVE-2019-5736)
  - Dirty Pipe mitigation (CVE-2-2022-0847)
  - IngressNightmare mitigation (CVE-2025-1974)

### Target Workloads
- Supported kinds: Deployment, StatefulSet, DaemonSet, Pod
- Target can be specified by name or label selector (exclusive)
- Namespace-scoped: VarmorPolicy
- Cluster-scoped: VarmorClusterPolicy

### Important Paths
- Controllers: `internal/policy/`, `internal/webhooks/`, `internal/agent/`
- Profile builders: `internal/profile/`
- eBPF enforcers: `pkg/lsm/bpfenforcer/`, `pkg/processtracer/`
- Audit: `pkg/auditor/`
- CRD definitions: `apis/varmor/v1beta1/`
- Generated client: `pkg/client/`
