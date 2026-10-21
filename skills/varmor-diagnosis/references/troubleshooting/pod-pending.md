# Pod Pending / ContainerCreating diagnosis guide

## Entry signals

Pod Pending or ContainerCreating with events/status involving Profiles, AppArmor, Seccomp, NetworkProxy, Secrets, sidecars, initContainers, or certificates.

## Rule out general Kubernetes causes first

Without vArmor Profile/injection/proxy evidence, prioritize scheduling, images, resources, PVCs, node taints, CNI, and other general causes. Do not force a vArmor attribution.

## vArmor investigation path

1. Is the Pod scheduled, and to which node?
2. Does it show AppArmor/Seccomp/BPF/NetworkProxy injection?
3. Does the policy still exist, and does `profileName` identify an AP?
4. Does AP contain a failed condition for that node?
5. Are the node agent, Profile loading, and kubelet/runtime healthy?
6. For NetworkProxy, inspect init, sidecar, Secret/certificates, resources, and ports.

## Typical scenarios

- **Profile not found**: Policy/AP exists but node resources are not prepared, or the Pod references an old/incorrect Profile;
- **Reference remains after policy deletion**: Residual annotations/SecurityContext in workload PodTemplate, bare Pod, or old Pod;
- **NetworkProxy init/sidecar failure**: Commonly redirection capabilities, Secret/certificates, resources, ports, or proxy readiness;
- **Pod created from an old template**: Policy updates or webhook recovery do not automatically modify old Pods.

Establish object ownership and affected scope before remediation recommendations; avoid directly deleting application Pods or weakening policies.
