package nrienforcer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	varmortypes "github.com/bytedance/vArmor/pkg/types"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/nri/pkg/api"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Input defines the data structure passed to Rego policies.
type Input struct {
	// Pod is the pod sandbox being created.
	Pod *api.PodSandbox `json:"pod"`
	// Container is the container being created.
	Container *api.Container `json:"container"`
	// Spec is the OCI runtime spec of the container.
	Spec *specs.Spec `json:"spec"`
	// Image is the container image name (with tag)
	Image string `json:"image"`
}

// getOCISpec attempts to retrieve the OCI runtime spec for a container.
// It tries the containerd client first, then falls back to the filesystem.
func (p *NRIEnforcer) getOCISpec(ctx context.Context, container *api.Container) (*specs.Spec, error) {
	// 1. Try containerd client
	spec, err := p.loadSpecFromContainerd(ctx, container.Id)
	if err == nil {
		return spec, nil
	}
	p.log.V(3).Info("Failed to load OCI spec from containerd, trying filesystem", "container", container.Name, "error", err)

	// 2. Try filesystem fallback
	spec, err = p.loadSpecFromFilesystem(container.Id)
	if err == nil {
		return spec, nil
	}
	p.log.V(3).Info("Failed to load OCI spec from filesystem", "container", container.Name, "error", err)

	return nil, fmt.Errorf("failed to retrieve OCI spec for container %s", container.Id)
}

func (p *NRIEnforcer) loadSpecFromContainerd(ctx context.Context, containerID string) (*specs.Spec, error) {
	ctxWithNs := namespaces.WithNamespace(ctx, varmortypes.K8sCriNamespace)
	ctn, err := p.client.LoadContainer(ctxWithNs, containerID)
	if err != nil {
		return nil, err
	}
	return ctn.Spec(ctxWithNs)
}

func (p *NRIEnforcer) loadSpecFromFilesystem(containerID string) (*specs.Spec, error) {
	// Pattern: /run/containerd/io.containerd.runtime.v2.task/<namespace>/<container_id>/config.json
	configPath := filepath.Join("/run/containerd/io.containerd.runtime.v2.task", varmortypes.K8sCriNamespace, containerID, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}

	return &spec, nil
}

// populateInputSpec manually constructs a partial spec from api.Container as a last resort or for supplemental data.
func populateInputSpec(container *api.Container) *specs.Spec {
	spec := &specs.Spec{
		Process: &specs.Process{
			Args: container.Args,
			Env:  container.Env,
		},
		Mounts: []specs.Mount{},
	}

	if container.Linux != nil {
		spec.Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{},
		}

		if container.Linux.Resources != nil {
			spec.Linux.Resources = &specs.LinuxResources{
				CPU:    &specs.LinuxCPU{},
				Memory: &specs.LinuxMemory{},
			}
			if container.Linux.Resources.Cpu != nil {
				if container.Linux.Resources.Cpu.Shares != nil {
					val := uint64(container.Linux.Resources.Cpu.Shares.GetValue())
					spec.Linux.Resources.CPU.Shares = &val
				}
				if container.Linux.Resources.Cpu.Quota != nil {
					val := container.Linux.Resources.Cpu.Quota.GetValue()
					spec.Linux.Resources.CPU.Quota = &val
				}
				if container.Linux.Resources.Cpu.Period != nil {
					val := uint64(container.Linux.Resources.Cpu.Period.GetValue())
					spec.Linux.Resources.CPU.Period = &val
				}
			}
			if container.Linux.Resources.Memory != nil {
				if container.Linux.Resources.Memory.Limit != nil {
					val := container.Linux.Resources.Memory.Limit.GetValue()
					spec.Linux.Resources.Memory.Limit = &val
				}
			}
		}
	}

	for _, m := range container.Mounts {
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: m.Destination,
			Type:        m.Type,
			Source:      m.Source,
			Options:     m.Options,
		})
	}

	return spec
}

// getContainerImage attempts to retrieve the container image name from containerd.
func (p *NRIEnforcer) getContainerImage(ctx context.Context, container *api.Container) (string, error) {
	ctxWithNs := namespaces.WithNamespace(ctx, varmortypes.K8sCriNamespace)
	ctn, err := p.client.LoadContainer(ctxWithNs, container.Id)
	if err != nil {
		return "", fmt.Errorf("failed to load container: %w", err)
	}

	image, err := ctn.Image(ctxWithNs)
	if err != nil {
		return "", fmt.Errorf("failed to get image: %w", err)
	}

	return image.Name(), nil
}
