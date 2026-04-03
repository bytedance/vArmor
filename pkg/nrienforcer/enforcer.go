package nrienforcer

import (
	"context"
	"fmt"
	"strings"
	"time"

	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	"github.com/containerd/containerd"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/go-logr/logr"
)

type NRIEnforcer struct {
	stub    stub.Stub
	opa     *Evaluator
	auditor *varmorauditor.Auditor
	log     logr.Logger
	client  *containerd.Client
}

func NewNRIEnforcer(opaEvaluator *Evaluator, auditor *varmorauditor.Auditor, log logr.Logger) (*NRIEnforcer, error) {
	client, err := containerd.New(varmortypes.RuntimeEndpoint, containerd.WithTimeout(2*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to create containerd client: %w", err)
	}

	return &NRIEnforcer{
		opa:     opaEvaluator,
		auditor: auditor,
		log:     log,
		client:  client,
	}, nil
}

// SyncPolicy updates the policy for a given profile.
func (p *NRIEnforcer) SyncPolicy(profileName string, builtinRules string, rawRules string, options Options, matchInfo PolicyMatchInfo) error {
	p.log.Info("SyncPolicy", "profile", profileName)
	return p.opa.UpdatePolicy(context.Background(), profileName, builtinRules, rawRules, options, matchInfo)
}

// DeletePolicy removes the policy for a given profile.
func (p *NRIEnforcer) DeletePolicy(profileName string) {
	p.log.Info("DeletePolicy", "profile", profileName)
	p.opa.DeletePolicy(profileName)
}

func (p *NRIEnforcer) Run(ctx context.Context) error {
	var opts []stub.Option
	opts = append(opts, stub.WithPluginName("varmor-nri-plugin"), stub.WithPluginIdx("00"))

	s, err := stub.New(p, opts...)
	if err != nil {
		return err
	}
	p.stub = s

	return p.stub.Run(ctx)
}

// Configure is called when the plugin is configured.
func (p *NRIEnforcer) Configure(ctx context.Context, config string, runtime string, version string) error {
	p.log.Info("Configured", "runtime", runtime, "version", version)
	return nil
}

// Synchronize is called when the plugin connects to the runtime.
func (p *NRIEnforcer) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	p.log.Info("Synchronized with runtime")
	return nil, nil
}

// Shutdown is called when the plugin is shutting down.
func (p *NRIEnforcer) Shutdown(ctx context.Context) {
	p.log.Info("Shutdown")
}

// RunPodSandbox is called when a pod sandbox is being run.
func (p *NRIEnforcer) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	return nil
}

// StopPodSandbox is called when a pod sandbox is being stopped.
func (p *NRIEnforcer) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	return nil
}

// RemovePodSandbox is called when a pod sandbox is being removed.
func (p *NRIEnforcer) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	return nil
}

// CreateContainer is called when a container is being created.
func (p *NRIEnforcer) CreateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	return nil, nil, nil
}

// StartContainer is called when a container is being started.
// This is where we hook in OPA.
func (p *NRIEnforcer) StartContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	p.log.Info("Processing StartContainer", "container", container.Name)

	input := Input{
		Pod:       pod,
		Container: container,
	}

	var containerImage string
	// Try to get container image from containerd
	image, err := p.getContainerImage(ctx, container)
	if err == nil {
		input.Image = image
		containerImage = image
		p.log.V(3).Info("Successfully retrieved container image", "container", container.Name, "image", input.Image)
	} else {
		p.log.V(3).Info("Failed to get container image", "container", container.Name, "error", err)
	}

	// Try to get OCI Spec from containerd client or filesystem
	spec, err := p.getOCISpec(ctx, container)
	if err == nil {
		p.log.V(3).Info("Successfully loaded OCI spec", "container", container.Name)
	} else {
		// Fallback: Construct partial spec from NRI api.Container if retrieval failed
		p.log.Error(err, "Failed to retrieve OCI spec, using partial spec from NRI", "container", container.Name)
		spec = populateInputSpec(container)
	}

	input.Spec = spec

	results, err := p.opa.Evaluate(ctx, input, pod)
	if err != nil {
		// System error during evaluation (unlikely with current Evaluate implementation which returns results with errors)
		p.log.Error(err, "OPA evaluation system error")
		return fmt.Errorf("OPA evaluation system error: %w", err)
	}

	return p.enforcePolicies(pod, container, containerImage, results)
}

func (p *NRIEnforcer) enforcePolicies(pod *api.PodSandbox, container *api.Container, image string, results []EvalResult) error {
	var blockErrors []string

	for _, res := range results {
		profileName := res.ProfileName

		if res.Error != nil {
			p.log.Error(res.Error, "Policy evaluation failed", "profile", profileName, "container", container.Name, "error", res.Error)

			msg := fmt.Sprintf("[%s] Policy evaluation error: %v", profileName, res.Error)

			switch res.Options.FailurePolicy {
			case "Fail":
				p.log.Error(res.Error, "Blocking container due to policy evaluation failure", "profile", profileName, "failurePolicy", "Fail")
				blockErrors = append(blockErrors, msg)
			case "Ignore":
				p.log.Info("Ignoring policy evaluation failure", "profile", profileName, "failurePolicy", "Ignore")
			default: // "Audit" or empty
				p.log.Error(res.Error, "Auditing policy evaluation failure", "profile", profileName, "failurePolicy", "Audit")
			}
		} else {
			p.log.V(3).Info("Policy evaluation succeeded", "profile", profileName, "container", container.Name)
		}

		// Handle Deny messages (Block only)
		if len(res.DenyMessages) > 0 {
			msg := fmt.Sprintf("[%s] Deny: %s", profileName, strings.Join(res.DenyMessages, "; "))
			p.log.Info("Policy rule matched - Deny", "profile", profileName, "container", container.Name, "messages", res.DenyMessages)

			if p.auditor != nil {
				p.auditor.LogNriEvent(
					pod.GetNamespace(),
					pod.GetName(),
					container.GetName(),
					container.GetId(),
					image,
					profileName,
					"StartContainer",
					msg,
					"Block",
				)
			}
			blockErrors = append(blockErrors, msg)
		}

		// Handle AuditDeny messages (Block + Alert)
		if len(res.AuditDenyMessages) > 0 {
			msg := fmt.Sprintf("[%s] AuditDeny: %s", profileName, strings.Join(res.AuditDenyMessages, "; "))
			p.log.Info("Policy rule matched - AuditDeny", "profile", profileName, "container", container.Name, "messages", res.AuditDenyMessages)

			if p.auditor != nil {
				p.auditor.LogNriEvent(
					pod.GetNamespace(),
					pod.GetName(),
					container.GetName(),
					container.GetId(),
					image,
					profileName,
					"StartContainer",
					msg,
					"Block", // Audit-Deny means Block and Alert
				)
			}
			blockErrors = append(blockErrors, msg)
		}

		// Handle AuditAllow messages (Alert only)
		if len(res.AuditAllowMessages) > 0 {
			msg := fmt.Sprintf("[%s] AuditAllow: %s", profileName, strings.Join(res.AuditAllowMessages, "; "))
			p.log.Info("Policy rule matched - AuditAllow", "profile", profileName, "container", container.Name, "messages", res.AuditAllowMessages)

			if p.auditor != nil {
				p.auditor.LogNriEvent(
					pod.GetNamespace(),
					pod.GetName(),
					container.GetName(),
					container.GetId(),
					image,
					profileName,
					"StartContainer",
					msg,
					"Audit",
				)
			}
		}
	}

	if len(blockErrors) > 0 {
		errMsg := fmt.Sprintf("Container %s denied: %s", container.Name, strings.Join(blockErrors, " | "))
		p.log.Info("Blocking container start", "container", container.Name, "reason", errMsg, "totalBlockReasons", len(blockErrors))
		return fmt.Errorf("%s", errMsg)
	}

	p.log.Info("Container allowed", "container", container.Name, "policiesEvaluated", len(results))
	return nil
}

// StopContainer is called when a container is being stopped.
func (p *NRIEnforcer) StopContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

// UpdateContainer is called when a container is being updated.
func (p *NRIEnforcer) UpdateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container, resources *api.LinuxResources) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

// PostUpdateContainer is called after a container has been updated.
func (p *NRIEnforcer) PostUpdateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container, resources *api.LinuxResources) error {
	return nil
}

// RemoveContainer is called when a container is being removed.
func (p *NRIEnforcer) RemoveContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	return nil
}
