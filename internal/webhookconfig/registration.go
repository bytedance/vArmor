// This file may have been modified by vArmor Authors. ("vArmor Modifications").
// All vArmor Modifications are Copyright 2022 vArmor Authors.
//
// Copyright 2021 Kyverno Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webhookconfig implements the webhook register and cert manager for the admission webhook.
package webhookconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	adminformers "k8s.io/client-go/informers/admissionregistration/v1"
	admissionv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	admlisters "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	"github.com/bytedance/vArmor/internal/config"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	"github.com/bytedance/vArmor/pkg/workload"
)

// Register manages webhook registration.
type Register struct {
	clientConfig        *rest.Config
	mutateInterface     admissionv1.MutatingWebhookConfigurationInterface
	validateInterface   admissionv1.ValidatingWebhookConfigurationInterface
	secretInterface     corev1.SecretInterface
	deploymentInterface appsv1.DeploymentInterface
	leaseInterface      coordinationv1.LeaseInterface
	mwcLister           admlisters.MutatingWebhookConfigurationLister
	mwcListerSynced     func() bool
	vwcLister           admlisters.ValidatingWebhookConfigurationLister
	vwcListerSynced     func() bool
	managerIP           string
	timeoutSeconds      int32
	inContainer         bool
	stopCh              <-chan struct{}
	log                 logr.Logger
	registry            *workload.Registry
	adapterDefaults     map[string]workload.WebhookOptions
}

// NewRegister creates new Register instance
func NewRegister(
	clientConfig *rest.Config,
	mutateInterface admissionv1.MutatingWebhookConfigurationInterface,
	validateInterface admissionv1.ValidatingWebhookConfigurationInterface,
	secretInterface corev1.SecretInterface,
	deploymentInterface appsv1.DeploymentInterface,
	leaseInterface coordinationv1.LeaseInterface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	mwcInformer adminformers.MutatingWebhookConfigurationInformer,
	vwcInformer adminformers.ValidatingWebhookConfigurationInformer,
	managerIP string,
	webhookTimeout int32,
	inContainer bool,
	stopCh <-chan struct{},
	workloadRegistry *workload.Registry,
	log logr.Logger) *Register {

	register := &Register{
		clientConfig:        clientConfig,
		mutateInterface:     mutateInterface,
		validateInterface:   validateInterface,
		secretInterface:     secretInterface,
		deploymentInterface: deploymentInterface,
		leaseInterface:      leaseInterface,
		managerIP:           managerIP,
		timeoutSeconds:      webhookTimeout,
		inContainer:         inContainer,
		mwcLister:           mwcInformer.Lister(),
		mwcListerSynced:     mwcInformer.Informer().HasSynced,
		vwcLister:           vwcInformer.Lister(),
		vwcListerSynced:     vwcInformer.Informer().HasSynced,
		stopCh:              stopCh,
		log:                 log.WithName("Register"),
		registry:            workloadRegistry,
		adapterDefaults:     newAdapterDefaults(workloadRegistry, log),
	}

	return register
}

// Register reconciles the admission webhook configurations to the desired
// state without deleting them first, so there is no admission window in which
// the configuration is absent. It is safe to call repeatedly (e.g. after a
// leader transition or a hot-reload).
func (wrc *Register) Register(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	certProps, err := varmortls.GetTLSCertProps(wrc.clientConfig)
	if err != nil {
		return err
	}
	secretName := varmortls.GenerateRootCASecretName(certProps)
	secret, err := wrc.secretInterface.Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to extract CA data from %s secret: %w", secretName, err)
	}

	// The bundle carries both the previous and current root CAs during a CA
	// rotation, so the apiserver trusts either webhook leaf until the old CA
	// is retired.
	caData, err := varmortls.BuildCABundle(secret)
	if err != nil {
		return fmt.Errorf("unable to build CA bundle from %s secret: %w", secretName, err)
	}
	err = wrc.createResourceMutatingWebhookConfiguration(ctx, caData)
	if err != nil {
		return err
	}

	err = wrc.createPolicyValidatingWebhookConfiguration(ctx, caData)
	if err != nil {
		return err
	}

	return nil
}

// maxUpdateRetries bounds the optimistic-concurrency retries when reconciling
// a webhook configuration that another actor changed between Get and Update.
const maxUpdateRetries = 3

// Reconciliation retries use a standard wait.Backoff.
const (
	initialReconcileBackoff = time.Second
	maxReconcileBackoff     = 30 * time.Second
	reconcileBackoffSteps   = 30
)

func newReconcileBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: initialReconcileBackoff,
		Factor:   2.0,
		Cap:      maxReconcileBackoff,
		Steps:    reconcileBackoffSteps,
	}
}

// RunConfigReconciliation is owned by the elected leader. Failed writes retry
// via wait.Backoff; any config change immediately schedules the latest state.
func (wrc *Register) RunConfigReconciliation(ctx context.Context) {
	changes := config.DynamicConfigChanges()
	backoff := newReconcileBackoff()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}
		if err := wrc.Register(ctx); err != nil {
			wrc.log.Info("WARNING: webhook reconciliation failed; will retry", "error", err)
			timer.Reset(backoff.Step())
		} else {
			backoff = newReconcileBackoff()
			timer.Stop()
		}
	}
}

// upsertMutatingWebhookConfiguration creates cfg when absent, otherwise
// updates the live object's webhook entries in place. Conflicts are retried
// with a freshly fetched resourceVersion.
func (wrc *Register) upsertMutatingWebhookConfiguration(ctx context.Context, cfg *admissionregistrationapi.MutatingWebhookConfiguration) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	logger := wrc.log

	existing, err := wrc.mutateInterface.Get(ctx, cfg.Name, metav1.GetOptions{})
	if k8errors.IsNotFound(err) {
		_, cerr := wrc.mutateInterface.Create(ctx, cfg, metav1.CreateOptions{})
		if cerr == nil {
			logger.Info("MutatingWebhookConfiguration created", "name", cfg.Name)
			return nil
		}
		if !k8errors.IsAlreadyExists(cerr) {
			return cerr
		}
		existing, err = wrc.mutateInterface.Get(ctx, cfg.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	desiredWebhooks := normalizedMutatingWebhooks(cfg)
	for attempt := 0; attempt < maxUpdateRetries; attempt++ {
		if apiequality.Semantic.DeepEqual(normalizedMutatingWebhooks(existing), desiredWebhooks) &&
			apiequality.Semantic.DeepEqual(existing.Labels, cfg.Labels) &&
			apiequality.Semantic.DeepEqual(existing.Annotations, cfg.Annotations) {
			return nil
		}
		existing.Webhooks = cfg.Webhooks
		existing.Labels = cfg.Labels
		existing.Annotations = cfg.Annotations
		_, err = wrc.mutateInterface.Update(ctx, existing, metav1.UpdateOptions{})
		if err == nil {
			logger.Info("MutatingWebhookConfiguration updated", "name", cfg.Name)
			return nil
		}
		if !k8errors.IsConflict(err) {
			return err
		}
		if existing, err = wrc.mutateInterface.Get(ctx, cfg.Name, metav1.GetOptions{}); err != nil {
			return err
		}
	}
	return fmt.Errorf("failed to update MutatingWebhookConfiguration %q after %d retries", cfg.Name, maxUpdateRetries)
}

// upsertValidatingWebhookConfiguration is the create-or-update counterpart for
// the ValidatingWebhookConfiguration.
func (wrc *Register) upsertValidatingWebhookConfiguration(ctx context.Context, cfg *admissionregistrationapi.ValidatingWebhookConfiguration) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	logger := wrc.log

	existing, err := wrc.validateInterface.Get(ctx, cfg.Name, metav1.GetOptions{})
	if k8errors.IsNotFound(err) {
		_, cerr := wrc.validateInterface.Create(ctx, cfg, metav1.CreateOptions{})
		if cerr == nil {
			logger.Info("ValidatingWebhookConfiguration created", "name", cfg.Name)
			return nil
		}
		if !k8errors.IsAlreadyExists(cerr) {
			return cerr
		}
		existing, err = wrc.validateInterface.Get(ctx, cfg.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	desiredWebhooks := normalizedValidatingWebhooks(cfg)
	for attempt := 0; attempt < maxUpdateRetries; attempt++ {
		if apiequality.Semantic.DeepEqual(normalizedValidatingWebhooks(existing), desiredWebhooks) &&
			apiequality.Semantic.DeepEqual(existing.Labels, cfg.Labels) &&
			apiequality.Semantic.DeepEqual(existing.Annotations, cfg.Annotations) {
			return nil
		}
		existing.Webhooks = cfg.Webhooks
		existing.Labels = cfg.Labels
		existing.Annotations = cfg.Annotations
		_, err = wrc.validateInterface.Update(ctx, existing, metav1.UpdateOptions{})
		if err == nil {
			logger.Info("ValidatingWebhookConfiguration updated", "name", cfg.Name)
			return nil
		}
		if !k8errors.IsConflict(err) {
			return err
		}
		if existing, err = wrc.validateInterface.Get(ctx, cfg.Name, metav1.GetOptions{}); err != nil {
			return err
		}
	}
	return fmt.Errorf("failed to update ValidatingWebhookConfiguration %q after %d retries", cfg.Name, maxUpdateRetries)
}

// Compare copies with admissionregistration/v1 defaults applied so API-server
// defaulting does not turn config resyncs into writes. The generated payload
// and caller-owned configuration retain their original representation.
func normalizedMutatingWebhooks(cfg *admissionregistrationapi.MutatingWebhookConfiguration) []admissionregistrationapi.MutatingWebhook {
	webhooks := cfg.DeepCopy().Webhooks
	for i := range webhooks {
		entry := &webhooks[i]
		entry.FailurePolicy = ptr.To(ptr.Deref(entry.FailurePolicy, admissionregistrationapi.Fail))
		entry.TimeoutSeconds = ptr.To(ptr.Deref(entry.TimeoutSeconds, int32(config.WebhookTimeout)))
		entry.ReinvocationPolicy = ptr.To(ptr.Deref(entry.ReinvocationPolicy, admissionregistrationapi.NeverReinvocationPolicy))
		normalizeWebhookDefaults(&entry.ClientConfig, entry.Rules, &entry.MatchPolicy, &entry.NamespaceSelector, &entry.ObjectSelector)
	}
	return webhooks
}

func normalizedValidatingWebhooks(cfg *admissionregistrationapi.ValidatingWebhookConfiguration) []admissionregistrationapi.ValidatingWebhook {
	webhooks := cfg.DeepCopy().Webhooks
	for i := range webhooks {
		entry := &webhooks[i]
		entry.FailurePolicy = ptr.To(ptr.Deref(entry.FailurePolicy, admissionregistrationapi.Fail))
		entry.TimeoutSeconds = ptr.To(ptr.Deref(entry.TimeoutSeconds, int32(config.WebhookTimeout)))
		normalizeWebhookDefaults(&entry.ClientConfig, entry.Rules, &entry.MatchPolicy, &entry.NamespaceSelector, &entry.ObjectSelector)
	}
	return webhooks
}

func normalizeWebhookDefaults(
	clientConfig *admissionregistrationapi.WebhookClientConfig,
	rules []admissionregistrationapi.RuleWithOperations,
	matchPolicy **admissionregistrationapi.MatchPolicyType,
	namespaceSelector, objectSelector **metav1.LabelSelector,
) {
	*matchPolicy = ptr.To(ptr.Deref(*matchPolicy, admissionregistrationapi.Equivalent))
	if *namespaceSelector == nil {
		*namespaceSelector = &metav1.LabelSelector{}
	}
	if *objectSelector == nil {
		*objectSelector = &metav1.LabelSelector{}
	}
	for i := range rules {
		rules[i].Scope = ptr.To(ptr.Deref(rules[i].Scope, admissionregistrationapi.AllScopes))
	}
	if clientConfig.Service != nil {
		clientConfig.Service.Port = ptr.To(ptr.Deref(clientConfig.Service.Port, int32(443)))
	}
}

func (wrc *Register) createResourceMutatingWebhookConfiguration(ctx context.Context, caData []byte) error {
	logger := wrc.log

	var cfg *admissionregistrationapi.MutatingWebhookConfiguration

	if wrc.inContainer {
		service := admissionregistrationapi.ServiceReference{
			Namespace: config.Namespace,
			Name:      config.WebhookServiceName,
			Path:      &config.MutatingWebhookServicePath,
		}
		clientConfig := admissionregistrationapi.WebhookClientConfig{
			Service:  &service,
			CABundle: caData,
		}
		cfg = wrc.generateMutatingWebhookConfig(config.MutatingWebhookConfigurationName, clientConfig, admissionregistrationapi.IfNeededReinvocationPolicy)
		logger.Info("MutatingWebhookConfiguration generated", "name", cfg.Name, "service", service)
	} else {
		url := fmt.Sprintf("https://%s:%d%s", wrc.managerIP, config.WebhookServicePort, config.MutatingWebhookServicePath)
		clientConfig := admissionregistrationapi.WebhookClientConfig{
			URL:      &url,
			CABundle: caData,
		}
		cfg = wrc.generateMutatingWebhookConfig(config.MutatingWebhookConfigurationDebugName, clientConfig, admissionregistrationapi.NeverReinvocationPolicy)
		logger.Info("MutatingWebhookConfiguration generated", "name", cfg.Name, "url", url)
	}

	// Create-or-update keeps the desired entries in place without ever deleting
	// the configuration, so there is no admission window in which it is absent.
	return wrc.upsertMutatingWebhookConfiguration(ctx, cfg)
}

func (wrc *Register) generateMutatingWebhookConfig(
	name string,
	clientConfig admissionregistrationapi.WebhookClientConfig,
	reinvocationPolicy admissionregistrationapi.ReinvocationPolicyType) *admissionregistrationapi.MutatingWebhookConfiguration {

	snapshot := config.GetDynamicConfig()
	var webhooks []admissionregistrationapi.MutatingWebhook
	for _, builtin := range []struct {
		kind       string
		name       string
		operations []admissionregistrationapi.OperationType
		rule       admissionregistrationapi.Rule
	}{
		{"Deployment", config.MutatingWorkloadWebhookName, []admissionregistrationapi.OperationType{admissionregistrationapi.Create, admissionregistrationapi.Update}, workloadResourceWebhookRule()},
		{"Pod", config.MutatingPodWebhookName, []admissionregistrationapi.OperationType{admissionregistrationapi.Create}, podResourceWebhookRule()},
	} {
		// The registry holds only enabled adapters; a missing entry means
		// this built-in kind was disabled at startup.
		a, ok := wrc.registry.LookupByKind(builtin.kind)
		if !ok {
			continue
		}
		opts := config.ResolveWorkloadAdapterOptions(snapshot, a, wrc.adapterDefaults[a.Name()], wrc.timeoutSeconds)
		entry := generateMutatingWebhook(
			builtin.name,
			clientConfig,
			builtin.operations,
			builtin.rule,
			opts.TimeoutSeconds,
			reinvocationPolicy,
		)
		// Built-in webhooks retain their historical fail-open admission contract.
		ignore := admissionregistrationapi.Ignore
		entry.FailurePolicy = &ignore
		entry.MatchConditions = opts.MatchConditions
		webhooks = append(webhooks, entry)
	}

	// Enabled custom (non-builtin) adapters contribute their rules, coalesced
	// into one entry per distinct webhook-option set. The list is empty in the
	// upstream default build, preserving the historical two-entry output.
	webhooks = append(webhooks, wrc.customAdapterWebhooks(snapshot, clientConfig, reinvocationPolicy)...)

	return &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Webhooks: webhooks,
	}
}

func generateMutatingWebhook(
	name string,
	clientConfig admissionregistrationapi.WebhookClientConfig,
	operationTypes []admissionregistrationapi.OperationType,
	rule admissionregistrationapi.Rule,
	timeoutSeconds int32,
	reinvocationPolicy admissionregistrationapi.ReinvocationPolicyType,
) admissionregistrationapi.MutatingWebhook {

	failurePolicy := admissionregistrationapi.Ignore
	selector := metav1.LabelSelector{
		MatchLabels: config.WebhookSelectorLabel,
	}
	sideEffect := admissionregistrationapi.SideEffectClassNoneOnDryRun

	return admissionregistrationapi.MutatingWebhook{
		Name:         name,
		ClientConfig: clientConfig,
		Rules: []admissionregistrationapi.RuleWithOperations{
			{
				Operations: operationTypes,
				Rule:       rule,
			},
		},
		FailurePolicy:           &failurePolicy,
		ObjectSelector:          &selector,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          &timeoutSeconds,
		AdmissionReviewVersions: []string{"v1"},
		ReinvocationPolicy:      &reinvocationPolicy,
	}
}

func workloadResourceWebhookRule() admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		Resources:   []string{"daemonsets", "deployments", "statefulsets"},
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1"},
	}
}

func podResourceWebhookRule() admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		Resources:   []string{"pods"},
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
	}
}

func (wrc *Register) createPolicyValidatingWebhookConfiguration(ctx context.Context, caData []byte) error {
	logger := wrc.log

	var cfg *admissionregistrationapi.ValidatingWebhookConfiguration

	if wrc.inContainer {
		service := admissionregistrationapi.ServiceReference{
			Namespace: config.Namespace,
			Name:      config.WebhookServiceName,
			Path:      &config.ValidatingWebhookServicePath,
		}
		clientConfig := admissionregistrationapi.WebhookClientConfig{
			Service:  &service,
			CABundle: caData,
		}
		cfg = wrc.generateValidatingWebhookConfig(config.ValidatingWebhookConfigurationName, clientConfig)
		logger.Info("ValidatingWebhookConfiguration generated", "name", cfg.Name, "service", service)
	} else {
		url := fmt.Sprintf("https://%s:%d%s", wrc.managerIP, config.WebhookServicePort, config.ValidatingWebhookServicePath)
		clientConfig := admissionregistrationapi.WebhookClientConfig{
			URL:      &url,
			CABundle: caData,
		}
		cfg = wrc.generateValidatingWebhookConfig(config.ValidatingWebhookConfigurationDebugName, clientConfig)
		logger.Info("ValidatingWebhookConfiguration generated", "name", cfg.Name, "url", url)
	}

	// Create-or-update keeps the desired entries in place without ever deleting
	// the configuration, so there is no admission window in which it is absent.
	return wrc.upsertValidatingWebhookConfiguration(ctx, cfg)
}

func (wrc *Register) generateValidatingWebhookConfig(name string, clientConfig admissionregistrationapi.WebhookClientConfig) *admissionregistrationapi.ValidatingWebhookConfiguration {
	failurePolicy := admissionregistrationapi.Ignore
	sideEffect := admissionregistrationapi.SideEffectClassNone
	timeoutSeconds := wrc.timeoutSeconds

	return &admissionregistrationapi.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Webhooks: []admissionregistrationapi.ValidatingWebhook{
			{
				Name:         config.ValidatingPolicyWebhookName,
				ClientConfig: clientConfig,
				Rules: []admissionregistrationapi.RuleWithOperations{
					{
						Operations: []admissionregistrationapi.OperationType{admissionregistrationapi.Create, admissionregistrationapi.Update},
						Rule:       policyResourceWebhookRule(),
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffect,
				TimeoutSeconds:          &timeoutSeconds,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}
}

func policyResourceWebhookRule() admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		Resources:   []string{"varmorpolicies", "varmorclusterpolicies"},
		APIGroups:   []string{"crd.varmor.org"},
		APIVersions: []string{"v1beta1"},
	}
}

// Check returns an error if the webhooks of vArmor is not configured
func (wrc *Register) Check() error {
	_, err := wrc.mwcLister.Get(getResourceMutatingWebhookConfigName(wrc.inContainer))
	if err != nil {
		return err
	}

	_, err = wrc.vwcLister.Get(getPolicyValidatingWebhookConfigName(wrc.inContainer))
	return err
}

// ShouldRemoveVarmorResources determines whether vArmor webhook resources should be cleaned up.
// This function checks the current state of the vArmor manager deployment to decide if cleanup is needed.
//
// Returns:
//   - true: Cleanup should be performed in the following scenarios:
//     1. Running outside of container environment (development/debug mode)
//     2. vArmor manager deployment not found in the cluster
//     3. vArmor manager deployment is being terminated
//     4. vArmor manager deployment is scaled to zero replicas
//   - false: Cleanup should not be performed, typically when the manager is updating or running normally
func (wrc *Register) ShouldRemoveVarmorResources() bool {
	logger := wrc.log.WithName("shouldRemoveVarmorResources()")

	if !wrc.inContainer {
		return true
	}

	deploy, err := wrc.deploymentInterface.Get(context.Background(), config.ManagerName, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			logger.Info("vArmor manager not found, cleanup webhook resources of vArmor")
			return true
		}

		logger.Error(err, "failed to get vArmor manager, not cleaning up webhook resources of vArmor")
		return false
	}

	if deploy.GetDeletionTimestamp() != nil {
		logger.Info("vArmor manager is terminating, cleanup webhook resources")
		return true
	}

	if *deploy.Spec.Replicas == 0 {
		logger.Info("vArmor manager is scaled to zero, cleanup webhook resources")
		return true
	}

	logger.Info("vArmor manager Pod is updating, won't clean up webhook resources")
	return false
}

// Remove removes the webhook configuration, secrets and leases
func (wrc *Register) Remove() {
	wrc.log.Info("cleaning up")
	wrc.removeWebhookConfigurations()
	wrc.removeSecrets()
	wrc.removeLeases()
}

func (wrc *Register) removeWebhookConfigurations() {
	logger := wrc.log

	configName := getResourceMutatingWebhookConfigName(wrc.inContainer)
	err := wrc.mutateInterface.Delete(context.Background(), configName, metav1.DeleteOptions{})
	if err != nil {
		if !k8errors.IsNotFound(err) {
			logger.Error(err, "failed to delete MutatingWebhookConfiguration", "name", configName)
		}
	} else {
		logger.Info("MutatingWebhookConfiguration deleted")
	}

	configName = getPolicyValidatingWebhookConfigName(wrc.inContainer)
	err = wrc.validateInterface.Delete(context.Background(), configName, metav1.DeleteOptions{})
	if err != nil {
		if !k8errors.IsNotFound(err) {
			logger.Error(err, "failed to delete ValidatingWebhookConfiguration", "name", configName)
		}
	} else {
		logger.Info("ValidatingWebhookConfiguration deleted")
	}
}

func (wrc *Register) removeSecrets() {
	logger := wrc.log.WithValues("removeSecrets()")

	certProps, err := varmortls.GetTLSCertProps(wrc.clientConfig)
	if err != nil {
		return
	}

	secretName := varmortls.GenerateRootCASecretName(certProps)
	err = wrc.secretInterface.Delete(context.Background(), secretName, metav1.DeleteOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			logger.Info("the secret of Root CA not found", "Secret", secretName)
		}
		logger.Error(err, "failed to delete the Root CA", "Secret", secretName)
	}

	secretName = varmortls.GenerateTLSPairSecretName(certProps)
	err = wrc.secretInterface.Delete(context.Background(), secretName, metav1.DeleteOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			logger.Info("the secret of TLS pair not found", "Secret", secretName)
		}
		logger.Error(err, "failed to delete the TLS pair", "Secret", secretName)
	}

	logger.Info("the secrets of webhook server deleted")
}

func (wrc *Register) removeLeases() {
	wrc.leaseInterface.DeleteCollection(context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{})
}

// getResourceMutatingWebhookConfigName returns the mutating webhook configuration name.
func getResourceMutatingWebhookConfigName(inContainer bool) string {
	if !inContainer {
		return config.MutatingWebhookConfigurationDebugName
	}
	return config.MutatingWebhookConfigurationName
}

// getPolicyValidatingWebhookConfigName returns the validating webhook configuration name.
func getPolicyValidatingWebhookConfigName(inContainer bool) string {
	if !inContainer {
		return config.ValidatingWebhookConfigurationDebugName
	}
	return config.ValidatingWebhookConfigurationName
}
