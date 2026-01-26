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

	"github.com/go-logr/logr"

	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	adminformers "k8s.io/client-go/informers/admissionregistration/v1"
	admissionv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	admlisters "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/rest"

	"github.com/bytedance/vArmor/internal/config"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

// Register manages webhook registration.
type Register struct {
	clientConfig         *rest.Config
	mutateInterface      admissionv1.MutatingWebhookConfigurationInterface
	validateInterface    admissionv1.ValidatingWebhookConfigurationInterface
	secretInterface      corev1.SecretInterface
	deploymentInterface  appsv1.DeploymentInterface
	leaseInterface       coordinationv1.LeaseInterface
	mwcLister            admlisters.MutatingWebhookConfigurationLister
	mwcListerSynced      func() bool
	vwcLister            admlisters.ValidatingWebhookConfigurationLister
	vwcListerSynced      func() bool
	managerIP            string
	timeoutSeconds       int32
	inContainer          bool
	stopCh               <-chan struct{}
	createDefaultWebhook chan string
	log                  logr.Logger
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
	log logr.Logger) *Register {

	register := &Register{
		clientConfig:         clientConfig,
		mutateInterface:      mutateInterface,
		validateInterface:    validateInterface,
		secretInterface:      secretInterface,
		deploymentInterface:  deploymentInterface,
		leaseInterface:       leaseInterface,
		managerIP:            managerIP,
		timeoutSeconds:       webhookTimeout,
		inContainer:          inContainer,
		createDefaultWebhook: make(chan string),
		mwcLister:            mwcInformer.Lister(),
		mwcListerSynced:      mwcInformer.Informer().HasSynced,
		vwcLister:            vwcInformer.Lister(),
		vwcListerSynced:      vwcInformer.Informer().HasSynced,
		stopCh:               stopCh,
		log:                  log.WithName("Register"),
	}

	return register
}

// Register clean up the old webhooks and re-creates admission webhooks configs on cluster
func (wrc *Register) Register() error {
	wrc.removeWebhookConfigurations()

	certProps, err := varmortls.GetTLSCertProps(wrc.clientConfig)
	if err != nil {
		return err
	}
	secretName := varmortls.GenerateRootCASecretName(certProps)
	caData, err := varmortls.ReadRootCASecret(wrc.secretInterface, secretName)
	if err != nil {
		return fmt.Errorf("unable to extract CA data from %s secret", secretName)
	}

	err = wrc.createResourceMutatingWebhookConfiguration(caData)
	if err != nil {
		return err
	}

	err = wrc.createPolicyValidatingWebhookConfiguration(caData)
	if err != nil {
		return err
	}

	return nil
}

func (wrc *Register) createResourceMutatingWebhookConfiguration(caData []byte) error {
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

	_, err := wrc.mutateInterface.Create(context.Background(), cfg, metav1.CreateOptions{})
	if err != nil {
		if k8errors.IsAlreadyExists(err) {
			logger.Info("MutatingWebhookConfiguration already exists", "name", cfg.Name)
			return nil
		}
		logger.Error(err, "failed to create MutatingWebhookConfiguration", "name", cfg.Name)
		return err
	}

	logger.Info("MutatingWebhookConfiguration created", "name", cfg.Name)
	return nil
}

func (wrc *Register) generateMutatingWebhookConfig(
	name string,
	clientConfig admissionregistrationapi.WebhookClientConfig,
	reinvocationPolicy admissionregistrationapi.ReinvocationPolicyType) *admissionregistrationapi.MutatingWebhookConfiguration {

	return &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Webhooks: []admissionregistrationapi.MutatingWebhook{
			generateMutatingWebhook(
				config.MutatingWorkloadWebhookName,
				clientConfig,
				[]admissionregistrationapi.OperationType{admissionregistrationapi.Create, admissionregistrationapi.Update},
				workloadResourceWebhookRule(),
				wrc.timeoutSeconds,
				reinvocationPolicy,
			),
			generateMutatingWebhook(
				config.MutatingPodWebhookName,
				clientConfig,
				[]admissionregistrationapi.OperationType{admissionregistrationapi.Create},
				podResourceWebhookRule(),
				wrc.timeoutSeconds,
				reinvocationPolicy,
			),
		},
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

func (wrc *Register) createPolicyValidatingWebhookConfiguration(caData []byte) error {
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

	_, err := wrc.validateInterface.Create(context.Background(), cfg, metav1.CreateOptions{})
	if err != nil {
		if k8errors.IsAlreadyExists(err) {
			logger.Info("ValidatingWebhookConfiguration already exists", "name", cfg.Name)
			return nil
		}
		logger.Error(err, "failed to create ValidatingWebhookConfiguration", "name", cfg.Name)
		return err
	}

	logger.Info("ValidatingWebhookConfiguration created", "name", cfg.Name)
	return nil
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
