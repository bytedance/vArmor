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
	secretInterface      corev1.SecretInterface
	deploymentInterface  appsv1.DeploymentInterface
	leaseInterface       coordinationv1.LeaseInterface
	mwcLister            admlisters.MutatingWebhookConfigurationLister
	mwcListerSynced      func() bool
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
	secretInterface corev1.SecretInterface,
	deploymentInterface appsv1.DeploymentInterface,
	leaseInterface coordinationv1.LeaseInterface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	mwcInformer adminformers.MutatingWebhookConfigurationInformer,
	managerIP string,
	webhookTimeout int32,
	inContainer bool,
	stopCh <-chan struct{},
	log logr.Logger) *Register {

	register := &Register{
		clientConfig:         clientConfig,
		mutateInterface:      mutateInterface,
		secretInterface:      secretInterface,
		deploymentInterface:  deploymentInterface,
		leaseInterface:       leaseInterface,
		managerIP:            managerIP,
		timeoutSeconds:       webhookTimeout,
		inContainer:          inContainer,
		createDefaultWebhook: make(chan string),
		mwcLister:            mwcInformer.Lister(),
		mwcListerSynced:      mwcInformer.Informer().HasSynced,
		stopCh:               stopCh,
		log:                  log.WithName("Register"),
	}

	return register
}

func (wrc *Register) removeWebhookConfigurations() {
	logger := wrc.log

	configName := getResourceMutatingWebhookConfigName(wrc.inContainer)
	err := wrc.mutateInterface.Delete(context.Background(), configName, metav1.DeleteOptions{})
	if err != nil {
		if !k8errors.IsNotFound(err) {
			logger.Error(err, "failed to delete MutatingWebhookConfiguration", "name", configName)
		}
		return
	}

	logger.Info("MutatingWebhookConfiguration deleted")
}

func (wrc *Register) workloadResourceWebhookRule() admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		Resources:   []string{"daemonsets", "deployments", "statefulsets"},
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1"},
	}
}

func (wrc *Register) podResourceWebhookRule() admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		Resources:   []string{"pods"},
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
	}
}

func (wrc *Register) generateDefaultDebugMutatingWebhookConfig(caData []byte) *admissionregistrationapi.MutatingWebhookConfiguration {
	logger := wrc.log
	url := fmt.Sprintf("https://%s:%d%s", wrc.managerIP, config.WebhookServicePort, config.MutatingWebhookServicePath)
	logger.Info("Debug MutatingWebhookConfiguration generated", "url", url)

	return &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: config.MutatingWebhookConfigurationDebugName,
		},
		Webhooks: []admissionregistrationapi.MutatingWebhook{
			generateDebugMutatingWebhook(
				config.MutatingWorkloadWebhookName,
				url,
				caData,
				wrc.timeoutSeconds,
				wrc.workloadResourceWebhookRule(),
				[]admissionregistrationapi.OperationType{admissionregistrationapi.Create, admissionregistrationapi.Update},
				admissionregistrationapi.Ignore,
			),
			generateDebugMutatingWebhook(
				config.MutatingPodWebhookName,
				url,
				caData,
				wrc.timeoutSeconds,
				wrc.podResourceWebhookRule(),
				[]admissionregistrationapi.OperationType{admissionregistrationapi.Create},
				admissionregistrationapi.Ignore,
			),
		},
	}
}

func (wrc *Register) generateDefaultMutatingWebhookConfig(caData []byte) *admissionregistrationapi.MutatingWebhookConfiguration {
	return &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: config.MutatingWebhookConfigurationName,
		},
		Webhooks: []admissionregistrationapi.MutatingWebhook{
			generateMutatingWebhook(
				config.MutatingWorkloadWebhookName,
				config.MutatingWebhookServicePath,
				caData,
				wrc.timeoutSeconds,
				wrc.workloadResourceWebhookRule(),
				[]admissionregistrationapi.OperationType{admissionregistrationapi.Create, admissionregistrationapi.Update},
				admissionregistrationapi.Ignore,
			),
			generateMutatingWebhook(
				config.MutatingPodWebhookName,
				config.MutatingWebhookServicePath,
				caData,
				wrc.timeoutSeconds,
				wrc.podResourceWebhookRule(),
				[]admissionregistrationapi.OperationType{admissionregistrationapi.Create},
				admissionregistrationapi.Ignore,
			),
		},
	}
}

func (wrc *Register) createResourceMutatingWebhookConfiguration(caData []byte) error {
	logger := wrc.log

	var cfg *admissionregistrationapi.MutatingWebhookConfiguration
	if !wrc.inContainer {
		cfg = wrc.generateDefaultDebugMutatingWebhookConfig(caData)
	} else {
		cfg = wrc.generateDefaultMutatingWebhookConfig(caData)
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

	return nil
}

// Check returns an error if the webhook is not configured
func (wrc *Register) Check() error {
	_, err := wrc.mwcLister.Get(getResourceMutatingWebhookConfigName(wrc.inContainer))
	return err
}

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

// Remove removes the webhook configuration, secrets and leases
func (wrc *Register) Remove() {
	wrc.log.Info("cleaning up")
	wrc.removeWebhookConfigurations()
	wrc.removeSecrets()
	wrc.removeLeases()
}
