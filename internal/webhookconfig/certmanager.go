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
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformer "k8s.io/client-go/informers/core/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/bytedance/vArmor/internal/config"
	varmortls "github.com/bytedance/vArmor/internal/tls"
)

type certManager struct {
	clientConfig         *rest.Config
	renewer              *varmortls.CertRenewer
	secretInterface      corev1.SecretInterface
	secretInformer       coreinformer.SecretInformer
	secretLister         corelister.SecretLister
	secretInformerSynced cache.InformerSynced
	secretQueue          chan bool
	stopCh               <-chan struct{}
	log                  logr.Logger
}

func NewCertManager(
	clientConfig *rest.Config,
	certRenewer *varmortls.CertRenewer,
	secretInterface corev1.SecretInterface,
	secretInformer coreinformer.SecretInformer,
	stopCh <-chan struct{},
	log logr.Logger) *certManager {

	manager := certManager{
		clientConfig:         clientConfig,
		renewer:              certRenewer,
		secretInterface:      secretInterface,
		secretInformer:       secretInformer,
		secretLister:         secretInformer.Lister(),
		secretInformerSynced: secretInformer.Informer().HasSynced,
		secretQueue:          make(chan bool, 1),
		stopCh:               stopCh,
		log:                  log,
	}

	return &manager
}

func (m *certManager) InitTLSPemPair() {
	_, err := m.renewer.InitTLSPemPair()
	if err != nil {
		m.log.Error(err, "InitTLSPemPair() failed")
		os.Exit(1)
	}
}

func (m *certManager) GetTLSPemPair() (*varmortls.PemPair, error) {
	var valid bool

	certProps, err := varmortls.GetTLSCertProps(m.clientConfig)
	if err != nil {
		return nil, err
	}
	secretName := varmortls.GenerateTLSPairSecretName(certProps)

	// Non-leader candidates will wait 15s to force acquire leadership,
	// so we need to retry it after the leader election is done and a new tls certificate is created.
	for i := 0; i < 15; i++ {
		valid, err = m.renewer.ValidCert(certProps)
		if err == nil {
			if valid {
				return varmortls.ReadTLSPair(m.secretInterface, secretName)
			} else {
				err = fmt.Errorf("certificate expired")
			}
		}

		m.log.Info("waiting for the certificate to be generated or rotated...", "reason", err)
		time.Sleep(4 * time.Second)
	}

	return nil, err
}

func (m *certManager) addSecretFunc(obj interface{}) {
	logger := m.log.WithName("addSecretFunc()")

	secret := obj.(*v1.Secret)
	if secret.Namespace != config.Namespace {
		return
	}

	val, ok := secret.Annotations[varmortls.SelfSignedAnnotation]
	if !ok || val != "true" {
		return
	}
	logger.V(2).Info("varmor secret added, reconciling webhook configurations")
	m.secretQueue <- true
}

func (m *certManager) updateSecretFunc(oldObj interface{}, newObj interface{}) {
	logger := m.log.WithName("updateSecretFunc()")

	old := oldObj.(*v1.Secret)
	new := newObj.(*v1.Secret)
	if new.Namespace != config.Namespace {
		return
	}

	val, ok := new.Annotations[varmortls.SelfSignedAnnotation]
	if !ok || val != "true" {
		return
	}

	if reflect.DeepEqual(old.DeepCopy().Data, new.DeepCopy().Data) {
		return
	}

	logger.V(2).Info("varmor secret updated, reconciling webhook configurations")
	m.secretQueue <- true
}

// Run starts the certificate manager's main event loop.
// This function runs continuously and handles three types of events:
// 1. Periodic certificate renewal checks based on config.CertRenewalInterval
// 2. Secret change events (add/update) that trigger certificate validation
// 3. Stop signal to gracefully shutdown the manager
//
// The manager operates in two modes:
// - Timer-driven: Regularly checks certificate validity and triggers rolling updates when needed
// - Event-driven: Responds to secret changes and validates certificates accordingly
func (m *certManager) Run(stopCh <-chan struct{}) {
	logger := m.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if !cache.WaitForCacheSync(stopCh, m.secretInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	m.secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.addSecretFunc,
		UpdateFunc: m.updateSecretFunc,
	})

	// Create a ticker for periodic certificate renewal checks
	// Uses the interval defined in config.CertRenewalInterval
	certsRenewalTicker := time.NewTicker(config.CertRenewalInterval)
	defer certsRenewalTicker.Stop()

	// Main event loop - processes three types of events
	for {
		select {
		// Case 1: Timer-driven certificate renewal check
		case <-certsRenewalTicker.C:
			certProps, err := varmortls.GetTLSCertProps(m.clientConfig)
			if err != nil {
				logger.Error(err, "failed to get TLS Certificate Properties")
				continue
			}
			valid, err := m.renewer.ValidCert(certProps)
			if err != nil {
				logger.Error(err, "failed to validate cert")

				if !strings.Contains(err.Error(), varmortls.ErrorsNotFound) {
					continue
				}
			}

			if valid {
				continue
			}

			logger.Info("rootCA is about to expire, trigger a rolling update to renew the cert")
			if err := m.renewer.RollingUpdateVarmorManager(); err != nil {
				logger.Error(err, "unable to trigger a rolling update to renew rootCA, force restarting")
				os.Exit(1)
			}

		// Case 2: Event-driven certificate validation (secret changes)
		case <-m.secretQueue:
			certProps, err := varmortls.GetTLSCertProps(m.clientConfig)
			if err != nil {
				logger.Error(err, "failed to get TLS Certificate Properties")
				continue
			}
			valid, err := m.renewer.ValidCert(certProps)
			if err != nil {
				logger.Error(err, "failed to validate cert")

				if !strings.Contains(err.Error(), varmortls.ErrorsNotFound) {
					continue
				}
			}

			if valid {
				continue
			}

			logger.Info("rootCA has changed, updating webhook configurations")
			if err := m.renewer.RollingUpdateVarmorManager(); err != nil {
				logger.Error(err, "unable to trigger a rolling update to re-register webhook server, force restarting")
				os.Exit(1)
			}

		// Case 3: Stop signal received - gracefully shutdown
		case <-m.stopCh:
			logger.Info("stopping cert renewer")
			return
		}
	}
}
