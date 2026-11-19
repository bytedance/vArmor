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
	"os"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
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

// rotation actions reported by rotateIfNeeded for logging and tests.
const (
	rotationActionNone    = ""
	rotationActionLeaf    = "leaf"
	rotationActionRoot    = "root"
	rotationActionRetired = "retired-previous-ca"
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
	// webhookReconcile re-applies the webhook configurations after a CA
	// rotation or previous-CA retirement so caBundle tracks the CA Secret.
	// Leaf-only rotations do not need it because the trust anchor is unchanged.
	webhookReconcile func(ctx context.Context) error
	log              logr.Logger
}

func NewCertManager(
	clientConfig *rest.Config,
	certRenewer *varmortls.CertRenewer,
	secretInterface corev1.SecretInterface,
	secretInformer coreinformer.SecretInformer,
	webhookReconcile func(ctx context.Context) error,
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
		webhookReconcile:     webhookReconcile,
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

// reconcileWebhooks invokes the injected webhook reconciliation callback.
// A nil callback (only expected in unit tests) is treated as a no-op.
func (m *certManager) reconcileWebhooks(ctx context.Context) error {
	if m.webhookReconcile == nil {
		return nil
	}
	return m.webhookReconcile(ctx)
}

// rotateIfNeeded performs one certificate renewal pass:
//  1. A retired root CA whose retention window elapsed is removed and the
//     webhook caBundle is rewritten to the current CA only.
//  2. An expiring root CA is replaced; the previous CA is retained and the
//     webhook caBundle is rewritten to trust both CAs.
//  3. An expiring leaf is re-issued by the current CA without touching the
//     caBundle; replicas hot-reload it through their Secret informer.
//
// It returns the action taken (rotationActionNone when everything is valid)
// so the event loop can log a concise audit line.
func (m *certManager) rotateIfNeeded(ctx context.Context) (string, error) {
	logger := m.log.WithName("rotateIfNeeded()")

	certProps, err := varmortls.GetTLSCertProps(m.clientConfig)
	if err != nil {
		return rotationActionNone, err
	}

	// Step 1: retire a previous CA once the make-before-break window elapsed.
	rotatedAt, hasPrevious, err := m.renewer.PreviousCARotatedAt(certProps)
	if err != nil {
		return rotationActionNone, fmt.Errorf("failed to inspect previous CA: %w", err)
	}
	if hasPrevious && time.Since(rotatedAt) >= config.PreviousCARetentionDuration {
		if err := m.renewer.RetirePreviousCA(certProps); err != nil {
			return rotationActionNone, fmt.Errorf("failed to retire previous CA: %w", err)
		}
		if err := m.reconcileWebhooks(ctx); err != nil {
			return rotationActionRetired, fmt.Errorf("previous CA retired but webhook reconciliation failed: %w", err)
		}
		logger.Info("previous root CA retired, webhook caBundle rewritten to the current CA only")
		return rotationActionRetired, nil
	}

	// Step 2: the trust anchor itself is expiring — full CA rotation with a
	// dual-CA caBundle so admission keeps verifying either leaf meanwhile.
	caExpiring, err := m.renewer.CANeedsRotation(certProps)
	if err != nil {
		return rotationActionNone, fmt.Errorf("failed to check root CA expiry: %w", err)
	}
	if caExpiring {
		if _, err := m.renewer.RotateRootCA(certProps); err != nil {
			return rotationActionNone, fmt.Errorf("failed to rotate root CA: %w", err)
		}
		if err := m.reconcileWebhooks(ctx); err != nil {
			return rotationActionRoot, fmt.Errorf("root CA rotated but webhook reconciliation failed: %w", err)
		}
		logger.Info("root CA rotated; previous CA retained in the dual-CA caBundle")
		return rotationActionRoot, nil
	}

	// Step 3: only the leaf certificate is expiring. Reuse the current CA so
	// the caBundle stays unchanged and no webhook rewrite is required.
	leafExpiring, err := m.renewer.LeafNeedsRotation(certProps)
	if err != nil {
		return rotationActionNone, fmt.Errorf("failed to check leaf certificate expiry: %w", err)
	}
	if !leafExpiring {
		return rotationActionNone, nil
	}

	if _, err := m.renewer.RotateLeafCert(certProps); err != nil {
		// Legacy CA Secrets predate private-key persistence: fall back to a
		// full CA rotation, which also upgrades the Secret layout.
		if errors.Is(err, varmortls.ErrCAPrivateKeyUnavailable) {
			logger.Info("CA private key unavailable, falling back to a full CA rotation")
			if _, rootErr := m.renewer.RotateRootCA(certProps); rootErr != nil {
				return rotationActionNone, fmt.Errorf("fallback root CA rotation failed: %w", rootErr)
			}
			if reconcileErr := m.reconcileWebhooks(ctx); reconcileErr != nil {
				return rotationActionRoot, fmt.Errorf("root CA rotated but webhook reconciliation failed: %w", reconcileErr)
			}
			return rotationActionRoot, nil
		}
		return rotationActionNone, fmt.Errorf("failed to rotate leaf certificate: %w", err)
	}
	logger.Info("webhook leaf certificate rotated; replicas will hot-reload it via the Secret informer")
	return rotationActionLeaf, nil
}

// Run starts the certificate manager's main event loop.
// This function runs continuously and handles three types of events:
// 1. Periodic certificate renewal checks based on config.CertRenewalInterval
// 2. Secret change events (add/update) that trigger webhook reconciliation
// 3. Stop signal to gracefully shutdown the manager
//
// Renewals no longer restart the manager: leaf rotations hot-reload through
// the Secret informer, while CA rotations rely on a dual-CA caBundle. A
// failed pass is retried on the next ticker or Secret event instead of
// terminating the process.
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stopCh
		cancel()
	}()

	// Main event loop - processes three types of events
	for {
		select {
		// Case 1: Timer-driven certificate renewal check
		case <-certsRenewalTicker.C:
			action, err := m.rotateIfNeeded(ctx)
			if err != nil {
				logger.Error(err, "certificate renewal pass failed; it will be retried")
			} else if action != rotationActionNone {
				logger.Info("certificate renewal completed", "action", action)
			}

		// Case 2: Event-driven webhook reconciliation (secret changes)
		case <-m.secretQueue:
			certProps, err := varmortls.GetTLSCertProps(m.clientConfig)
			if err != nil {
				logger.Error(err, "failed to get TLS Certificate Properties")
				continue
			}
			valid, err := m.renewer.ValidCert(certProps)
			if err != nil {
				logger.Error(err, "failed to validate cert after a Secret change")
				continue
			}
			if !valid {
				// The Secret may hold an externally repaired but not-yet-valid
				// pair: run a full renewal pass to converge it.
				if action, rotateErr := m.rotateIfNeeded(ctx); rotateErr != nil {
					logger.Error(rotateErr, "certificate renewal pass failed; it will be retried")
				} else if action != rotationActionNone {
					logger.Info("certificate renewal completed", "action", action)
				}
				continue
			}
			// Valid material: make caBundle track dual-CA / retirement changes.
			if err := m.reconcileWebhooks(ctx); err != nil {
				logger.Error(err, "webhook reconciliation after a Secret change failed; it will be retried")
			}

		// Case 3: Stop signal received - gracefully shutdown
		case <-m.stopCh:
			logger.Info("stopping cert renewer")
			return
		}
	}
}
