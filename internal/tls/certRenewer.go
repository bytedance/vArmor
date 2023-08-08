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

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	"github.com/bytedance/vArmor/internal/config"
)

const (
	SelfSignedAnnotation    string = "self-signed-cert"
	RootCAKey               string = "rootCA.crt"
	rollingUpdateAnnotation string = "cert.varmor.org/force-rolling-update"
)

// CertRenewer creates rootCA and pem pair to register
// webhook configurations and webhook server
// renews RootCA at the given interval.
type CertRenewer struct {
	clientConfig         *rest.Config
	secretInterface      corev1.SecretInterface
	deploymentInterface  appsv1.DeploymentInterface
	certRenewalInterval  time.Duration
	certValidityDuration time.Duration
	managerIP            string
	debug                bool
	log                  logr.Logger
}

// NewCertRenewer returns an instance of CertRenewer.
func NewCertRenewer(clientConfig *rest.Config, secretInterface corev1.SecretInterface, deploymentInterface appsv1.DeploymentInterface, certRenewalInterval, certValidityDuration time.Duration, managerIP string, debug bool, log logr.Logger) *CertRenewer {
	return &CertRenewer{
		clientConfig:         clientConfig,
		secretInterface:      secretInterface,
		deploymentInterface:  deploymentInterface,
		certRenewalInterval:  certRenewalInterval,
		certValidityDuration: certValidityDuration,
		managerIP:            managerIP,
		debug:                debug,
		log:                  log,
	}
}

// ValidCert validates the CA Cert.
func (c *CertRenewer) ValidCert(certProps CertificateProps) (bool, error) {
	logger := c.log.WithName("ValidCert")

	secretName := GenerateRootCASecretName(certProps)
	rootCA, err := ReadRootCASecret(c.secretInterface, secretName)
	if err != nil {
		return false, err
	}

	secretName = GenerateTLSPairSecretName(certProps)
	tlsPair, err := ReadTLSPair(c.secretInterface, secretName)
	if err != nil {
		return false, err
	}

	// build cert pool
	pool := x509.NewCertPool()
	caPem, _ := pem.Decode(rootCA)
	if caPem == nil {
		logger.Error(err, "bad certificate")
		return false, nil
	}

	cac, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		logger.Error(err, "failed to parse CA cert")
		return false, nil
	}
	pool.AddCert(cac)

	// valid PEM pair
	_, err = tls.X509KeyPair(tlsPair.Certificate, tlsPair.PrivateKey)
	if err != nil {
		logger.Error(err, "invalid PEM pair")
		return false, nil
	}

	certPem, _ := pem.Decode(tlsPair.Certificate)
	if certPem == nil {
		logger.Error(err, "bad private key")
		return false, nil
	}

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		logger.Error(err, "failed to parse cert")
		return false, nil
	}

	if _, err = cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Now().Add(c.certRenewalInterval),
	}); err != nil {
		logger.Error(err, "invalid cert")
		return false, nil
	}

	return true, nil
}

// WriteCACertToSecret stores the CA cert in secret.
func (c *CertRenewer) WriteCACertToSecret(caPEM *PemPair, secretName string) error {
	secret, err := c.secretInterface.Get(context.Background(), secretName, metav1.GetOptions{})
	if err == nil {
		secret.Annotations = map[string]string{SelfSignedAnnotation: "true"}
		secret.Data = map[string][]byte{RootCAKey: caPEM.Certificate}
		secret.Type = v1.SecretTypeOpaque
		_, err = c.secretInterface.Update(context.Background(), secret, metav1.UpdateOptions{})
		return err
	} else {
		if k8errors.IsNotFound(err) {
			secret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName,
					Annotations: map[string]string{
						SelfSignedAnnotation: "true",
					},
				},
				Data: map[string][]byte{
					RootCAKey: caPEM.Certificate,
				},
				Type: v1.SecretTypeOpaque,
			}
			_, err = c.secretInterface.Create(context.Background(), secret, metav1.CreateOptions{})
		}
	}

	return err
}

// WriteTLSPairToSecret writes the pair of TLS certificate and key to the specified secret.
func (c *CertRenewer) WriteTLSPairToSecret(pemPair *PemPair, secretName string) error {
	secret, err := c.secretInterface.Get(context.Background(), secretName, metav1.GetOptions{})
	if err == nil {
		secret.Data = map[string][]byte{
			v1.TLSCertKey:       pemPair.Certificate,
			v1.TLSPrivateKeyKey: pemPair.PrivateKey,
		}
		secret.Type = v1.SecretTypeTLS
		_, err = c.secretInterface.Update(context.Background(), secret, metav1.UpdateOptions{})
	} else {
		if k8errors.IsNotFound(err) {
			secret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName,
				},
				Data: map[string][]byte{
					v1.TLSCertKey:       pemPair.Certificate,
					v1.TLSPrivateKeyKey: pemPair.PrivateKey,
				},
				Type: v1.SecretTypeTLS,
			}
			_, err = c.secretInterface.Create(context.Background(), secret, metav1.CreateOptions{})
		}
	}

	return err
}

// buildTLSPemPairAndWriteToSecrets Issues TLS certificate for webhook server using self-signed CA cert.
// Returns signed and approved TLS certificate in PEM format.
func (c *CertRenewer) buildTLSPemPairAndWriteToSecrets(props CertificateProps) (*PemPair, error) {
	caCert, caPEM, err := GenerateCACert(c.certValidityDuration)
	if err != nil {
		return nil, err
	}

	secretName := GenerateRootCASecretName(props)
	if err := c.WriteCACertToSecret(caPEM, secretName); err != nil {
		return nil, fmt.Errorf("failed to write or update CA cert to secret %s: %v", secretName, err)
	}

	tlsPair, err := GenerateCertPem(caCert, props, c.certValidityDuration, c.managerIP, c.debug)
	if err != nil {
		return nil, err
	}

	secretName = GenerateTLSPairSecretName(props)
	if err = c.WriteTLSPairToSecret(tlsPair, secretName); err != nil {
		return nil, fmt.Errorf("unable to save TLS pair to the secret %s: %v", secretName, err)
	}

	return tlsPair, nil
}

// InitTLSPemPair Loads or creates PEM private key and TLS certificate for webhook server.
// Created pair is stored in cluster's secret.
// Returns struct with key/certificate pair.
func (c *CertRenewer) InitTLSPemPair() (*PemPair, error) {
	logger := c.log.WithName("InitTLSPemPair")

	certProps, err := GetTLSCertProps(c.clientConfig)
	if err != nil {
		return nil, err
	}

	valid, err := c.ValidCert(certProps)
	if err == nil && valid {
		logger.Info("using existing TLS pair")
		tlsPair, err := ReadTLSPair(c.secretInterface, GenerateTLSPairSecretName(certProps))
		return tlsPair, err
	}

	logger.Info("buiding new root CA and TLS pair")
	return c.buildTLSPemPairAndWriteToSecrets(certProps)
}

// RollingUpdate triggers a rolling update of varmor-manager pod.
// It is used when the rootCA is renewed, the restart of
// varmor-manager pod will register webhook server with new cert.
func (c *CertRenewer) RollingUpdateVarmorManager() error {
	logger := c.log.WithName("RollingUpdateVarmorManager")

	update := func() error {
		deploy, err := c.deploymentInterface.Get(context.Background(), config.ManagerName, metav1.GetOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to find manager")
		}

		if IsVarmorManagerInRollingUpdate(deploy) {
			logger.Info("manager is in rolling update, won't trigger the update again")
			return nil
		}

		if deploy.Spec.Template.Annotations == nil {
			deploy.Spec.Template.Annotations = make(map[string]string)
		}
		deploy.Spec.Template.Annotations[rollingUpdateAnnotation] = time.Now().Format(time.RFC3339)

		if _, err = c.deploymentInterface.Update(context.Background(), deploy, metav1.UpdateOptions{}); err != nil {
			return errors.Wrap(err, "failed to update manager")
		}

		return nil
	}

	exbackoff := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.5,
		MaxInterval:         time.Second,
		MaxElapsedTime:      3 * time.Second,
		Clock:               backoff.SystemClock,
	}

	exbackoff.Reset()
	return backoff.Retry(update, exbackoff)
}
