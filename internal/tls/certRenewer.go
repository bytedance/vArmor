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

// Package tls implements the certificate renewer for the admission webhook
package tls

import (
	"bytes"
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
	RootCAPrivateKeyKey     string = "rootCA.key"
	PreviousRootCAKey       string = "previousRootCA.crt"
	rollingUpdateAnnotation string = "cert.varmor.org/force-rolling-update"
	// PreviousCARotatedAtAnnotation records when the current root CA replaced
	// the previous one. The previous CA is kept in the Secret until the
	// retention window elapses so webhook caBundles can trust both CAs.
	PreviousCARotatedAtAnnotation string = "cert.varmor.org/previous-ca-rotated-at"
)

// ErrCAPrivateKeyUnavailable signals that the CA Secret predates private-key
// persistence, so a leaf-only rotation is impossible and a full CA rotation
// is required instead.
var ErrCAPrivateKeyUnavailable = errors.New("root CA private key not found in CA Secret, a full CA rotation is required")

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
	inContainer          bool
	log                  logr.Logger
}

// NewCertRenewer returns an instance of CertRenewer.
func NewCertRenewer(
	clientConfig *rest.Config,
	secretInterface corev1.SecretInterface,
	deploymentInterface appsv1.DeploymentInterface,
	certRenewalInterval, certValidityDuration time.Duration,
	managerIP string,
	inContainer bool,
	log logr.Logger) *CertRenewer {

	return &CertRenewer{
		clientConfig:         clientConfig,
		secretInterface:      secretInterface,
		deploymentInterface:  deploymentInterface,
		certRenewalInterval:  certRenewalInterval,
		certValidityDuration: certValidityDuration,
		managerIP:            managerIP,
		inContainer:          inContainer,
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

// certExpiresBefore reports whether the PEM certificate's NotAfter is at or
// before now plus the renewal interval, i.e. whether it must be rotated at
// the next renewal pass.
func certExpiresBefore(certPEM []byte, renewalInterval time.Duration) (bool, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true, fmt.Errorf("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return !cert.NotAfter.After(time.Now().Add(renewalInterval)), nil
}

// LeafNeedsRotation reports whether the webhook leaf certificate expires at
// or before the next renewal interval. Missing Secrets, empty key material
// and unparsable PEM are treated as needing rotation with a nil error, so
// the renewal pass converges by re-issuing the pair instead of aborting until
// a process restart. Transient API errors are still returned for retry.
func (c *CertRenewer) LeafNeedsRotation(props CertificateProps) (bool, error) {
	secret, err := c.secretInterface.Get(context.Background(), GenerateTLSPairSecretName(props), metav1.GetOptions{})
	if k8errors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	certPEM := secret.Data[v1.TLSCertKey]
	if len(certPEM) == 0 {
		return true, nil
	}
	needsRotation, err := certExpiresBefore(certPEM, c.certRenewalInterval)
	if err != nil {
		// Corrupt PEM cannot be repaired in place: rotate rather than abort.
		return true, nil
	}
	return needsRotation, nil
}

// CANeedsRotation reports whether the root CA certificate expires at or
// before the next renewal interval. As with LeafNeedsRotation, a missing
// Secret, empty key material or unparsable PEM requires rotation and is
// reported with a nil error, while transient API errors are propagated.
func (c *CertRenewer) CANeedsRotation(props CertificateProps) (bool, error) {
	secret, err := c.secretInterface.Get(context.Background(), GenerateRootCASecretName(props), metav1.GetOptions{})
	if k8errors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	caPEM := secret.Data[RootCAKey]
	if len(caPEM) == 0 {
		return true, nil
	}
	needsRotation, err := certExpiresBefore(caPEM, c.certRenewalInterval)
	if err != nil {
		// Corrupt PEM cannot be repaired in place: rotate rather than abort.
		return true, nil
	}
	return needsRotation, nil
}

// WriteCACertToSecret stores the CA cert and private key in secret.
//
// When the Secret already holds a different root CA, the old certificate is
// moved to PreviousRootCAKey so webhook caBundles can trust both CAs during
// the rotation, and PreviousCARotatedAtAnnotation records the handover time.
func (c *CertRenewer) WriteCACertToSecret(caPEM *PemPair, secretName string) error {
	secret, err := c.secretInterface.Get(context.Background(), secretName, metav1.GetOptions{})
	if err == nil {
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}

		previousCA := secret.Data[RootCAKey]
		if len(previousCA) > 0 && !bytes.Equal(previousCA, caPEM.Certificate) {
			secret.Data[PreviousRootCAKey] = previousCA
			secret.Annotations[PreviousCARotatedAtAnnotation] = time.Now().Format(time.RFC3339)
		}
		secret.Data[RootCAKey] = caPEM.Certificate
		secret.Data[RootCAPrivateKeyKey] = caPEM.PrivateKey
		secret.Annotations[SelfSignedAnnotation] = "true"
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
					RootCAKey:           caPEM.Certificate,
					RootCAPrivateKeyKey: caPEM.PrivateKey,
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

// RotateRootCA mints a brand-new root CA and a leaf signed by it. The
// previous CA certificate is preserved in the CA Secret (PreviousRootCAKey)
// so webhook caBundles can trust both CAs until the old CA is retired.
// The returned pair is the new webhook server's leaf certificate.
func (c *CertRenewer) RotateRootCA(props CertificateProps) (*PemPair, error) {
	caCert, caPEM, err := GenerateCACert(c.certValidityDuration)
	if err != nil {
		return nil, err
	}

	secretName := GenerateRootCASecretName(props)
	if err := c.WriteCACertToSecret(caPEM, secretName); err != nil {
		return nil, fmt.Errorf("failed to write or update CA cert to secret %s: %v", secretName, err)
	}

	tlsPair, err := GenerateCertPem(caCert, props, c.certValidityDuration, c.managerIP, c.inContainer)
	if err != nil {
		return nil, err
	}

	secretName = GenerateTLSPairSecretName(props)
	if err = c.WriteTLSPairToSecret(tlsPair, secretName); err != nil {
		return nil, fmt.Errorf("unable to save TLS pair to the secret %s: %v", secretName, err)
	}

	return tlsPair, nil
}

// parseCAKeyPair rebuilds the signing KeyPair from the PEM material stored in
// the CA Secret. The private key is only present in Secrets created (or
// rotated) after key persistence was introduced.
func parseCAKeyPair(caCertPEM, caKeyPEM []byte) (*KeyPair, error) {
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode root CA certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root CA certificate: %v", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, ErrCAPrivateKeyUnavailable
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root CA private key: %v", err)
	}

	return &KeyPair{Cert: cert, Key: key}, nil
}

// RotateLeafCert issues a fresh webhook leaf signed by the current root CA
// without touching the CA Secret or the webhook caBundle. Replicas pick the
// new pair up through the CertProvider's Secret informer hot-reload, so no
// manager restart is involved.
//
// It returns ErrCAPrivateKeyUnavailable when the CA Secret predates private
// key persistence; the caller must fall back to RotateRootCA in that case.
func (c *CertRenewer) RotateLeafCert(props CertificateProps) (*PemPair, error) {
	caSecret, err := c.secretInterface.Get(context.Background(), GenerateRootCASecretName(props), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	caKeyPair, err := parseCAKeyPair(caSecret.Data[RootCAKey], caSecret.Data[RootCAPrivateKeyKey])
	if err != nil {
		return nil, err
	}

	tlsPair, err := GenerateCertPem(caKeyPair, props, c.certValidityDuration, c.managerIP, c.inContainer)
	if err != nil {
		return nil, err
	}

	secretName := GenerateTLSPairSecretName(props)
	if err = c.WriteTLSPairToSecret(tlsPair, secretName); err != nil {
		return nil, fmt.Errorf("unable to save TLS pair to the secret %s: %v", secretName, err)
	}

	return tlsPair, nil
}

// RetirePreviousCA drops the previous root CA and its handover timestamp from
// the CA Secret. After this the webhook caBundle carries the current CA only.
// It is a no-op when the Secret or the previous CA is absent.
func (c *CertRenewer) RetirePreviousCA(props CertificateProps) error {
	secretName := GenerateRootCASecretName(props)
	secret, err := c.secretInterface.Get(context.Background(), secretName, metav1.GetOptions{})
	if k8errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, ok := secret.Data[PreviousRootCAKey]; !ok {
		return nil
	}

	delete(secret.Data, PreviousRootCAKey)
	delete(secret.Annotations, PreviousCARotatedAtAnnotation)
	_, err = c.secretInterface.Update(context.Background(), secret, metav1.UpdateOptions{})
	return err
}

// PreviousCARotatedAt returns the handover timestamp recorded when the current
// root CA replaced the previous one. It reports false when no previous CA is
// being retained.
func (c *CertRenewer) PreviousCARotatedAt(props CertificateProps) (time.Time, bool, error) {
	secret, err := c.secretInterface.Get(context.Background(), GenerateRootCASecretName(props), metav1.GetOptions{})
	if k8errors.IsNotFound(err) {
		// A missing CA Secret is bootstrapped by a later rotation step, so it
		// must not abort the renewal pass as if a previous CA were being tracked.
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if len(secret.Data[PreviousRootCAKey]) == 0 {
		return time.Time{}, false, nil
	}
	raw, ok := secret.Annotations[PreviousCARotatedAtAnnotation]
	if !ok {
		return time.Time{}, false, fmt.Errorf("CA Secret retains a previous CA but lacks the %q annotation", PreviousCARotatedAtAnnotation)
	}
	rotatedAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("failed to parse %q: %v", PreviousCARotatedAtAnnotation, err)
	}
	return rotatedAt, true, nil
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
	return c.RotateRootCA(certProps)
}

// RollingUpdateVarmorManager triggers a rolling update of varmor-manager pod.
//
// It is no longer part of the steady-state renewal path: leaf rotations are
// hot-reloaded from the Secret informer and CA rotations rely on the dual-CA
// caBundle. It is retained as an operational escape hatch for environments
// where an in-place certificate recovery is not possible.
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
