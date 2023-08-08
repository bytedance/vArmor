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
	"fmt"
	"net/url"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	"github.com/bytedance/vArmor/internal/config"
)

const ErrorsNotFound = "root CA certificate not found"

func GenerateRootCASecretName(props CertificateProps) string {
	return props.Service + "." + props.Namespace + ".varmor-tls-ca"
}

func GenerateTLSPairSecretName(props CertificateProps) string {
	return props.Service + "." + props.Namespace + ".varmor-tls-pair"
}

// GenerateInClusterServiceName The generated service name should be the common name for TLS certificate.
func GenerateInClusterServiceName(props CertificateProps) string {
	return props.Service + "." + props.Namespace + ".svc"
}

// GetTLSCertProps provides the TLS Certificate Properties.
func GetTLSCertProps(configuration *rest.Config) (certProps CertificateProps, err error) {
	apiServerURL, err := url.Parse(configuration.Host)
	if err != nil {
		return certProps, err
	}

	certProps = CertificateProps{
		Service:       config.WebhookServiceName,
		Namespace:     config.Namespace,
		APIServerHost: apiServerURL.Hostname(),
	}
	return certProps, nil
}

// ReadRootCASecret returns the RootCA from the pre-defined secret.
func ReadRootCASecret(secretInterface corev1.SecretInterface, secretName string) (result []byte, err error) {
	tlsCA, err := secretInterface.Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	result = tlsCA.Data[RootCAKey]
	if len(result) == 0 {
		return nil, fmt.Errorf("root CA secret format error")
	}

	return result, nil
}

// ReadTLSPair returns the pem pair from the pre-defined secret.
func ReadTLSPair(secretInterface corev1.SecretInterface, secretName string) (*PemPair, error) {
	tlsPair, err := secretInterface.Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	pemPair := PemPair{
		Certificate: tlsPair.Data[v1.TLSCertKey],
		PrivateKey:  tlsPair.Data[v1.TLSPrivateKeyKey],
	}

	if len(pemPair.Certificate) == 0 {
		return nil, fmt.Errorf("TLS Certificate not found in secret %s", secretName)
	}
	if len(pemPair.PrivateKey) == 0 {
		return nil, fmt.Errorf("TLS PrivateKey not found in secret %s", secretName)
	}

	return &pemPair, nil
}

func IsVarmorManagerInRollingUpdate(deploy *appsv1.Deployment) bool {
	return deploy.Status.Replicas > *deploy.Spec.Replicas
}
