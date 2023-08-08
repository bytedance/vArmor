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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/bytedance/vArmor/internal/config"
)

// CertificateProps Properties of TLS certificate which should be issued for webhook server.
type CertificateProps struct {
	Service       string
	Namespace     string
	APIServerHost string
	ServerIP      string
}

// PemPair The pair of TLS certificate corresponding private key, both in PEM format.
type PemPair struct {
	Certificate []byte
	PrivateKey  []byte
}

// KeyPair ...
type KeyPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// CertificateToPem ...
func CertificateToPem(certificateDER []byte) []byte {
	certificate := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	}

	return pem.EncodeToMemory(certificate)
}

// PrivateKeyToPem Creates PEM block from private key object.
func PrivateKeyToPem(rsaKey *rsa.PrivateKey) []byte {
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}

	return pem.EncodeToMemory(privateKey)
}

// GenerateCACert creates the self-signed CA cert and private key.
// It will be used to sign the webhook server certificate.
func GenerateCACert(certValidityDuration time.Duration) (*KeyPair, *PemPair, error) {
	now := time.Now()
	begin := now.Add(-1 * time.Hour)
	end := now.Add(certValidityDuration)

	templ := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: config.CertCommonName,
		},
		NotBefore:             begin,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key: %v", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, templ, templ, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate: %v", err)
	}

	pemPair := &PemPair{
		Certificate: CertificateToPem(der),
		PrivateKey:  PrivateKeyToPem(key),
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate %v", err)
	}

	caCert := &KeyPair{
		Cert: cert,
		Key:  key,
	}

	return caCert, pemPair, nil
}

// GenerateCertPem takes the results of GenerateCACert and uses it to create the
// PEM-encoded public certificate and private key, respectively.
func GenerateCertPem(caCert *KeyPair, props CertificateProps, certValidityDuration time.Duration, managerIP string, debug bool) (*PemPair, error) {
	now := time.Now()
	begin := now.Add(-1 * time.Hour)
	end := now.Add(certValidityDuration)

	csCommonName := props.Service
	dnsNames := make([]string, 3)
	dnsNames[0] = csCommonName
	dnsNames[1] = fmt.Sprintf("%s.%s", props.Service, props.Namespace)
	dnsNames[2] = GenerateInClusterServiceName(props)

	var ips []net.IP
	apiServerIP := net.ParseIP(props.APIServerHost)
	if apiServerIP != nil {
		ips = append(ips, apiServerIP)
	} else {
		dnsNames = append(dnsNames, props.APIServerHost)
	}

	if managerIP != "" && debug {
		if strings.Contains(managerIP, ":") {
			host, _, _ := net.SplitHostPort(managerIP)
			managerIP = host
		}

		ip := net.ParseIP(managerIP)
		ips = append(ips, ip)
	}

	templ := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: csCommonName,
		},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             begin,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating key for webhook %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, templ, caCert.Cert, key.Public(), caCert.Key)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate for webhook %v", err)
	}

	pemPair := &PemPair{
		Certificate: CertificateToPem(der),
		PrivateKey:  PrivateKeyToPem(key),
	}

	return pemPair, nil
}
