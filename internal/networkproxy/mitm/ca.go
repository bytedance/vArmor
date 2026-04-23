/*
Copyright The vArmor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	// caValidityYears is the validity period for the auto-generated CA certificate.
	caValidityYears = 10

	// clockSkewTolerance is the time to subtract from NotBefore to handle
	// minor clock differences between containers in the same Pod.
	clockSkewTolerance = 5 * time.Minute

	// caCommonName is the CN used for the auto-generated CA certificate.
	caCommonName = "vArmor MITM CA"

	// caOrganization is the O used for the auto-generated CA certificate.
	caOrganization = "vArmor"
)

// CACertificate holds the PEM-encoded CA certificate and private key.
type CACertificate struct {
	// CertPEM is the PEM-encoded CA certificate.
	CertPEM []byte
	// KeyPEM is the PEM-encoded CA private key (ECDSA P-256).
	KeyPEM []byte
	// Cert is the parsed x509 certificate (for signing leaf certificates).
	Cert *x509.Certificate
	// Key is the parsed ECDSA private key (for signing leaf certificates).
	Key *ecdsa.PrivateKey
}

// GenerateCA creates a new self-signed CA certificate with ECDSA P-256.
//
// The generated CA has:
//   - 10-year validity
//   - NotBefore set to 5 minutes before now (clock skew tolerance)
//   - KeyUsage: CertSign, CRLSign
//   - IsCA: true, MaxPathLen: 0 (can only sign leaf certs, not intermediate CAs)
func GenerateCA() (*CACertificate, error) {
	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{caOrganization},
		},
		NotBefore:             now.Add(-clockSkewTolerance),
		NotAfter:              now.AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign: parent == template
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse back to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &CACertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		Key:     privateKey,
	}, nil
}

// ParseCA parses PEM-encoded CA certificate and key back into a CACertificate.
// This is used when loading an existing CA from a Secret during reconcile.
func ParseCA(certPEM, keyPEM []byte) (*CACertificate, error) {
	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return &CACertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		Key:     key,
	}, nil
}

// generateSerialNumber returns a random 128-bit serial number.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
