//go:build envoyintegration

// Copyright 2026 vArmor Authors
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

package networkproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	mitm "github.com/bytedance/vArmor/internal/networkproxy/mitm"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

func testCertificate(t *testing.T, dir, host string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		template.DNSNames = nil
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPath, keyPath := filepath.Join(dir, "leaf.crt"), filepath.Join(dir, "leaf.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid test certificate")
	}
	return certPath, keyPath, roots
}

// certificateSDS publishes the certificate fixture through the production
// SDS encoder, keeping the audit matrix on the actual dynamic TLS path.
func certificateSDS(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := profile.GenerateTLSSecrets(cert, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	path := certPath + ".sds.json"
	if err := os.WriteFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hostCIDRCertificate(t *testing.T, dir, domain string) (string, string, *x509.CertPool, []byte) {
	t.Helper()
	material, err := mitm.GenerateMITMMaterial([]string{domain})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(material.Leaf.CertPEM, material.Leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "leaf.crt"), filepath.Join(dir, "leaf.key")
	if err := os.WriteFile(certPath, material.Leaf.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, material.Leaf.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(material.CA.Cert)
	return certPath, keyPath, roots, pair.Certificate[0]
}
