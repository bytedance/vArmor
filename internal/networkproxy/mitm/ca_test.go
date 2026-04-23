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
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Verify PEM outputs are non-empty
	if len(ca.CertPEM) == 0 {
		t.Fatal("CA CertPEM is empty")
	}
	if len(ca.KeyPEM) == 0 {
		t.Fatal("CA KeyPEM is empty")
	}

	// Verify parsed objects
	if ca.Cert == nil {
		t.Fatal("CA Cert is nil")
	}
	if ca.Key == nil {
		t.Fatal("CA Key is nil")
	}

	// Verify it's a CA certificate
	if !ca.Cert.IsCA {
		t.Error("certificate IsCA should be true")
	}
	if !ca.Cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be true")
	}
	if ca.Cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", ca.Cert.MaxPathLen)
	}

	// Verify subject
	if ca.Cert.Subject.CommonName != caCommonName {
		t.Errorf("CN = %q, want %q", ca.Cert.Subject.CommonName, caCommonName)
	}
	if len(ca.Cert.Subject.Organization) == 0 || ca.Cert.Subject.Organization[0] != caOrganization {
		t.Errorf("Organization = %v, want [%s]", ca.Cert.Subject.Organization, caOrganization)
	}

	// Verify algorithm
	if ca.Key.Curve != elliptic.P256() {
		t.Error("expected ECDSA P-256 key")
	}

	// Verify key usage
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("KeyUsage should include CertSign")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("KeyUsage should include CRLSign")
	}

	// Verify validity period
	now := time.Now()
	expectedNotBefore := now.Add(-clockSkewTolerance)
	expectedNotAfter := now.AddDate(caValidityYears, 0, 0)

	// Allow 10 seconds tolerance for test execution time
	if ca.Cert.NotBefore.After(expectedNotBefore.Add(10 * time.Second)) {
		t.Errorf("NotBefore %v is too late (expected around %v)", ca.Cert.NotBefore, expectedNotBefore)
	}
	if ca.Cert.NotBefore.Before(expectedNotBefore.Add(-10 * time.Second)) {
		t.Errorf("NotBefore %v is too early (expected around %v)", ca.Cert.NotBefore, expectedNotBefore)
	}
	if ca.Cert.NotAfter.Before(expectedNotAfter.Add(-10 * time.Second)) {
		t.Errorf("NotAfter %v is too early (expected around %v)", ca.Cert.NotAfter, expectedNotAfter)
	}

	// Verify self-signed (issuer == subject)
	if ca.Cert.Issuer.CommonName != ca.Cert.Subject.CommonName {
		t.Errorf("Issuer CN %q != Subject CN %q (not self-signed)", ca.Cert.Issuer.CommonName, ca.Cert.Subject.CommonName)
	}
}

func TestGenerateCA_UniqueSerials(t *testing.T) {
	ca1, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() 1 failed: %v", err)
	}
	ca2, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() 2 failed: %v", err)
	}

	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) == 0 {
		t.Error("two CA certificates have the same serial number")
	}
}

func TestGenerateCA_UniqueKeys(t *testing.T) {
	ca1, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() 1 failed: %v", err)
	}
	ca2, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() 2 failed: %v", err)
	}

	if ca1.Key.D.Cmp(ca2.Key.D) == 0 {
		t.Error("two CA keys are identical")
	}
}

func TestParseCA(t *testing.T) {
	// Generate a CA first
	original, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Parse it back
	parsed, err := ParseCA(original.CertPEM, original.KeyPEM)
	if err != nil {
		t.Fatalf("ParseCA() failed: %v", err)
	}

	// Verify parsed values match original
	if parsed.Cert.Subject.CommonName != original.Cert.Subject.CommonName {
		t.Errorf("parsed CN %q != original CN %q", parsed.Cert.Subject.CommonName, original.Cert.Subject.CommonName)
	}
	if !parsed.Cert.IsCA {
		t.Error("parsed certificate should be CA")
	}
	if parsed.Key.D.Cmp(original.Key.D) != 0 {
		t.Error("parsed key does not match original")
	}

	// Verify PEM roundtrip
	if string(parsed.CertPEM) != string(original.CertPEM) {
		t.Error("CertPEM roundtrip mismatch")
	}
	if string(parsed.KeyPEM) != string(original.KeyPEM) {
		t.Error("KeyPEM roundtrip mismatch")
	}
}

func TestParseCA_InvalidCertPEM(t *testing.T) {
	_, err := ParseCA([]byte("not a pem"), []byte("not a pem"))
	if err == nil {
		t.Fatal("ParseCA() should fail with invalid cert PEM")
	}
}

func TestParseCA_InvalidKeyPEM(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	_, err = ParseCA(ca.CertPEM, []byte("not a pem"))
	if err == nil {
		t.Fatal("ParseCA() should fail with invalid key PEM")
	}
}

func TestParseCA_NonCACertificate(t *testing.T) {
	// Generate a CA and leaf, then try to parse the leaf as CA
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}
	leaf, err := SignLeafCertificate(ca, []string{"example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	// Use leaf cert with CA key — should fail because cert is not CA
	_, err = ParseCA(leaf.CertPEM, ca.KeyPEM)
	if err == nil {
		t.Fatal("ParseCA() should fail when certificate is not a CA")
	}
}

func TestPEMFormat(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Verify cert PEM block type
	certBlock, _ := pem.Decode(ca.CertPEM)
	if certBlock == nil {
		t.Fatal("failed to decode CertPEM")
	}
	if certBlock.Type != "CERTIFICATE" {
		t.Errorf("cert PEM type = %q, want CERTIFICATE", certBlock.Type)
	}

	// Verify key PEM block type
	keyBlock, _ := pem.Decode(ca.KeyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode KeyPEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("key PEM type = %q, want EC PRIVATE KEY", keyBlock.Type)
	}

	// Verify the key is actually ECDSA P-256
	parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse EC private key: %v", err)
	}
	if parsedKey.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestCACanSignCertificates(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Verify the CA can actually sign a certificate
	leaf, err := SignLeafCertificate(ca, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	// Parse leaf and verify chain
	leafBlock, _ := pem.Decode(leaf.CertPEM)
	if leafBlock == nil {
		t.Fatal("failed to decode leaf cert PEM")
	}
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	// Verify with CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("leaf certificate verification against CA failed: %v", err)
	}
}
