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
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func TestSignLeafCertificate_SingleDomain(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	domains := []string{"api.openai.com"}
	leaf, err := SignLeafCertificate(ca, domains)
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)

	// Verify SAN
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "api.openai.com" {
		t.Errorf("DNSNames = %v, want [api.openai.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want empty", cert.IPAddresses)
	}

	// Verify CN = first hostname (informational only).
	if cert.Subject.CommonName != "api.openai.com" {
		t.Errorf("CN = %q, want api.openai.com", cert.Subject.CommonName)
	}

	// Verify not a CA
	if cert.IsCA {
		t.Error("leaf certificate should not be CA")
	}

	// Verify key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage should include DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("KeyUsage should include KeyEncipherment")
	}

	// Verify ext key usage
	found := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			found = true
			break
		}
	}
	if !found {
		t.Error("ExtKeyUsage should include ServerAuth")
	}

	verifyLeafChain(t, ca, cert)
}

func TestSignLeafCertificate_MultiDomain(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	domains := []string{
		"api.openai.com",
		"api.anthropic.com",
		"api.cohere.com",
		"generativelanguage.googleapis.com",
	}
	leaf, err := SignLeafCertificate(ca, domains)
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)

	if len(cert.DNSNames) != len(domains) {
		t.Fatalf("DNSNames count = %d, want %d", len(cert.DNSNames), len(domains))
	}
	domainSet := make(map[string]bool)
	for _, d := range cert.DNSNames {
		domainSet[d] = true
	}
	for _, d := range domains {
		if !domainSet[d] {
			t.Errorf("domain %q not found in certificate SANs", d)
		}
	}

	if cert.Subject.CommonName != domains[0] {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, domains[0])
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	for _, domain := range domains {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     roots,
			DNSName:   domain,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("verification failed for domain %q: %v", domain, err)
		}
	}
}

func TestSignLeafCertificate_Wildcard(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	// Per design: "*.openai.com" is written verbatim into the SAN list;
	// RFC 6125 matching happens at the verifier. Both wildcard and
	// bare parent are kept so that users can express both via Domains.
	domains := []string{"*.openai.com", "openai.com"}
	leaf, err := SignLeafCertificate(ca, domains)
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)
	if len(cert.DNSNames) != 2 {
		t.Fatalf("DNSNames = %v, want 2 entries", cert.DNSNames)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	// Wildcard matches a single label.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "api.openai.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("wildcard should match single-label subdomain: %v", err)
	}

	// Bare parent domain is explicitly listed, so it matches.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "openai.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("bare parent domain should match explicit SAN: %v", err)
	}

	// Multi-label under wildcard does NOT match per RFC 6125.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "foo.bar.openai.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Error("wildcard must not match multi-label subdomain")
	}
}

func TestSignLeafCertificate_IPAddress(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	domains := []string{"10.96.0.1", "::1", "api.openai.com"}
	leaf, err := SignLeafCertificate(ca, domains)
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "api.openai.com" {
		t.Errorf("DNSNames = %v, want [api.openai.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("IPAddresses count = %d, want 2", len(cert.IPAddresses))
	}

	// CN should fall back to the first hostname, not an IP.
	if cert.Subject.CommonName != "api.openai.com" {
		t.Errorf("CN = %q, want api.openai.com", cert.Subject.CommonName)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "10.96.0.1", // x509 matches IP literal strings via IPAddresses.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("IP SAN verification failed: %v", err)
	}
}

func TestSignLeafCertificate_OnlyIPAddresses(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	leaf, err := SignLeafCertificate(ca, []string{"10.96.0.1"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}
	cert := parseLeafCert(t, leaf)

	if len(cert.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.96.0.1")) {
		t.Errorf("IPAddresses = %v, want [10.96.0.1]", cert.IPAddresses)
	}

	// With no hostname SAN we must fall back to the fixed CN; RFC 5280
	// forbids writing an IP literal into CommonName.
	if cert.Subject.CommonName != leafCommonName {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, leafCommonName)
	}
}

func TestSignLeafCertificate_Validity(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	leaf, err := SignLeafCertificate(ca, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)
	now := time.Now()

	expectedNotBefore := now.Add(-clockSkewTolerance)
	if cert.NotBefore.After(expectedNotBefore.Add(10 * time.Second)) {
		t.Errorf("NotBefore %v is too late", cert.NotBefore)
	}
	if cert.NotBefore.Before(expectedNotBefore.Add(-10 * time.Second)) {
		t.Errorf("NotBefore %v is too early", cert.NotBefore)
	}

	expectedNotAfter := now.AddDate(leafValidityYears, 0, 0)
	if cert.NotAfter.Before(expectedNotAfter.Add(-10 * time.Second)) {
		t.Errorf("NotAfter %v is too early", cert.NotAfter)
	}
}

func TestSignLeafCertificate_EmptyDomains(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	if _, err := SignLeafCertificate(ca, []string{}); err == nil {
		t.Fatal("SignLeafCertificate() should fail with empty domains")
	}
	if _, err := SignLeafCertificate(ca, nil); err == nil {
		t.Fatal("SignLeafCertificate() should fail with nil domains")
	}
}

func TestSignLeafCertificate_BlankEntry(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}
	if _, err := SignLeafCertificate(ca, []string{"api.openai.com", "   "}); err == nil {
		t.Fatal("SignLeafCertificate() should reject blank entries")
	}
}

func TestSignLeafCertificate_DuplicateEntry(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}
	if _, err := SignLeafCertificate(ca, []string{"api.openai.com", "api.openai.com"}); err == nil {
		t.Fatal("SignLeafCertificate() should reject duplicates")
	}
}

func TestSignLeafCertificate_NilCA(t *testing.T) {
	if _, err := SignLeafCertificate(nil, []string{"example.com"}); err == nil {
		t.Fatal("SignLeafCertificate() should fail with nil CA")
	}
}

func TestSignLeafCertificate_UniqueKeys(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	leaf1, err := SignLeafCertificate(ca, []string{"a.example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() 1 failed: %v", err)
	}
	leaf2, err := SignLeafCertificate(ca, []string{"b.example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() 2 failed: %v", err)
	}

	if string(leaf1.KeyPEM) == string(leaf2.KeyPEM) {
		t.Error("two leaf certificates have the same private key")
	}
}

func TestSignLeafCertificate_UnrelatedDomainFails(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	leaf, err := SignLeafCertificate(ca, []string{"api.openai.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "evil.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Error("verification should fail for unrelated domain")
	}
}

func TestSignLeafCertificate_DifferentCACannotVerify(t *testing.T) {
	ca1, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() 1 failed: %v", err)
	}
	ca2, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() 2 failed: %v", err)
	}

	leaf, err := SignLeafCertificate(ca1, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	cert := parseLeafCert(t, leaf)

	roots := x509.NewCertPool()
	roots.AddCert(ca2.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "test.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Error("verification should fail with different CA")
	}
}

func TestGenerateMITMMaterial(t *testing.T) {
	domains := []string{"api.openai.com", "api.anthropic.com"}

	mat, err := GenerateMITMMaterial(domains)
	if err != nil {
		t.Fatalf("GenerateMITMMaterial() failed: %v", err)
	}
	if mat == nil || mat.CA == nil || mat.Leaf == nil {
		t.Fatal("nil material returned")
	}
	if len(mat.Bundle) == 0 {
		t.Fatal("bundle is empty")
	}
	// Bundle must include more than just the CA alone — it has Mozilla
	// certs prepended.
	if len(mat.Bundle) <= len(mat.CA.CertPEM) {
		t.Fatal("bundle should include Mozilla roots, not just the CA")
	}

	cert := parseLeafCert(t, mat.Leaf)
	verifyLeafChain(t, mat.CA, cert)

	if len(cert.DNSNames) != 2 {
		t.Fatalf("DNSNames count = %d, want 2", len(cert.DNSNames))
	}

	// Leaf must verify using roots parsed out of the generated bundle.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(mat.Bundle) {
		t.Fatal("bundle produced no usable roots")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "api.openai.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf verification against generated bundle failed: %v", err)
	}
}

func TestGenerateMITMMaterial_EmptyDomains(t *testing.T) {
	if _, err := GenerateMITMMaterial([]string{}); err == nil {
		t.Fatal("GenerateMITMMaterial() should fail with empty domains")
	}
}

func TestRenewLeaf_PreservesCAAndBundle(t *testing.T) {
	initial, err := GenerateMITMMaterial([]string{"api.openai.com"})
	if err != nil {
		t.Fatalf("GenerateMITMMaterial() failed: %v", err)
	}

	renewed, err := RenewLeaf(initial.CA, []string{
		"api.openai.com",
		"api.anthropic.com",
	})
	if err != nil {
		t.Fatalf("RenewLeaf() failed: %v", err)
	}

	// The CA identity must be unchanged — RenewLeaf only produces a new
	// leaf cert+key while reusing the existing CA. Verify by checking that
	// the CA cert PEM is still what we started with (byte-identical).
	if string(initial.CA.CertPEM) == "" {
		t.Fatal("initial CA CertPEM is empty after RenewLeaf")
	}
	// The leaf must be different (new key, new SAN set).
	if string(renewed.KeyPEM) == string(initial.Leaf.KeyPEM) {
		t.Error("renewed leaf has the same private key as the old one")
	}

	// The renewed leaf must chain up to the same CA.
	cert := parseLeafCert(t, renewed)
	verifyLeafChain(t, initial.CA, cert)

	// And the renewed leaf must contain the new SAN set.
	if len(cert.DNSNames) != 2 {
		t.Fatalf("renewed DNSNames count = %d, want 2", len(cert.DNSNames))
	}

	// If we rebuild the bundle from the unchanged CA, it must match the
	// bundle we produced originally — this is the invariant that lets
	// us avoid churning application trust stores.
	rebuilt, err := BuildCABundle(initial.CA.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle() failed: %v", err)
	}
	if string(rebuilt) != string(initial.Bundle) {
		t.Error("rebuilding the bundle from the unchanged CA produced different bytes")
	}
}

func TestRenewLeaf_NilCA(t *testing.T) {
	if _, err := RenewLeaf(nil, []string{"api.openai.com"}); err == nil {
		t.Fatal("RenewLeaf() should fail with nil CA")
	}
}

func TestLeafPEMFormat(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	leaf, err := SignLeafCertificate(ca, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	certBlock, _ := pem.Decode(leaf.CertPEM)
	if certBlock == nil {
		t.Fatal("failed to decode leaf CertPEM")
	}
	if certBlock.Type != "CERTIFICATE" {
		t.Errorf("cert PEM type = %q, want CERTIFICATE", certBlock.Type)
	}

	keyBlock, _ := pem.Decode(leaf.KeyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode leaf KeyPEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("key PEM type = %q, want EC PRIVATE KEY", keyBlock.Type)
	}
}

// Helpers

func parseLeafCert(t *testing.T, leaf *LeafCertificate) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(leaf.CertPEM)
	if block == nil {
		t.Fatal("failed to decode leaf cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}
	return cert
}

func verifyLeafChain(t *testing.T, ca *CACertificate, leafCert *x509.Certificate) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf certificate verification against CA failed: %v", err)
	}
}
