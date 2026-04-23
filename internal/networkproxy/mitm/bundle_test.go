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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestBuildCABundle(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	bundle, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle() failed: %v", err)
	}

	// Bundle should contain the Mozilla certs + vArmor CA
	if len(bundle) == 0 {
		t.Fatal("bundle is empty")
	}

	// Bundle should be larger than Mozilla bundle alone
	if len(bundle) <= len(MozillaCABundle()) {
		t.Error("bundle should be larger than Mozilla bundle alone")
	}

	// Bundle should end with the vArmor CA cert
	if !bytes.HasSuffix(bundle, ca.CertPEM) {
		t.Error("bundle should end with the vArmor CA certificate")
	}

	// Bundle should start with Mozilla bundle content
	if !bytes.HasPrefix(bundle, mozillaCABundle[:100]) {
		t.Error("bundle should start with Mozilla CA bundle")
	}
}

func TestBuildCABundle_ContainsVArmorCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	bundle, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle() failed: %v", err)
	}

	// Parse all certificates in the bundle
	var certs []*x509.Certificate
	remaining := bundle
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		t.Fatal("no certificates found in bundle")
	}

	// The last certificate should be our vArmor CA
	lastCert := certs[len(certs)-1]
	if lastCert.Subject.CommonName != caCommonName {
		t.Errorf("last cert CN = %q, want %q", lastCert.Subject.CommonName, caCommonName)
	}
	if !lastCert.IsCA {
		t.Error("last cert should be a CA")
	}

	// There should be multiple Mozilla CAs
	mozillaCount := 0
	for _, cert := range certs {
		if cert.Subject.CommonName != caCommonName {
			mozillaCount++
		}
	}
	if mozillaCount == 0 {
		t.Error("no Mozilla CA certificates found in bundle")
	}
	t.Logf("bundle contains %d Mozilla CAs + 1 vArmor CA = %d total", mozillaCount, len(certs))
}

func TestBuildCABundle_LeafVerifiableAgainstBundle(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	leaf, err := SignLeafCertificate(ca, []string{"api.openai.com"})
	if err != nil {
		t.Fatalf("SignLeafCertificate() failed: %v", err)
	}

	bundle, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle() failed: %v", err)
	}

	// Build a cert pool from the bundle
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		t.Fatal("failed to parse any certificates from bundle")
	}

	// Parse leaf cert
	leafBlock, _ := pem.Decode(leaf.CertPEM)
	if leafBlock == nil {
		t.Fatal("failed to decode leaf cert PEM")
	}
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	// Verify leaf against the full bundle
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "api.openai.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("leaf verification against bundle failed: %v", err)
	}
}

func TestBuildCABundle_EmptyCACert(t *testing.T) {
	_, err := BuildCABundle([]byte{})
	if err == nil {
		t.Fatal("BuildCABundle() should fail with empty CA cert")
	}
}

func TestBuildCABundle_NilCACert(t *testing.T) {
	_, err := BuildCABundle(nil)
	if err == nil {
		t.Fatal("BuildCABundle() should fail with nil CA cert")
	}
}

func TestMozillaCABundle_NotEmpty(t *testing.T) {
	bundle := MozillaCABundle()
	if len(bundle) == 0 {
		t.Fatal("embedded Mozilla CA bundle is empty")
	}

	// Should contain at least some PEM certificate blocks
	certCount := strings.Count(string(bundle), "-----BEGIN CERTIFICATE-----")
	if certCount == 0 {
		t.Fatal("no PEM certificates found in Mozilla bundle")
	}
	t.Logf("Mozilla bundle contains %d certificates, %d bytes", certCount, len(bundle))
}

func TestBuildCABundle_NewlineSeparation(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	bundle, err := BuildCABundle(ca.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle() failed: %v", err)
	}

	// The upstream Mozilla bundle legitimately contains "\n\n\n"
	// between section headers and the following certificate, so we
	// cannot assert on absence of triple newlines globally. What we
	// actually care about is the Mozilla/vArmor-CA junction: the
	// embedded bundle should appear verbatim at the start, followed by
	// at most a single separating newline and then the CA PEM.
	if !bytes.HasPrefix(bundle, mozillaCABundle) {
		t.Fatal("bundle does not start with the embedded Mozilla bundle")
	}
	tail := bundle[len(mozillaCABundle):]
	switch {
	case bytes.Equal(tail, ca.CertPEM):
		// Mozilla bundle already ended with a newline; nothing inserted.
	case len(tail) > 0 && tail[0] == '\n' && bytes.Equal(tail[1:], ca.CertPEM):
		// Exactly one separating newline was inserted by BuildCABundle.
	default:
		preview := tail
		if len(preview) > 64 {
			preview = preview[:64]
		}
		t.Fatalf("unexpected content at Mozilla/CA junction: %q", string(preview))
	}
}
