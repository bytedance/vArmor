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

package audit

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	mitm "github.com/bytedance/vArmor/internal/networkproxy/mitm"
)

// Use production-issued certificates, not the synthetic certificates used by
// routing-only tests. Each case starts a fresh Envoy and verifies its actual
// peer certificate, so stale TLS material cannot hide a signing regression.
func TestMITMHostCIDREnvoyAudit(t *testing.T) {
	runMITMEgressEnvoyAudit(t, httpHostTestOptions{hostCIDRCertificate: true})
}

func mitmHostCIDRTestCertificate(t *testing.T, dir, domain string) (string, string, *x509.CertPool, []byte) {
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
