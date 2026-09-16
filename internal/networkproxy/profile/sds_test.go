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

package profile

import (
	"bytes"
	"crypto/tls"
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/encoding/protojson"

	mitm "github.com/bytedance/vArmor/internal/networkproxy/mitm"
)

func TestTLSSecretsMaterialAndValidation(t *testing.T) {
	a, err := mitm.GenerateMITMMaterial([]string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := mitm.GenerateMITMMaterial([]string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	cert, validation, err := GenerateTLSSecrets(a.Leaf.CertPEM, a.Leaf.KeyPEM, a.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) (*discoveryv3.DiscoveryResponse, *tlsv3.Secret) {
		var response discoveryv3.DiscoveryResponse
		if err := protojson.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Resources) != 1 || response.VersionInfo == "" {
			t.Fatal("missing version or secret")
		}
		var secret tlsv3.Secret
		if err := response.Resources[0].UnmarshalTo(&secret); err != nil {
			t.Fatal(err)
		}
		if err := secret.ValidateAll(); err != nil {
			t.Fatal(err)
		}
		return &response, &secret
	}
	ca, s := decode(cert)
	if s.Name != MITMCertSecretName || s.GetTlsCertificate() == nil {
		t.Fatal("wrong certificate secret")
	}
	value := s.GetTlsCertificate()
	if !bytes.Equal([]byte(value.CertificateChain.GetInlineString()), a.Leaf.CertPEM) || !bytes.Equal([]byte(value.PrivateKey.GetInlineString()), a.Leaf.KeyPEM) {
		t.Fatal("material changed during encoding")
	}
	if _, err := tls.X509KeyPair([]byte(value.CertificateChain.GetInlineString()), []byte(value.PrivateKey.GetInlineString())); err != nil {
		t.Fatal(err)
	}
	_, s = decode(validation)
	if s.Name != MITMValidationSecretName || s.GetValidationContext() == nil || s.GetValidationContext().GetTrustedCa().GetInlineString() != string(a.Bundle) {
		t.Fatal("wrong trust secret")
	}
	next, _, err := GenerateTLSSecrets(b.Leaf.CertPEM, b.Leaf.KeyPEM, b.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := decode(next)
	if ca.VersionInfo == cb.VersionInfo {
		t.Fatal("material rotation did not change version")
	}
	for _, tc := range []struct {
		name              string
		cert, key, bundle []byte
	}{
		{"mismatched key", a.Leaf.CertPEM, b.Leaf.KeyPEM, a.Bundle},
		{"invalid cert", []byte("bad"), a.Leaf.KeyPEM, a.Bundle},
		{"invalid trust", a.Leaf.CertPEM, a.Leaf.KeyPEM, []byte("bad")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := GenerateTLSSecrets(tc.cert, tc.key, tc.bundle); err == nil {
				t.Fatal("invalid material accepted")
			}
		})
	}
}
