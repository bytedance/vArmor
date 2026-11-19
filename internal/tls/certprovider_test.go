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

package tls

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testPemPair(t *testing.T) *PemPair {
	t.Helper()
	ca, _, err := GenerateCACert(time.Hour)
	require.NoError(t, err)
	props := CertificateProps{Service: "varmor-webhook", Namespace: "varmor", APIServerHost: "varmor.example.com"}
	pair, err := GenerateCertPem(ca, props, time.Hour, "", true)
	require.NoError(t, err)
	return pair
}

func certDER(t *testing.T, p *CertProvider) []byte {
	t.Helper()
	cert, err := p.GetCertificate(nil)
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
	return cert.Certificate[0]
}

func TestNewCertProvider_RejectsNil(t *testing.T) {
	_, err := NewCertProvider(nil, logr.Discard())
	assert.Error(t, err)
}

func TestNewCertProvider_RejectsMalformedInitialPair(t *testing.T) {
	_, err := NewCertProvider(&PemPair{Certificate: []byte("not-a-cert"), PrivateKey: []byte("not-a-key")}, logr.Discard())
	assert.Error(t, err)
}

func TestCertProvider_GetCertificateServesInitialPair(t *testing.T) {
	pair := testPemPair(t)
	provider, err := NewCertProvider(pair, logr.Discard())
	require.NoError(t, err)

	cert, err := provider.GetCertificate(nil)
	require.NoError(t, err)
	expected, err := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, expected.Certificate, cert.Certificate)
}

func TestCertProvider_UpdateSwapsCertificate(t *testing.T) {
	provider, err := NewCertProvider(testPemPair(t), logr.Discard())
	require.NoError(t, err)
	first := certDER(t, provider)

	require.NoError(t, provider.Update(testPemPair(t)))
	second := certDER(t, provider)
	assert.NotEqual(t, first, second)
}

func TestCertProvider_UpdateKeepsLastGoodOnMalformedPair(t *testing.T) {
	provider, err := NewCertProvider(testPemPair(t), logr.Discard())
	require.NoError(t, err)
	good := certDER(t, provider)

	err = provider.Update(&PemPair{Certificate: []byte("bad-cert"), PrivateKey: []byte("bad-key")})
	assert.Error(t, err)
	assert.Equal(t, good, certDER(t, provider), "the last-good certificate must still be served")

	err = provider.Update(nil)
	assert.Error(t, err)
	assert.Equal(t, good, certDER(t, provider))
}

func TestCertProvider_HandleSecret_IgnoresUnrelatedAndEmptyUpdates(t *testing.T) {
	pair := testPemPair(t)
	provider, err := NewCertProvider(pair, logr.Discard())
	require.NoError(t, err)
	initial := certDER(t, provider)

	assert.False(t, provider.HandleSecret(nil, "varmor-webhook.varmor.varmor-tls-pair"))

	wrongName := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "some-other-secret"}}
	assert.False(t, provider.HandleSecret(wrongName, "varmor-webhook.varmor.varmor-tls-pair"))
	assert.Equal(t, initial, certDER(t, provider))

	emptyData := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "varmor-webhook.varmor.varmor-tls-pair"},
		Data:       map[string][]byte{},
	}
	assert.False(t, provider.HandleSecret(emptyData, "varmor-webhook.varmor.varmor-tls-pair"))
	assert.Equal(t, initial, certDER(t, provider))
}

func TestCertProvider_HandleSecret_HotReloadsValidPair(t *testing.T) {
	provider, err := NewCertProvider(testPemPair(t), logr.Discard())
	require.NoError(t, err)
	initial := certDER(t, provider)

	rotated := testPemPair(t)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "varmor-webhook.varmor.varmor-tls-pair"},
		Data: map[string][]byte{
			v1.TLSCertKey:       rotated.Certificate,
			v1.TLSPrivateKeyKey: rotated.PrivateKey,
		},
	}
	assert.True(t, provider.HandleSecret(secret, "varmor-webhook.varmor.varmor-tls-pair"))
	assert.NotEqual(t, initial, certDER(t, provider))
}

func TestCertProvider_HandleSecret_KeepsLastGoodOnMalformedSecret(t *testing.T) {
	provider, err := NewCertProvider(testPemPair(t), logr.Discard())
	require.NoError(t, err)
	initial := certDER(t, provider)

	bad := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "varmor-webhook.varmor.varmor-tls-pair"},
		Data: map[string][]byte{
			v1.TLSCertKey:       []byte("bad"),
			v1.TLSPrivateKeyKey: []byte("bad"),
		},
	}
	assert.False(t, provider.HandleSecret(bad, "varmor-webhook.varmor.varmor-tls-pair"))
	assert.Equal(t, initial, certDER(t, provider))
}
