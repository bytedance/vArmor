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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func newTestRenewer(t *testing.T, initial ...runtime.Object) (*CertRenewer, CertificateProps) {
	t.Helper()
	restConfig := &rest.Config{Host: "https://varmor.example.com:6443"}
	// Use the same derivation as InitTLSPemPair so secret names line up.
	props, err := GetTLSCertProps(restConfig)
	require.NoError(t, err)
	client := fake.NewSimpleClientset(initial...)
	renewer := NewCertRenewer(
		restConfig,
		client.CoreV1().Secrets(props.Namespace),
		client.AppsV1().Deployments(props.Namespace),
		time.Hour,
		24*time.Hour,
		"",
		true,
		logr.Discard(),
	)
	return renewer, props
}

func readSecret(t *testing.T, renewer *CertRenewer, name string) *v1.Secret {
	t.Helper()
	secret, err := renewer.secretInterface.Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	return secret
}

func verifyLeafAgainstCA(t *testing.T, leafPEM, caPEM []byte) {
	t.Helper()
	caBlock, _ := pem.Decode(caPEM)
	require.NotNil(t, caBlock)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)

	leafBlock, _ := pem.Decode(leafPEM)
	require.NotNil(t, leafBlock)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now()})
	assert.NoError(t, err)
}

func TestRotateRootCA_PersistsKeyAndLeaf(t *testing.T) {
	renewer, props := newTestRenewer(t)

	pair, err := renewer.RotateRootCA(props)
	require.NoError(t, err)
	require.NotNil(t, pair)

	caSecret := readSecret(t, renewer, GenerateRootCASecretName(props))
	assert.NotEmpty(t, caSecret.Data[RootCAKey])
	assert.NotEmpty(t, caSecret.Data[RootCAPrivateKeyKey], "CA private key must be persisted for leaf-only rotation")
	assert.Empty(t, caSecret.Data[PreviousRootCAKey])
	assert.Equal(t, "true", caSecret.Annotations[SelfSignedAnnotation])

	pairSecret := readSecret(t, renewer, GenerateTLSPairSecretName(props))
	assert.Equal(t, pair.Certificate, pairSecret.Data[v1.TLSCertKey])
	verifyLeafAgainstCA(t, pairSecret.Data[v1.TLSCertKey], caSecret.Data[RootCAKey])
}

func TestRotateRootCA_PreservesPreviousCA(t *testing.T) {
	renewer, props := newTestRenewer(t)

	first, err := renewer.RotateRootCA(props)
	require.NoError(t, err)
	firstCA := readSecret(t, renewer, GenerateRootCASecretName(props)).Data[RootCAKey]

	second, err := renewer.RotateRootCA(props)
	require.NoError(t, err)
	assert.NotEqual(t, first.Certificate, second.Certificate)

	caSecret := readSecret(t, renewer, GenerateRootCASecretName(props))
	assert.Equal(t, firstCA, caSecret.Data[PreviousRootCAKey])
	assert.NotEqual(t, firstCA, caSecret.Data[RootCAKey])
	assert.NotEmpty(t, caSecret.Annotations[PreviousCARotatedAtAnnotation])
	_, err = time.Parse(time.RFC3339, caSecret.Annotations[PreviousCARotatedAtAnnotation])
	assert.NoError(t, err)

	// The new leaf must be signed by the new CA and both must be parseable.
	verifyLeafAgainstCA(t, caSecret.Data[PreviousRootCAKey], caSecret.Data[PreviousRootCAKey])
	verifyLeafAgainstCA(t, readSecret(t, renewer, GenerateTLSPairSecretName(props)).Data[v1.TLSCertKey], caSecret.Data[RootCAKey])
}

func TestRotateLeafCert_KeepsCASecretUntouched(t *testing.T) {
	renewer, props := newTestRenewer(t)
	_, err := renewer.RotateRootCA(props)
	require.NoError(t, err)

	caBefore := readSecret(t, renewer, GenerateRootCASecretName(props))
	pairBefore := readSecret(t, renewer, GenerateTLSPairSecretName(props))

	newPair, err := renewer.RotateLeafCert(props)
	require.NoError(t, err)
	assert.NotEqual(t, pairBefore.Data[v1.TLSCertKey], newPair.Certificate)

	caAfter := readSecret(t, renewer, GenerateRootCASecretName(props))
	assert.Equal(t, caBefore.Data[RootCAKey], caAfter.Data[RootCAKey], "leaf rotation must not change the CA")
	assert.Equal(t, caBefore.Data[RootCAPrivateKeyKey], caAfter.Data[RootCAPrivateKeyKey])
	assert.Empty(t, caAfter.Data[PreviousRootCAKey])

	verifyLeafAgainstCA(t, newPair.Certificate, caAfter.Data[RootCAKey])
}

func TestRotateLeafCert_LegacySecretWithoutCAKeyFallsBack(t *testing.T) {
	// Legacy CA Secrets only stored the CA certificate, not the private key.
	props, err := GetTLSCertProps(&rest.Config{Host: "https://varmor.example.com:6443"})
	require.NoError(t, err)
	legacyCA := testCAPEM(t)
	legacySecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        GenerateRootCASecretName(props),
			Namespace:   props.Namespace,
			Annotations: map[string]string{SelfSignedAnnotation: "true"},
		},
		Data: map[string][]byte{RootCAKey: legacyCA.Certificate},
	}
	client := fake.NewSimpleClientset(legacySecret)
	renewer := NewCertRenewer(
		&rest.Config{Host: "https://varmor.example.com:6443"},
		client.CoreV1().Secrets(props.Namespace),
		client.AppsV1().Deployments(props.Namespace),
		time.Hour,
		24*time.Hour,
		"",
		true,
		logr.Discard(),
	)

	_, err = renewer.RotateLeafCert(props)
	assert.True(t, errors.Is(err, ErrCAPrivateKeyUnavailable), "expected fallback error, got %v", err)
}

func TestRetirePreviousCA(t *testing.T) {
	renewer, props := newTestRenewer(t)

	// No previous CA yet: no-op.
	assert.NoError(t, renewer.RetirePreviousCA(props))

	require.NoError(t, func() error { _, e := renewer.RotateRootCA(props); return e }())
	require.NoError(t, func() error { _, e := renewer.RotateRootCA(props); return e }())
	caSecret := readSecret(t, renewer, GenerateRootCASecretName(props))
	assert.NotEmpty(t, caSecret.Data[PreviousRootCAKey])

	require.NoError(t, renewer.RetirePreviousCA(props))
	caSecret = readSecret(t, renewer, GenerateRootCASecretName(props))
	assert.Empty(t, caSecret.Data[PreviousRootCAKey])
	assert.Empty(t, caSecret.Annotations[PreviousCARotatedAtAnnotation])
	assert.NotEmpty(t, caSecret.Data[RootCAKey], "the current CA must remain after retirement")
}

func TestPreviousCARotatedAt(t *testing.T) {
	renewer, props := newTestRenewer(t)
	_, err := renewer.RotateRootCA(props)
	require.NoError(t, err)

	_, hasPrevious, err := renewer.PreviousCARotatedAt(props)
	require.NoError(t, err)
	assert.False(t, hasPrevious)

	_, err = renewer.RotateRootCA(props)
	require.NoError(t, err)
	rotatedAt, hasPrevious, err := renewer.PreviousCARotatedAt(props)
	require.NoError(t, err)
	assert.True(t, hasPrevious)
	assert.WithinDuration(t, time.Now(), rotatedAt, time.Minute)
}

func TestInitTLSPemPair_ReusesValidSecrets(t *testing.T) {
	renewer, props := newTestRenewer(t)
	created, err := renewer.RotateRootCA(props)
	require.NoError(t, err)

	reused, err := renewer.InitTLSPemPair()
	require.NoError(t, err)
	assert.Equal(t, created.Certificate, reused.Certificate, "valid Secrets must be reused, not regenerated")
}

func TestCANeedsRotation_MaterialDefectsTreatedAsNeedingRotation(t *testing.T) {
	props, err := GetTLSCertProps(&rest.Config{Host: "https://varmor.example.com:6443"})
	require.NoError(t, err)

	_, expiredCAPEM, err := GenerateCACert(-time.Hour)
	require.NoError(t, err)
	_, validCAPEM, err := GenerateCACert(24 * time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name   string
		secret *v1.Secret
		want   bool
	}{
		{name: "missing CA secret", want: true},
		{
			name:   "empty CA data",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateRootCASecretName(props), Namespace: props.Namespace}},
			want:   true,
		},
		{
			name:   "corrupt CA PEM",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateRootCASecretName(props), Namespace: props.Namespace}, Data: map[string][]byte{RootCAKey: []byte("garbage")}},
			want:   true,
		},
		{
			name:   "valid CA",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateRootCASecretName(props), Namespace: props.Namespace}, Data: map[string][]byte{RootCAKey: validCAPEM.Certificate}},
			want:   false,
		},
		{
			name:   "expired CA",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateRootCASecretName(props), Namespace: props.Namespace}, Data: map[string][]byte{RootCAKey: expiredCAPEM.Certificate}},
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var initial []runtime.Object
			if tt.secret != nil {
				initial = append(initial, tt.secret)
			}
			renewer, _ := newTestRenewer(t, initial...)

			got, err := renewer.CANeedsRotation(props)
			require.NoError(t, err, "material defects must be repaired by a rotation, not abort the pass")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLeafNeedsRotation_MaterialDefectsTreatedAsNeedingRotation(t *testing.T) {
	props, err := GetTLSCertProps(&rest.Config{Host: "https://varmor.example.com:6443"})
	require.NoError(t, err)

	caKeyPair, _, err := GenerateCACert(24 * time.Hour)
	require.NoError(t, err)
	validLeaf, err := GenerateCertPem(caKeyPair, props, 24*time.Hour, "", true)
	require.NoError(t, err)
	expiredLeaf, err := GenerateCertPem(caKeyPair, props, -time.Hour, "", true)
	require.NoError(t, err)

	tests := []struct {
		name   string
		secret *v1.Secret
		want   bool
	}{
		{name: "missing pair secret", want: true},
		{
			name:   "empty pair data",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateTLSPairSecretName(props), Namespace: props.Namespace}},
			want:   true,
		},
		{
			name: "corrupt leaf PEM",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateTLSPairSecretName(props), Namespace: props.Namespace},
				Data: map[string][]byte{v1.TLSCertKey: []byte("garbage"), v1.TLSPrivateKeyKey: []byte("garbage")}},
			want: true,
		},
		{
			name: "valid leaf",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateTLSPairSecretName(props), Namespace: props.Namespace},
				Data: map[string][]byte{v1.TLSCertKey: validLeaf.Certificate, v1.TLSPrivateKeyKey: validLeaf.PrivateKey}},
			want: false,
		},
		{
			name: "expired leaf",
			secret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: GenerateTLSPairSecretName(props), Namespace: props.Namespace},
				Data: map[string][]byte{v1.TLSCertKey: expiredLeaf.Certificate, v1.TLSPrivateKeyKey: expiredLeaf.PrivateKey}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var initial []runtime.Object
			if tt.secret != nil {
				initial = append(initial, tt.secret)
			}
			renewer, _ := newTestRenewer(t, initial...)

			got, err := renewer.LeafNeedsRotation(props)
			require.NoError(t, err, "material defects must be repaired by a rotation, not abort the pass")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNeedsRotation_PropagatesTransientAPIErrors(t *testing.T) {
	restConfig := &rest.Config{Host: "https://varmor.example.com:6443"}
	props, err := GetTLSCertProps(restConfig)
	require.NoError(t, err)

	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8errors.NewInternalError(fmt.Errorf("api server unavailable"))
	})
	renewer := NewCertRenewer(
		restConfig,
		client.CoreV1().Secrets(props.Namespace),
		client.AppsV1().Deployments(props.Namespace),
		time.Hour,
		24*time.Hour,
		"",
		true,
		logr.Discard(),
	)

	_, err = renewer.CANeedsRotation(props)
	assert.Error(t, err, "transient API errors must propagate so the pass retries instead of rotating")
	_, err = renewer.LeafNeedsRotation(props)
	assert.Error(t, err, "transient API errors must propagate so the pass retries instead of rotating")
}

func TestPreviousCARotatedAt_MissingSecretReportsNoPrevious(t *testing.T) {
	renewer, props := newTestRenewer(t)

	rotatedAt, hasPrevious, err := renewer.PreviousCARotatedAt(props)
	require.NoError(t, err)
	assert.False(t, hasPrevious)
	assert.True(t, rotatedAt.IsZero())
}
