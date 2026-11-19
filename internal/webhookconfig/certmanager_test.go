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

package webhookconfig

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/bytedance/vArmor/internal/config"
	varmortls "github.com/bytedance/vArmor/internal/tls"
)

type rotationFixture struct {
	renewer   *varmortls.CertRenewer
	manager   *certManager
	client    *fake.Clientset
	props     varmortls.CertificateProps
	reconcile *int
}

func newRotationFixture(t *testing.T, initial ...runtime.Object) rotationFixture {
	t.Helper()
	restConfig := &rest.Config{Host: "https://varmor.example.com:6443"}
	props, err := varmortls.GetTLSCertProps(restConfig)
	require.NoError(t, err)

	client := fake.NewSimpleClientset(initial...)
	renewer := varmortls.NewCertRenewer(
		restConfig,
		client.CoreV1().Secrets(props.Namespace),
		client.AppsV1().Deployments(props.Namespace),
		time.Hour,
		24*time.Hour,
		"",
		true,
		logr.Discard(),
	)

	reconcileCalls := 0
	manager := &certManager{
		clientConfig:    restConfig,
		renewer:         renewer,
		secretInterface: client.CoreV1().Secrets(props.Namespace),
		webhookReconcile: func(_ context.Context) error {
			reconcileCalls++
			return nil
		},
		log: logr.Discard(),
	}
	return rotationFixture{renewer: renewer, manager: manager, client: client, props: props, reconcile: &reconcileCalls}
}

// seedSecrets writes a CA Secret (with key) and a matching TLS pair Secret.
// caDuration/leafDuration control validity: negative durations model expiry.
func seedSecrets(t *testing.T, f rotationFixture, caDuration, leafDuration time.Duration) {
	t.Helper()
	caKeyPair, caPEM, err := varmortls.GenerateCACert(caDuration)
	require.NoError(t, err)
	leaf, err := varmortls.GenerateCertPem(caKeyPair, f.props, leafDuration, "", true)
	require.NoError(t, err)

	caSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        varmortls.GenerateRootCASecretName(f.props),
			Namespace:   f.props.Namespace,
			Annotations: map[string]string{varmortls.SelfSignedAnnotation: "true"},
		},
		Data: map[string][]byte{
			varmortls.RootCAKey:           caPEM.Certificate,
			varmortls.RootCAPrivateKeyKey: caPEM.PrivateKey,
		},
	}
	pairSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      varmortls.GenerateTLSPairSecretName(f.props),
			Namespace: f.props.Namespace,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       leaf.Certificate,
			v1.TLSPrivateKeyKey: leaf.PrivateKey,
		},
	}
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), caSecret, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), pairSecret, metav1.CreateOptions{})
	require.NoError(t, err)
}

func (f rotationFixture) caSecret(t *testing.T) *v1.Secret {
	t.Helper()
	s, err := f.client.CoreV1().Secrets(f.props.Namespace).Get(
		context.Background(), varmortls.GenerateRootCASecretName(f.props), metav1.GetOptions{})
	require.NoError(t, err)
	return s
}

func TestRotateIfNeeded_AllValidNoAction(t *testing.T) {
	f := newRotationFixture(t)
	seedSecrets(t, f, 24*time.Hour, 24*time.Hour)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionNone, action)
	assert.Zero(t, *f.reconcile, "valid certs must not trigger webhook reconciliation")
}

func TestRotateIfNeeded_ExpiredLeafRotatesWithoutCABundleChange(t *testing.T) {
	f := newRotationFixture(t)
	seedSecrets(t, f, 24*time.Hour, -time.Hour)
	caBefore := f.caSecret(t).Data[varmortls.RootCAKey]
	pairBefore, err := f.client.CoreV1().Secrets(f.props.Namespace).Get(
		context.Background(), varmortls.GenerateTLSPairSecretName(f.props), metav1.GetOptions{})
	require.NoError(t, err)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionLeaf, action)
	assert.Zero(t, *f.reconcile, "leaf rotation must not rewrite the webhook caBundle")

	caAfter := f.caSecret(t)
	assert.Equal(t, caBefore, caAfter.Data[varmortls.RootCAKey], "CA must be untouched by a leaf rotation")
	assert.Empty(t, caAfter.Data[varmortls.PreviousRootCAKey])

	pairAfter, err := f.client.CoreV1().Secrets(f.props.Namespace).Get(
		context.Background(), varmortls.GenerateTLSPairSecretName(f.props), metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, pairBefore.Data[v1.TLSCertKey], pairAfter.Data[v1.TLSCertKey])
}

func TestRotateIfNeeded_ExpiredCARotatesWithDualBundleReconcile(t *testing.T) {
	f := newRotationFixture(t)
	seedSecrets(t, f, -time.Hour, -time.Hour)
	oldCA := f.caSecret(t).Data[varmortls.RootCAKey]

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionRoot, action)
	assert.Equal(t, 1, *f.reconcile, "CA rotation must reconcile the dual-CA webhook bundle")

	caAfter := f.caSecret(t)
	assert.Equal(t, oldCA, caAfter.Data[varmortls.PreviousRootCAKey], "the old CA must be retained")
	assert.NotEqual(t, oldCA, caAfter.Data[varmortls.RootCAKey])
	assert.NotEmpty(t, caAfter.Annotations[varmortls.PreviousCARotatedAtAnnotation])
}

func TestRotateIfNeeded_LegacySecretFallsBackToRootRotation(t *testing.T) {
	f := newRotationFixture(t)
	caKeyPair, caPEM, err := varmortls.GenerateCACert(24 * time.Hour)
	require.NoError(t, err)
	expiredLeaf, err := varmortls.GenerateCertPem(caKeyPair, f.props, -time.Hour, "", true)
	require.NoError(t, err)

	legacyCA := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        varmortls.GenerateRootCASecretName(f.props),
			Namespace:   f.props.Namespace,
			Annotations: map[string]string{varmortls.SelfSignedAnnotation: "true"},
		},
		// Legacy layout: certificate only, no rootCA.key.
		Data: map[string][]byte{varmortls.RootCAKey: caPEM.Certificate},
	}
	pairSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: varmortls.GenerateTLSPairSecretName(f.props), Namespace: f.props.Namespace},
		Data: map[string][]byte{
			v1.TLSCertKey:       expiredLeaf.Certificate,
			v1.TLSPrivateKeyKey: expiredLeaf.PrivateKey,
		},
	}
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), legacyCA, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), pairSecret, metav1.CreateOptions{})
	require.NoError(t, err)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionRoot, action)
	assert.Equal(t, 1, *f.reconcile)
	assert.NotEmpty(t, f.caSecret(t).Data[varmortls.RootCAPrivateKeyKey], "rotation must upgrade the legacy Secret layout")
}

func TestRotateIfNeeded_RetiresPreviousCAAfterRetentionWindow(t *testing.T) {
	f := newRotationFixture(t)
	seedSecrets(t, f, 24*time.Hour, 24*time.Hour)

	// Simulate a CA rotation that happened longer ago than the retention window.
	_, previousCAPEM, err := varmortls.GenerateCACert(24 * time.Hour)
	require.NoError(t, err)
	ca := f.caSecret(t)
	ca.Data[varmortls.PreviousRootCAKey] = previousCAPEM.Certificate
	ca.Annotations[varmortls.PreviousCARotatedAtAnnotation] = time.Now().Add(-config.PreviousCARetentionDuration - time.Hour).Format(time.RFC3339)
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Update(context.Background(), ca, metav1.UpdateOptions{})
	require.NoError(t, err)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionRetired, action)
	assert.Equal(t, 1, *f.reconcile)

	after := f.caSecret(t)
	assert.Empty(t, after.Data[varmortls.PreviousRootCAKey])
	assert.Empty(t, after.Annotations[varmortls.PreviousCARotatedAtAnnotation])
	assert.NotEmpty(t, after.Data[varmortls.RootCAKey])
}

func TestRotateIfNeeded_KeepsRecentPreviousCA(t *testing.T) {
	f := newRotationFixture(t)
	seedSecrets(t, f, 24*time.Hour, 24*time.Hour)

	_, previousCAPEM, err := varmortls.GenerateCACert(24 * time.Hour)
	require.NoError(t, err)
	ca := f.caSecret(t)
	ca.Data[varmortls.PreviousRootCAKey] = previousCAPEM.Certificate
	ca.Annotations[varmortls.PreviousCARotatedAtAnnotation] = time.Now().Format(time.RFC3339)
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Update(context.Background(), ca, metav1.UpdateOptions{})
	require.NoError(t, err)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionNone, action)
	assert.Zero(t, *f.reconcile)
	assert.NotEmpty(t, f.caSecret(t).Data[varmortls.PreviousRootCAKey], "recent previous CA must survive")
}

// seedCASecret writes only a valid CA Secret (including its private key),
// leaving the TLS pair Secret absent.
func seedCASecret(t *testing.T, f rotationFixture) []byte {
	t.Helper()
	_, caPEM, err := varmortls.GenerateCACert(24 * time.Hour)
	require.NoError(t, err)
	caSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        varmortls.GenerateRootCASecretName(f.props),
			Namespace:   f.props.Namespace,
			Annotations: map[string]string{varmortls.SelfSignedAnnotation: "true"},
		},
		Data: map[string][]byte{
			varmortls.RootCAKey:           caPEM.Certificate,
			varmortls.RootCAPrivateKeyKey: caPEM.PrivateKey,
		},
	}
	_, err = f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), caSecret, metav1.CreateOptions{})
	require.NoError(t, err)
	return caPEM.Certificate
}

func createGarbagePairSecret(t *testing.T, f rotationFixture) {
	t.Helper()
	pairSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: varmortls.GenerateTLSPairSecretName(f.props), Namespace: f.props.Namespace},
		Data: map[string][]byte{
			v1.TLSCertKey:       []byte("garbage"),
			v1.TLSPrivateKeyKey: []byte("garbage"),
		},
	}
	_, err := f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), pairSecret, metav1.CreateOptions{})
	require.NoError(t, err)
}

func TestRotateIfNeeded_MissingSecretsBootstrapFreshCA(t *testing.T) {
	// Empty cluster: no CA Secret and no TLS pair Secret.
	f := newRotationFixture(t)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionRoot, action)
	assert.Equal(t, 1, *f.reconcile, "fresh bootstrap must rewrite the webhook caBundle")

	valid, err := f.renewer.ValidCert(f.props)
	require.NoError(t, err)
	assert.True(t, valid, "the pass must recreate both Secrets without a process restart")
}

func TestRotateIfNeeded_CorruptCAIsRebuilt(t *testing.T) {
	f := newRotationFixture(t)
	caSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        varmortls.GenerateRootCASecretName(f.props),
			Namespace:   f.props.Namespace,
			Annotations: map[string]string{varmortls.SelfSignedAnnotation: "true"},
		},
		Data: map[string][]byte{varmortls.RootCAKey: []byte("garbage")},
	}
	_, err := f.client.CoreV1().Secrets(f.props.Namespace).Create(context.Background(), caSecret, metav1.CreateOptions{})
	require.NoError(t, err)
	createGarbagePairSecret(t, f)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionRoot, action)
	assert.Equal(t, 1, *f.reconcile)
	assert.NotEmpty(t, f.caSecret(t).Data[varmortls.RootCAPrivateKeyKey], "rebuild must persist the CA private key")

	valid, err := f.renewer.ValidCert(f.props)
	require.NoError(t, err)
	assert.True(t, valid, "corrupt CA material must converge via RotateRootCA")
}

func TestRotateIfNeeded_CorruptLeafIsReissued(t *testing.T) {
	f := newRotationFixture(t)
	caBefore := seedCASecret(t, f)
	createGarbagePairSecret(t, f)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionLeaf, action)
	assert.Zero(t, *f.reconcile, "leaf repair must not touch the webhook caBundle")
	assert.Equal(t, caBefore, f.caSecret(t).Data[varmortls.RootCAKey], "the CA must stay untouched")

	valid, err := f.renewer.ValidCert(f.props)
	require.NoError(t, err)
	assert.True(t, valid, "corrupt leaf material must converge via RotateLeafCert")
}

func TestRotateIfNeeded_MissingPairSecretIsReissued(t *testing.T) {
	f := newRotationFixture(t)
	caBefore := seedCASecret(t, f)

	action, err := f.manager.rotateIfNeeded(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rotationActionLeaf, action)
	assert.Zero(t, *f.reconcile)
	assert.Equal(t, caBefore, f.caSecret(t).Data[varmortls.RootCAKey])

	valid, err := f.renewer.ValidCert(f.props)
	require.NoError(t, err)
	assert.True(t, valid, "a missing pair Secret must be recreated without restarting the manager")
}
