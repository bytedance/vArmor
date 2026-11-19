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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testCAPEM(t *testing.T) *PemPair {
	t.Helper()
	_, caPEM, err := GenerateCACert(time.Hour)
	require.NoError(t, err)
	return caPEM
}

func parseBundleCerts(t *testing.T, bundle []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := bundle
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, cert)
		rest = remaining
	}
	require.NotEmpty(t, certs)
	return certs
}

func TestBuildCABundle_Errors(t *testing.T) {
	_, err := BuildCABundle(nil)
	assert.Error(t, err)

	missingCurrent := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		Data:       map[string][]byte{PreviousRootCAKey: []byte("x")},
	}
	_, err = BuildCABundle(missingCurrent)
	assert.Error(t, err)

	badCurrent := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		Data:       map[string][]byte{RootCAKey: []byte("not-a-cert")},
	}
	_, err = BuildCABundle(badCurrent)
	assert.Error(t, err)
}

func TestBuildCABundle_CurrentOnly(t *testing.T) {
	ca := testCAPEM(t)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		Data:       map[string][]byte{RootCAKey: ca.Certificate},
	}

	bundle, err := BuildCABundle(secret)
	require.NoError(t, err)

	block, _ := pem.Decode(bundle)
	require.NotNil(t, block)
	assert.True(t, bytes.Equal(pem.EncodeToMemory(block), bundle), "bundle must hold the single normalized current CA PEM")
	assert.Len(t, parseBundleCerts(t, bundle), 1)
}

func TestBuildCABundle_PreviousThenCurrentOrdering(t *testing.T) {
	previous := testCAPEM(t)
	current := testCAPEM(t)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		Data: map[string][]byte{
			PreviousRootCAKey: previous.Certificate,
			RootCAKey:         current.Certificate,
		},
	}

	bundle, err := BuildCABundle(secret)
	require.NoError(t, err)

	certs := parseBundleCerts(t, bundle)
	require.Len(t, certs, 2)

	previousBlock, _ := pem.Decode(previous.Certificate)
	currentBlock, _ := pem.Decode(current.Certificate)
	assert.Equal(t, previousBlock.Bytes, certs[0].Raw)
	assert.Equal(t, currentBlock.Bytes, certs[1].Raw)
}

func TestBuildCABundle_DeduplicatesIdenticalCAs(t *testing.T) {
	ca := testCAPEM(t)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		Data: map[string][]byte{
			PreviousRootCAKey: ca.Certificate,
			RootCAKey:         ca.Certificate,
		},
	}

	bundle, err := BuildCABundle(secret)
	require.NoError(t, err)
	assert.Len(t, parseBundleCerts(t, bundle), 1)
}

func TestBuildCABundle_IgnoresCorruptPreviousCA(t *testing.T) {
	current := testCAPEM(t)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		Data: map[string][]byte{
			PreviousRootCAKey: []byte("garbage"),
			RootCAKey:         current.Certificate,
		},
	}

	bundle, err := BuildCABundle(secret)
	require.NoError(t, err)
	assert.Len(t, parseBundleCerts(t, bundle), 1)
}
