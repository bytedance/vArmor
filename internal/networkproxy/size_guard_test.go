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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testLogger returns a no-op logger suitable for unit tests.
func testLogger() logr.Logger {
	return logr.Discard()
}

// ============================================================================
// computeSecretDataSize tests
// ============================================================================

func TestComputeSecretDataSize_StringData(t *testing.T) {
	secret := &v1.Secret{
		StringData: map[string]string{
			"a": "hello",                  // 5
			"b": "world!",                 // 6
			"c": strings.Repeat("x", 100), // 100
		},
	}
	got := computeSecretDataSize(secret)
	want := 5 + 6 + 100
	if got != want {
		t.Errorf("computeSecretDataSize() = %d, want %d", got, want)
	}
}

func TestComputeSecretDataSize_BinaryData(t *testing.T) {
	secret := &v1.Secret{
		Data: map[string][]byte{
			"bin1": make([]byte, 50),
			"bin2": make([]byte, 200),
		},
	}
	got := computeSecretDataSize(secret)
	want := 50 + 200
	if got != want {
		t.Errorf("computeSecretDataSize() = %d, want %d", got, want)
	}
}

func TestComputeSecretDataSize_Mixed(t *testing.T) {
	secret := &v1.Secret{
		StringData: map[string]string{
			"str": strings.Repeat("a", 1000),
		},
		Data: map[string][]byte{
			"bin": make([]byte, 500),
		},
	}
	got := computeSecretDataSize(secret)
	want := 1000 + 500
	if got != want {
		t.Errorf("computeSecretDataSize() = %d, want %d", got, want)
	}
}

func TestComputeSecretDataSize_Empty(t *testing.T) {
	secret := &v1.Secret{}
	got := computeSecretDataSize(secret)
	if got != 0 {
		t.Errorf("computeSecretDataSize() = %d, want 0", got)
	}
}

// ============================================================================
// checkSecretSize tests
// ============================================================================

func TestCheckSecretSize_BelowWarn(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		StringData: map[string]string{
			"data": strings.Repeat("x", 100*1024), // 100 KB
		},
	}
	if err := checkSecretSize(secret, testLogger()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckSecretSize_AboveWarn_BelowMax(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-warn", Namespace: "demo"},
		StringData: map[string]string{
			"data": strings.Repeat("x", 750*1024), // 750 KB
		},
	}
	// Should warn (log only) but NOT return an error.
	if err := checkSecretSize(secret, testLogger()); err != nil {
		t.Errorf("should only warn, not error; got: %v", err)
	}
}

func TestCheckSecretSize_AboveMax(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-reject", Namespace: "prod"},
		StringData: map[string]string{
			"data": strings.Repeat("x", 950*1024), // 950 KB
		},
	}
	err := checkSecretSize(secret, testLogger())
	if err == nil {
		t.Fatal("should return error for oversized secret")
	}
	if !strings.Contains(err.Error(), "exceeds the maximum allowed threshold") {
		t.Errorf("error message mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "prod/test-reject") {
		t.Errorf("error should contain namespace/name: %v", err)
	}
}

func TestCheckSecretSize_ExactlyAtWarnThreshold(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "ns"},
		StringData: map[string]string{
			"data": strings.Repeat("x", SecretSizeWarnThreshold),
		},
	}
	// Exactly at the threshold → condition is ">" not ">=", so no warning.
	if err := checkSecretSize(secret, testLogger()); err != nil {
		t.Errorf("at warn threshold should not error: %v", err)
	}
}

func TestCheckSecretSize_ExactlyAtMaxThreshold(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "ns"},
		StringData: map[string]string{
			"data": strings.Repeat("x", SecretSizeMaxThreshold),
		},
	}
	// Exactly at the threshold → ">" not ">=", so no error.
	if err := checkSecretSize(secret, testLogger()); err != nil {
		t.Errorf("at max threshold should not error: %v", err)
	}
}

func TestCheckSecretSize_OneByteOverMax(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "ns"},
		StringData: map[string]string{
			"data": strings.Repeat("x", SecretSizeMaxThreshold+1),
		},
	}
	if err := checkSecretSize(secret, testLogger()); err == nil {
		t.Fatal("one byte over max should return error")
	}
}
