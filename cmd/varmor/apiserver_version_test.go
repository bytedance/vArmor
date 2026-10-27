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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

const validAPIServerVersion = `{"major":"1","minor":"30+","gitVersion":"v1.30.4-vke.6"}`

func preserveAPIServerVersion(t *testing.T) {
	t.Helper()
	previousVersion, previousAppArmorGA := varmorconfig.ServerVersion, varmorconfig.AppArmorGA
	t.Cleanup(func() {
		varmorconfig.ServerVersion, varmorconfig.AppArmorGA = previousVersion, previousAppArmorGA
	})
}

func newVersionTestClient(t *testing.T, handler http.HandlerFunc) rest.Interface {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return client.Discovery().RESTClient()
}

func TestWaitForAPIServerVersion_RetriesUntilValid(t *testing.T) {
	preserveAPIServerVersion(t)
	varmorconfig.ServerVersion = &version.Info{}
	varmorconfig.AppArmorGA = false
	var attempts atomic.Int32
	client := newVersionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/version", r.URL.Path)
		switch attempts.Add(1) {
		case 1:
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		case 2:
			// A successful HTTP response with incomplete version fields must not
			// allow capability initialization to proceed either.
			_, err := w.Write([]byte(`{"gitVersion":"v1.30.4-vke.6"}`))
			assert.NoError(t, err)
		default:
			_, err := w.Write([]byte(validAPIServerVersion))
			assert.NoError(t, err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	assert.NoError(t, waitForAPIServerVersion(ctx, client, logr.Discard()))
	assert.EqualValues(t, 3, attempts.Load())
	assert.Equal(t, "1", varmorconfig.ServerVersion.Major)
	assert.Equal(t, "30+", varmorconfig.ServerVersion.Minor)
	assert.Equal(t, "v1.30.4-vke.6", varmorconfig.ServerVersion.GitVersion)
	assert.True(t, varmorconfig.AppArmorGA)
}

func TestUpdateAPIServerVersion_InvalidResponsePreservesCache(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "unavailable", status: http.StatusServiceUnavailable},
		{name: "invalid JSON", status: http.StatusOK, body: `{`},
		{name: "null", status: http.StatusOK, body: `null`},
		{name: "empty", status: http.StatusOK, body: `{}`},
		{name: "missing gitVersion", status: http.StatusOK, body: `{"major":"1","minor":"30"}`},
		{name: "missing major", status: http.StatusOK, body: `{"minor":"30","gitVersion":"v1.30.4"}`},
		{name: "invalid minor", status: http.StatusOK, body: `{"major":"1","minor":"invalid","gitVersion":"v1.30.4"}`},
		{name: "same gitVersion with missing fields", status: http.StatusOK, body: `{"gitVersion":"v1.30.4-vke.6"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preserveAPIServerVersion(t)
			previous := &version.Info{Major: "1", Minor: "30+", GitVersion: "v1.30.4-vke.6"}
			varmorconfig.ServerVersion = previous
			varmorconfig.AppArmorGA = true
			client := newVersionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, err := w.Write([]byte(tc.body))
				assert.NoError(t, err)
			})
			assert.Error(t, updateAPIServerVersion(context.Background(), client, logr.Discard()))
			assert.Same(t, previous, varmorconfig.ServerVersion)
			assert.True(t, varmorconfig.AppArmorGA)
		})
	}
}

func TestUpdateAPIServerVersion_RefreshesVersion(t *testing.T) {
	preserveAPIServerVersion(t)
	varmorconfig.ServerVersion = &version.Info{Major: "1", Minor: "29", GitVersion: "v1.29.0"}
	varmorconfig.AppArmorGA = false
	client := newVersionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(validAPIServerVersion))
		assert.NoError(t, err)
	})
	assert.NoError(t, updateAPIServerVersion(context.Background(), client, logr.Discard()))
	assert.Equal(t, "v1.30.4-vke.6", varmorconfig.ServerVersion.GitVersion)
	assert.True(t, varmorconfig.AppArmorGA)
}

func TestWaitForAPIServerVersion_CancelDuringRequest(t *testing.T) {
	preserveAPIServerVersion(t)
	previous := &version.Info{}
	varmorconfig.ServerVersion = previous
	started, disconnected, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	client := newVersionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(disconnected)
		case <-release:
		}
	})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- waitForAPIServerVersion(ctx, client, logr.Discard()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("version request did not start")
	}
	cancel()
	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not stop after cancellation")
	}
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight version request was not cancelled")
	}
	assert.Same(t, previous, varmorconfig.ServerVersion)
}

func TestWaitForAPIServerVersion_CancelDuringBackoff(t *testing.T) {
	preserveAPIServerVersion(t)
	var attempts atomic.Int32
	client := newVersionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	})
	// The first retry delay is at least one second. Cancellation must interrupt
	// that delay instead of waiting for the next attempt.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	assert.ErrorIs(t, waitForAPIServerVersion(ctx, client, logr.Discard()), context.DeadlineExceeded)
	assert.Less(t, time.Since(started), time.Second)
	assert.EqualValues(t, 1, attempts.Load())
}

func TestWaitForAPIServerVersion_AlreadyCancelled(t *testing.T) {
	var attempts atomic.Int32
	client := newVersionTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, waitForAPIServerVersion(ctx, client, logr.Discard()), context.Canceled)
	assert.Zero(t, attempts.Load())
}
