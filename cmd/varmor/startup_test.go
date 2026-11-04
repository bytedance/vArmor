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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run the real entry point in a subprocess so signal handling and startup
// ordering are exercised without sharing global flags or version caches.
func TestStartupProcess(t *testing.T) {
	argsJSON := os.Getenv("VARMOR_STARTUP_TEST_ARGS")
	if argsJSON == "" {
		return
	}
	var args []string
	require.NoError(t, json.Unmarshal([]byte(argsJSON), &args))
	flag.CommandLine = flag.NewFlagSet("varmor", flag.ExitOnError)
	os.Args = append([]string{"varmor"}, args...)
	main()
}

func TestStartup_WaitsForAPIServerVersion(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		preDelete bool
	}{
		{name: "manager"},
		{name: "agent", args: []string{"-agent"}},
		{name: "pre-delete", args: []string{"-preDelete"}, preDelete: true},
		{name: "agent pre-delete", args: []string{"-agent", "-preDelete"}, preDelete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan string, 32)
			var versionRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					versionRequests.Add(1)
				}
				select {
				case requests <- r.Method + " " + r.URL.Path:
				case <-r.Context().Done():
					return
				}
				// Every version request fails. Other requests must only come from
				// pre-delete, which is intentionally allowed to start cleanup.
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			}))
			t.Cleanup(server.Close)

			kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
			kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: %s
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user: {}
`, server.URL)
			require.NoError(t, os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0600))
			args := append([]string{"-kubeconfig=" + kubeconfigPath}, tc.args...)
			argsJSON, err := json.Marshal(args)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupProcess$")
			cmd.Env = append(os.Environ(), "VARMOR_STARTUP_TEST_ARGS="+string(argsJSON))
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			require.NoError(t, cmd.Start())
			exited := make(chan struct{})
			var processErr error
			go func() {
				processErr = cmd.Wait()
				close(exited)
			}()
			t.Cleanup(func() {
				cancel()
				<-exited
				if t.Failed() {
					t.Log(output.String())
				}
			})

			deadline := time.NewTimer(8 * time.Second)
			defer deadline.Stop()
			for attempts := 0; ; {
				select {
				case request := <-requests:
					if request != "GET /version" {
						require.True(t, tc.preDelete, "business initialization started without a valid version: %s", request)
						assert.Equal(t, "DELETE /apis/crd.varmor.org/v1beta1/varmorclusterpolicies", request)
						assert.EqualValues(t, 1, versionRequests.Load(), "pre-delete must not retry version discovery")
						return
					}
					attempts++
					if attempts < 2 {
						continue
					}
					require.False(t, tc.preDelete, "pre-delete is blocked on version discovery")
					require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
					select {
					case <-exited:
						require.NoError(t, processErr, output.String())
					case <-time.After(3 * time.Second):
						t.Fatal("startup did not stop while waiting for a valid version")
					}
					assert.NotContains(t, output.String(), "vArmor manager startup")
					assert.NotContains(t, output.String(), "vArmor agent startup")
					return
				case <-exited:
					t.Fatalf("process exited before the startup check: %v\n%s", processErr, output.String())
				case <-deadline.C:
					t.Fatal("startup did not retry version discovery or enter pre-delete cleanup")
				}
			}
		})
	}
}
