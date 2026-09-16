//go:build envoyintegration

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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"

	audit "github.com/bytedance/vArmor/internal/auditor"
)

// All scenarios use the actual ALS decoder and event classification. This
// harness supplies only loopback transport, process lifecycle and log capture.
type observedEvent struct{ Action, Path, FilterChain, DstAddress string }

func startAuditCollector(t *testing.T) (string, func() []observedEvent) {
	t.Helper()
	// Unix socket paths are short even for long table-driven subtest names.
	dir, err := os.MkdirTemp("", "envoy-als-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	socket := filepath.Join(dir, "als.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var out envoyOutput
	server := grpc.NewServer()
	accesslogv3.RegisterAccessLogServiceServer(server, audit.NewALSIntegrationService(&out))
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	return socket, func() []observedEvent {
		var events []observedEvent
		dec := json.NewDecoder(bytes.NewReader(out.snapshot()))
		for {
			var event struct {
				Action string `json:"action"`
				Event  struct {
					Path        string `json:"path"`
					FilterChain string `json:"filterChain"`
					DstAddress  string `json:"dstAddress"`
				} `json:"event"`
			}
			err := dec.Decode(&event)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, observedEvent{event.Action, event.Event.Path, event.Event.FilterChain, event.Event.DstAddress})
		}
		return events
	}
}

func envoyBinary(t *testing.T) string {
	t.Helper()
	name := os.Getenv("ENVOY_BINARY")
	if name == "" {
		t.Skip("set ENVOY_BINARY to run local Envoy integration tests")
	}
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func startEnvoy(t *testing.T, binary, config string) *envoyOutput {
	t.Helper()
	output := &envoyOutput{}
	cmd := exec.Command(binary, "-c", config, "--concurrency", "1", "--disable-hot-restart", "--log-level", "warning")
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Envoy did not exit after kill")
		}
		if t.Failed() {
			t.Logf("Envoy output: %s", output.snapshot())
		}
	})
	return output
}

type envoyOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *envoyOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *envoyOutput) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}
func (b *envoyOutput) String() string { return string(b.snapshot()) }

func freePort(t *testing.T, host string) int {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
func socketAddress(port int) map[string]interface{} {
	return map[string]interface{}{"socket_address": map[string]interface{}{"address": "127.0.0.1", "port_value": port}}
}
func setALSFlushInterval(node interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		if _, ok := v["log_name"]; ok {
			v["buffer_flush_interval"] = "0.05s"
		}
		for _, child := range v {
			setALSFlushInterval(child)
		}
	case []interface{}:
		for _, child := range v {
			setALSFlushInterval(child)
		}
	}
}
func atomicWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}
func awaitCondition(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitEnvoyReady(t *testing.T, adminPort int, output *envoyOutput) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 200 * time.Millisecond}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Envoy did not become ready: %s", output.snapshot())
}
