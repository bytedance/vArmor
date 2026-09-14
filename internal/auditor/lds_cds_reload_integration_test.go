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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// TestLDSCDSReloadEnvoy exercises file-based xDS updates with real traffic and
// the production ALS consumer. TLS files already exist, as they must in a
// deployed MITM-capable instance. Only loopback transport plumbing is replaced.
func TestLDSCDSReloadEnvoy(t *testing.T) {
	binary := os.Getenv("ENVOY_BINARY")
	if binary == "" {
		t.Skip("set ENVOY_BINARY to run local Envoy integration tests")
	}
	var err error
	binary, err = exec.LookPath(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range []string{"lds_first", "cds_first", "atomic_directory"} {
		t.Run(order, func(t *testing.T) {
			dir := t.TempDir()
			cert, key, roots := wildcardTestCertificate(t, dir, "api.example.com")
			socketDir, err := os.MkdirTemp("", "reload-als-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(socketDir) })
			socket := filepath.Join(socketDir, "als.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			service, events := wildcardTestConsumer(t)
			server := grpc.NewServer()
			accesslogv3.RegisterAccessLogServiceServer(server, service)
			go server.Serve(listener)
			t.Cleanup(func() { server.Stop(); listener.Close() })
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls.Add(1); w.WriteHeader(http.StatusOK) }))
			t.Cleanup(upstream.Close)
			upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
			proxyPort, adminPort := wildcardFreePort(t), wildcardFreePort(t)
			for adminPort == proxyPort {
				adminPort = wildcardFreePort(t)
			}
			audit := profile.AuditSinkConfig{ProfileName: "reload-test", ALSUDSPath: socket}
			old, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{DefaultAction: "allow"}, 1, uint16(proxyPort), nil, profile.IPStackConfig{IPv4: true}, audit)
			if err != nil {
				t.Fatal(err)
			}
			next, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{DefaultAction: "deny", HTTPRules: []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"allow", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"api.example.com"}, Paths: []varmor.HTTPPathMatch{{Exact: "/allowed"}}}}}}, 2, uint16(proxyPort), &profile.MITMInput{Domains: []string{"api.example.com"}, LeafCertPath: cert, LeafKeyPath: key}, profile.IPStackConfig{IPv4: true}, audit)
			if err != nil {
				t.Fatal(err)
			}
			oldLDS, oldCDS := reloadTransport(t, old.LDS, old.CDS, proxyPort, upstreamPort)
			newLDS, newCDS := reloadTransport(t, next.LDS, next.CDS, proxyPort, upstreamPort)
			ldsDir, cdsDir := filepath.Join(dir, "lds"), filepath.Join(dir, "cds")
			if order == "atomic_directory" {
				ldsDir = filepath.Join(dir, "shared")
				cdsDir = ldsDir
			}
			for _, d := range []string{ldsDir, cdsDir} {
				if err := os.MkdirAll(d, 0700); err != nil {
					t.Fatal(err)
				}
			}
			ldsPath, cdsPath := filepath.Join(ldsDir, "lds.yaml"), filepath.Join(cdsDir, "cds.yaml")
			if order == "atomic_directory" {
				for _, revision := range []string{"old", "new"} {
					if err := os.Mkdir(filepath.Join(ldsDir, revision), 0700); err != nil {
						t.Fatal(err)
					}
				}
				reloadWrite(t, filepath.Join(ldsDir, "old/lds.yaml"), oldLDS)
				reloadWrite(t, filepath.Join(ldsDir, "old/cds.yaml"), oldCDS)
				reloadWrite(t, filepath.Join(ldsDir, "new/lds.yaml"), newLDS)
				reloadWrite(t, filepath.Join(ldsDir, "new/cds.yaml"), newCDS)
				for link, target := range map[string]string{"..data": "old", "lds.yaml": "..data/lds.yaml", "cds.yaml": "..data/cds.yaml"} {
					if err := os.Symlink(target, filepath.Join(ldsDir, link)); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				reloadWrite(t, ldsPath, oldLDS)
				reloadWrite(t, cdsPath, oldCDS)
			}
			source := func(path, dir string) any {
				return map[string]any{"path_config_source": map[string]any{"path": path, "watched_directory": map[string]any{"path": dir}}}
			}
			bootstrap := map[string]any{"node": map[string]any{"id": "reload-test", "cluster": "reload-test"}, "admin": map[string]any{"address": wildcardSocketAddress(adminPort)}, "dynamic_resources": map[string]any{"lds_config": source(ldsPath, ldsDir), "cds_config": source(cdsPath, cdsDir)}}
			config, err := json.Marshal(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "bootstrap.json")
			reloadWrite(t, configPath, config)
			var output wildcardLockedBuffer
			cmd := exec.Command(binary, "-c", configPath, "--concurrency", "1", "--disable-hot-restart", "--log-level", "warning")
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				if t.Failed() {
					t.Logf("Envoy output: %s", output.snapshot())
				}
			})
			admin := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 500 * time.Millisecond}
			t.Cleanup(admin.CloseIdleConnections)
			adminURL := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
			stats := func() map[string]float64 {
				resp, err := admin.Get(adminURL + "/stats?format=json&filter=workers_started%7Clds.update_rejected%7Ccds.update_success")
				if err != nil {
					return nil
				}
				defer resp.Body.Close()
				var doc struct {
					Stats []struct {
						Name  string
						Value float64
					}
				}
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					return nil
				}
				values := map[string]float64{}
				for _, s := range doc.Stats {
					values[s.Name] = s.Value
				}
				return values
			}
			active := func(version string) bool {
				resp, err := admin.Get(adminURL + "/config_dump")
				if err != nil {
					return false
				}
				defer resp.Body.Close()
				var doc struct {
					Configs []struct {
						Listeners []struct {
							Active struct {
								Version string `json:"version_info"`
							} `json:"active_state"`
						} `json:"dynamic_listeners"`
					}
				}
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					return false
				}
				for _, c := range doc.Configs {
					for _, l := range c.Listeners {
						if l.Active.Version == version {
							return true
						}
					}
				}
				return false
			}
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
			}}}
			t.Cleanup(client.CloseIdleConnections)
			request := func(scheme, path string) int {
				resp, err := client.Get(scheme + "://api.example.com" + path)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					t.Fatal(err)
				}
				return resp.StatusCode
			}
			reloadWait(t, "initial listener", func() bool { return active("1") && stats()["listener_manager.workers_started"] == 1 })
			if got := request("http", "/secret"); got != 200 {
				t.Fatalf("initial HTTP=%d want 200", got)
			}
			if got := upstreamCalls.Load(); got != 1 {
				t.Fatalf("initial upstream calls=%d want 1", got)
			}
			rejected := func() bool { return stats()["listener_manager.lds.update_rejected"] > 0 }
			waitCDS := func() {
				reloadWait(t, "new CDS", func() bool { return stats()["cluster_manager.cds.update_success"] >= 2 })
			}
			wantEvents := map[wildcardObservedEvent]int{}
			check := func(scheme, path, stage string, status int, action string) {
				got := request(scheme, path)
				t.Logf("%s %s %s: HTTP=%d", stage, scheme, path, got)
				if got != status {
					t.Errorf("%s %s %s HTTP=%d want %d", stage, scheme, path, got, status)
				}
				chain := "http_chain"
				if scheme == "https" {
					chain = "mitm_tls_dns_chain"
				}
				wantEvents[wildcardObservedEvent{Action: action, Path: path, FilterChain: chain}]++
			}
			if order == "cds_first" {
				reloadWrite(t, cdsPath, newCDS)
				waitCDS()
			}
			if order == "atomic_directory" {
				if err := os.Symlink("new", filepath.Join(ldsDir, "..data.next")); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(ldsDir, "..data.next"), filepath.Join(ldsDir, "..data")); err != nil {
					t.Fatal(err)
				}
			} else {
				reloadWrite(t, ldsPath, newLDS)
			}
			reloadWait(t, "LDS update accepted or rejected", func() bool { return active("2") || rejected() })
			if rejected() {
				// Finish the delayed CDS update without another LDS notification, then
				// expose the stale allow policy rather than hiding the rejection in a timeout.
				if order == "lds_first" {
					reloadWrite(t, cdsPath, newCDS)
				}
				waitCDS()
				t.Fatalf("new LDS rejected; after CDS loaded, HTTP /secret=%d (want 403), active old listener=%v", request("http", "/secret"), active("1"))
			}
			if order == "lds_first" {
				check("http", "/secret", "before CDS", 403, "DENIED")
				check("https", "/secret", "before CDS", 403, "DENIED")
				check("https", "/allowed", "before CDS", 503, "AUDIT")
				if got := upstreamCalls.Load(); got != 1 {
					t.Errorf("request escaped before CDS: upstream calls=%d want 1", got)
				}
				reloadWrite(t, cdsPath, newCDS)
			}
			waitCDS()
			check("http", "/secret", "after CDS", 403, "DENIED")
			check("https", "/secret", "after CDS", 403, "DENIED")
			check("https", "/allowed", "after CDS", 200, "AUDIT")
			if got := upstreamCalls.Load(); got != 2 {
				t.Errorf("upstream calls=%d want 2 (initial and allowed)", got)
			}
			if rejected() {
				t.Error("unexpected LDS rejection")
			}
			wantCount := 0
			for _, n := range wantEvents {
				wantCount += n
			}
			reloadWait(t, "audit delivery", func() bool { return len(events()) >= wantCount })
			time.Sleep(300 * time.Millisecond)
			gotEvents := map[wildcardObservedEvent]int{}
			for _, e := range events() {
				gotEvents[e]++
			}
			if len(gotEvents) != len(wantEvents) {
				t.Errorf("audit events=%v want %v", gotEvents, wantEvents)
			}
			for e, n := range wantEvents {
				if gotEvents[e] != n {
					t.Errorf("audit event %v count=%d want %d", e, gotEvents[e], n)
				}
			}
		})
	}
}

func reloadWait(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func reloadWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

// Keep generated routes, RBAC, cluster names and audit configuration intact.
func reloadTransport(t *testing.T, ldsYAML, cdsYAML string, proxyPort, upstreamPort int) ([]byte, []byte) {
	t.Helper()
	var lds, cds map[string]any
	if err := yaml.Unmarshal([]byte(ldsYAML), &lds); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(cdsYAML), &cds); err != nil {
		t.Fatal(err)
	}
	listener := lds["resources"].([]any)[0].(map[string]any)
	listener["address"] = wildcardSocketAddress(proxyPort)
	var filters []any
	for _, raw := range listener["listener_filters"].([]any) {
		if raw.(map[string]any)["name"] != "envoy.filters.listener.original_dst" {
			filters = append(filters, raw)
		}
	}
	listener["listener_filters"] = filters
	wildcardSetFlushInterval(listener)
	for i, raw := range cds["resources"].([]any) {
		c := raw.(map[string]any)
		if c["type"] != "ORIGINAL_DST" {
			continue
		}
		name := c["name"]
		cds["resources"].([]any)[i] = map[string]any{"@type": c["@type"], "name": name, "type": "STATIC", "connect_timeout": "1s", "load_assignment": map[string]any{"cluster_name": name, "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": wildcardSocketAddress(upstreamPort)}}}}}}}
	}
	l, err := json.Marshal(lds)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(cds)
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}
