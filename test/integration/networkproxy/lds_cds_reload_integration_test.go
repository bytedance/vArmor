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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// TestLDSCDSReloadEnvoy exercises file-based xDS updates with real traffic and
// the production ALS consumer. TLS files already exist, as they must in a
// deployed MITM-capable instance. Only loopback transport plumbing is replaced.
func TestLDSCDSReloadEnvoy(t *testing.T) {
	binary := envoyBinary(t)
	for _, order := range []string{"lds_first", "cds_first", "atomic_directory"} {
		t.Run(order, func(t *testing.T) {
			dir := t.TempDir()
			cert, key, roots := testCertificate(t, dir, "api.example.com")
			socket, events := startAuditCollector(t)
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls.Add(1); w.WriteHeader(http.StatusOK) }))
			t.Cleanup(upstream.Close)
			upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
			proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
			for adminPort == proxyPort {
				adminPort = freePort(t, "127.0.0.1")
			}
			audit := profile.AuditSinkConfig{ProfileName: "reload-test", ALSUDSPath: socket}
			old, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{DefaultAction: "allow"}, 1, uint16(proxyPort), nil, profile.IPStackConfig{IPv4: true}, audit)
			if err != nil {
				t.Fatal(err)
			}
			next, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{DefaultAction: "deny", HTTPRules: []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"allow", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"api.example.com"}, Paths: []varmor.HTTPPathMatch{{Exact: "/allowed"}}}}}}, 2, uint16(proxyPort), &profile.MITMInput{Domains: []string{"api.example.com"}, CertificateSDSPath: certificateSDS(t, cert, key)}, profile.IPStackConfig{IPv4: true}, audit)
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
				atomicWrite(t, filepath.Join(ldsDir, "old/lds.yaml"), oldLDS)
				atomicWrite(t, filepath.Join(ldsDir, "old/cds.yaml"), oldCDS)
				atomicWrite(t, filepath.Join(ldsDir, "new/lds.yaml"), newLDS)
				atomicWrite(t, filepath.Join(ldsDir, "new/cds.yaml"), newCDS)
				for link, target := range map[string]string{"..data": "old", "lds.yaml": "..data/lds.yaml", "cds.yaml": "..data/cds.yaml"} {
					if err := os.Symlink(target, filepath.Join(ldsDir, link)); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				atomicWrite(t, ldsPath, oldLDS)
				atomicWrite(t, cdsPath, oldCDS)
			}
			source := func(path, dir string) any {
				return map[string]any{"path_config_source": map[string]any{"path": path, "watched_directory": map[string]any{"path": dir}}}
			}
			bootstrap := map[string]any{"node": map[string]any{"id": "reload-test", "cluster": "reload-test"}, "admin": map[string]any{"address": socketAddress(adminPort)}, "dynamic_resources": map[string]any{"lds_config": source(ldsPath, ldsDir), "cds_config": source(cdsPath, cdsDir)}}
			config, err := json.Marshal(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "bootstrap.json")
			atomicWrite(t, configPath, config)
			startEnvoy(t, binary, configPath)
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
			awaitCondition(t, "initial listener", func() bool { return active("1") && stats()["listener_manager.workers_started"] == 1 })
			if got := request("http", "/secret"); got != 200 {
				t.Fatalf("initial HTTP=%d want 200", got)
			}
			if got := upstreamCalls.Load(); got != 1 {
				t.Fatalf("initial upstream calls=%d want 1", got)
			}
			rejected := func() bool { return stats()["listener_manager.lds.update_rejected"] > 0 }
			waitCDS := func() {
				awaitCondition(t, "new CDS", func() bool { return stats()["cluster_manager.cds.update_success"] >= 2 })
			}
			type eventKey struct{ Action, Path, FilterChain string }
			wantEvents := map[eventKey]int{}
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
				wantEvents[eventKey{Action: action, Path: path, FilterChain: chain}]++
			}
			if order == "cds_first" {
				atomicWrite(t, cdsPath, newCDS)
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
				atomicWrite(t, ldsPath, newLDS)
			}
			awaitCondition(t, "LDS update accepted or rejected", func() bool { return active("2") || rejected() })
			if rejected() {
				// Finish the delayed CDS update without another LDS notification, then
				// expose the stale allow policy rather than hiding the rejection in a timeout.
				if order == "lds_first" {
					atomicWrite(t, cdsPath, newCDS)
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
				atomicWrite(t, cdsPath, newCDS)
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
			awaitCondition(t, "audit delivery", func() bool { return len(events()) >= wantCount })
			time.Sleep(300 * time.Millisecond)
			gotEvents := map[eventKey]int{}
			for _, e := range events() {
				gotEvents[eventKey{e.Action, e.Path, e.FilterChain}]++
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
	listener["address"] = socketAddress(proxyPort)
	var filters []any
	for _, raw := range listener["listener_filters"].([]any) {
		if raw.(map[string]any)["name"] != "envoy.filters.listener.original_dst" {
			filters = append(filters, raw)
		}
	}
	listener["listener_filters"] = filters
	setALSFlushInterval(listener)
	for i, raw := range cds["resources"].([]any) {
		c := raw.(map[string]any)
		if c["type"] != "ORIGINAL_DST" {
			continue
		}
		name := c["name"]
		cds["resources"].([]any)[i] = map[string]any{"@type": c["@type"], "name": name, "type": "STATIC", "connect_timeout": "1s", "load_assignment": map[string]any{"cluster_name": name, "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": socketAddress(upstreamPort)}}}}}}}
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
