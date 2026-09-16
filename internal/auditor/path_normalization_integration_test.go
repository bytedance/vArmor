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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

type pathNormalizationCase struct {
	name, requestURI, forwardedURI string
	prefix, unmatched              bool
}

type pathNormalizationRow struct {
	name, defaultAction string
	qualifiers          [][]string
	status              int
	action              string
}

// ENVOY_BINARY enables real HTTP/TLS, generated RBAC and production ALS tests.
// Only listener/upstream transport and ALS flush timing are adapted for loopback.
func TestHTTPPathNormalizationEnvoyAudit(t *testing.T) {
	binary := os.Getenv("ENVOY_BINARY")
	if binary == "" {
		t.Skip("set ENVOY_BINARY to run local Envoy integration tests")
	}
	binary, err := exec.LookPath(binary)
	if !assert.NoError(t, err) {
		return
	}
	rows := []pathNormalizationRow{
		{"allow_unmatched", "allow", nil, 200, ""},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}, 403, ""},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}, 403, "DENIED"},
		{"allow_audit", "allow", [][]string{{"audit"}}, 200, "AUDIT"},
		{"deny_unmatched", "deny", nil, 403, "DENIED"},
		{"deny_allow", "deny", [][]string{{"allow"}}, 200, ""},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}, 200, "AUDIT"},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}, 403, "DENIED"},
	}
	paths := []pathNormalizationCase{
		{"literal", "/admin/secret", "/admin/secret", false, false},
		{"slash_lower", "/admin%2fsecret", "/admin/secret", false, false},
		{"slash_upper", "/admin%2Fsecret", "/admin/secret", false, false},
		{"backslash_lower", "/admin%5csecret", "/admin/secret", false, false},
		{"backslash_upper", "/admin%5Csecret", "/admin/secret", false, false},
		{"dot_segments", "/public%2f..%2fadmin%2fsecret", "/admin/secret", false, false},
		{"merge_slashes", "/admin%2f%2fsecret", "/admin/secret", false, false},
		{"prefix", "/admin%2fsecret/child", "/admin/secret/child", true, false},
		{"query_preserved", "/admin%2fsecret?next=%2fother%5cvalue", "/admin/secret?next=%2fother%5cvalue", false, false},
		{"case_sensitive", "/Admin%2fsecret", "/Admin/secret", false, true},
		{"unrelated", "/public%2finfo", "/public/info", false, true},
		{"query_only", "/public?path=/admin%2fsecret", "/public?path=/admin%2fsecret", false, true},
		// Do not recursively decode escapes on behalf of an arbitrary backend.
		{"double_encoded", "/admin%252fsecret", "/admin%252fsecret", false, true},
	}
	for _, mode := range []string{"http", "mitm"} {
		for _, path := range paths {
			cases := rows
			// Full audit matrix for both exact and prefix rules; the remaining
			// encodings and nonmatches exercise the two audited decisions.
			if path.name != "slash_lower" && path.name != "prefix" {
				cases = []pathNormalizationRow{rows[2], rows[6]}
			}
			for _, row := range cases {
				if path.unmatched {
					row.status, row.action = 200, ""
					if row.defaultAction == "deny" {
						row.status, row.action = 403, "DENIED"
					}
				}
				t.Run(mode+"/"+path.name+"/"+row.name, func(t *testing.T) {
					runPathNormalizationEnvoy(t, binary, mode, path, row)
				})
			}
		}
	}
}

type pathNormalizationUpstream struct {
	URI, Path, Query, Method, Body string
}

func runPathNormalizationEnvoy(t *testing.T, binary, mode string, path pathNormalizationCase, row pathNormalizationRow) {
	t.Helper()
	dir := t.TempDir()
	cert, key, roots := mitmEgressTestCertificate(t, dir, "api.example.com")
	socketDir, err := os.MkdirTemp("", "path-als-")
	if !assert.NoError(t, err) {
		return
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "als.sock")
	listener, err := net.Listen("unix", socket)
	if !assert.NoError(t, err) {
		return
	}
	service, events := mitmEgressTestConsumer(t)
	server := grpc.NewServer()
	accesslogv3.RegisterAccessLogServiceServer(server, service)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); listener.Close() })
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(pathNormalizationUpstream{r.RequestURI, r.URL.Path, r.URL.RawQuery, r.Method, string(body)})
	}))
	t.Cleanup(upstream.Close)
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
	proxyPort, adminPort := mitmEgressFreePort(t, "127.0.0.1"), mitmEgressFreePort(t, "127.0.0.1")
	for adminPort == proxyPort {
		adminPort = mitmEgressFreePort(t, "127.0.0.1")
	}
	e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction}
	// Retain an active audit logger even when the tested row must be silent.
	e.Rules = []varmor.NetworkProxyEgressRule{{Qualifiers: []string{"allow", "audit"}, IP: "192.0.2.1"}}
	match := varmor.HTTPPathMatch{Exact: "/admin/secret"}
	if path.prefix {
		match = varmor.HTTPPathMatch{Prefix: "/admin/"}
	}
	for _, qualifiers := range row.qualifiers {
		e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: qualifiers,
			Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{match}},
		})
	}
	var mitm *profile.MITMInput
	scheme, chain := "http", "http_chain"
	if mode == "mitm" {
		scheme, chain = "https", "mitm_tls_dns_chain"
		mitm = &profile.MITMInput{Domains: []string{"api.example.com"}, CertificateSDSPath: mitmCertificateSDS(t, cert, key)}
	}
	result, err := profile.TranslateEgressRules(e, 1, uint16(proxyPort), mitm, profile.IPStackConfig{IPv4: true}, profile.AuditSinkConfig{ProfileName: "path-normalization-test", ALSUDSPath: socket})
	if !assert.NoError(t, err) {
		return
	}
	var lds, cds map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.LDS), &lds); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(result.CDS), &cds); err != nil {
		t.Fatal(err)
	}
	envoyListener := lds["resources"].([]interface{})[0].(map[string]interface{})
	delete(envoyListener, "@type")
	envoyListener["address"] = mitmEgressSocketAddress(proxyPort)
	// The test connects directly rather than via transparent redirection.
	var filters []interface{}
	for _, raw := range envoyListener["listener_filters"].([]interface{}) {
		if raw.(map[string]interface{})["name"] != "envoy.filters.listener.original_dst" {
			filters = append(filters, raw)
		}
	}
	envoyListener["listener_filters"] = filters
	var clusters []interface{}
	for _, raw := range cds["resources"].([]interface{}) {
		cluster := raw.(map[string]interface{})
		delete(cluster, "@type")
		if cluster["type"] == "ORIGINAL_DST" {
			name := cluster["name"]
			cluster = map[string]interface{}{
				"name": name, "type": "STATIC", "connect_timeout": "1s",
				"load_assignment": map[string]interface{}{"cluster_name": name, "endpoints": []interface{}{
					map[string]interface{}{"lb_endpoints": []interface{}{map[string]interface{}{"endpoint": map[string]interface{}{"address": mitmEgressSocketAddress(upstreamPort)}}}},
				}},
			}
		}
		clusters = append(clusters, cluster)
	}
	// Shorten ALS batching, not audit selection, for bounded silent checks.
	mitmEgressSetFlushInterval(envoyListener)
	bootstrap := map[string]interface{}{
		"node":             map[string]interface{}{"id": "path-normalization-test", "cluster": "path-normalization-test"},
		"admin":            map[string]interface{}{"address": mitmEgressSocketAddress(adminPort)},
		"static_resources": map[string]interface{}{"listeners": []interface{}{envoyListener}, "clusters": clusters},
	}
	data, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "envoy.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	var output mitmEgressLockedBuffer
	cmd := exec.Command(binary, "-c", configPath, "--concurrency", "1", "--disable-hot-restart", "--log-level", "error")
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		if t.Failed() {
			t.Logf("Envoy output: %s", output.snapshot())
		}
	})
	adminClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 200 * time.Millisecond}
	t.Cleanup(adminClient.CloseIdleConnections)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := adminClient.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort))
		ready := false
		if err == nil {
			ready = resp.StatusCode == 200
			resp.Body.Close()
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Envoy did not become ready: %s", output.snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}

	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)))
		},
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(client.CloseIdleConnections)
	// POST ensures normalization forwards the original method and body.
	req, err := http.NewRequest(http.MethodPost, scheme+"://api.example.com"+path.requestURI, strings.NewReader("payload"))
	if !assert.NoError(t, err) {
		return
	}
	resp, err := client.Do(req)
	if !assert.NoError(t, err) {
		return
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !assert.NoError(t, readErr) {
		return
	}
	assert.Equal(t, row.status, resp.StatusCode, "request=%s response=%s", path.requestURI, body)
	wantCalls := int32(0)
	if row.status == 200 {
		wantCalls = 1
		var received pathNormalizationUpstream
		if assert.NoError(t, json.Unmarshal(body, &received)) {
			expected, err := url.ParseRequestURI(path.forwardedURI)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, pathNormalizationUpstream{path.forwardedURI, expected.Path, expected.RawQuery, "POST", "payload"}, received)
		}
	}
	assert.Equal(t, wantCalls, upstreamCalls.Load())
	deadline = time.Now().Add(3 * time.Second)
	if row.action != "" {
		for len(events()) == 0 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Observe additional flush periods to catch duplicate events and silent rows.
	time.Sleep(300 * time.Millisecond)
	got := events()
	if row.action == "" {
		assert.Empty(t, got)
	} else {
		assert.Equal(t, []mitmEgressObservedEvent{{Action: row.action, Path: path.forwardedURI, FilterChain: chain, DstAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))}}, got)
	}
	t.Logf("request=%s HTTP=%d upstream=%s events=%+v", path.requestURI, resp.StatusCode, strings.TrimSpace(string(body)), got)
}
