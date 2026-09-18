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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// Exercise mapped subnets with the complete audit matrix on both HTTP and
// TCP. The listener destination is 127.0.0.1, not the subnet's base address,
// so accidentally clamping an IPv6 prefix to IPv4 /32 cannot pass unnoticed.
func TestMappedCIDREnvoyAudit(t *testing.T) {
	binary := envoyBinary(t)
	type auditRow struct {
		name, defaultAction string
		qualifiers          [][]string
		allowed             bool
		action              string
		unmatched           bool
	}
	matrix := []auditRow{
		{"allow_unmatched", "allow", [][]string{{"deny", "audit"}}, true, "", true},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}, false, "", false},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}, false, "DENIED", false},
		{"allow_audit", "allow", [][]string{{"audit"}}, true, "AUDIT", false},
		{"deny_unmatched", "deny", [][]string{{"allow", "audit"}}, false, "DENIED", true},
		{"deny_allow", "deny", [][]string{{"allow"}}, true, "", false},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}, true, "AUDIT", false},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}, false, "DENIED", false},
	}
	type row struct {
		auditRow
		cidr, protocol string
	}
	var rows []row
	for _, bits := range []int{96, 97, 104, 112, 120, 126, 127, 128} {
		for _, protocol := range []string{"http", "tcp"} {
			for _, m := range matrix {
				if bits == 96 && m.unmatched {
					continue
				} // IPv4 /0 has no outside IPv4 address.
				host := "127.0.0.1"
				if m.unmatched {
					host = "192.0.2.1"
				}
				m.name = fmt.Sprintf("%s/prefix_%d/%s", protocol, bits, m.name)
				rows = append(rows, row{m, fmt.Sprintf("::ffff:%s/%d", host, bits), protocol})
			}
		}
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			var calls atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := upstream.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				calls.Add(1)
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return
				}
				if tc.protocol == "http" {
					request, err := http.ReadRequest(bufio.NewReader(conn))
					if err != nil {
						return
					}
					request.Body.Close()
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
				} else {
					_, _ = io.Copy(conn, conn)
				}
			}()
			t.Cleanup(func() { upstream.Close(); <-done })
			socket, events := startAuditCollector(t)
			proxyPort, adminPort := freePort(t, "127.0.0.1"), freePort(t, "127.0.0.1")
			for proxyPort == adminPort {
				adminPort = freePort(t, "127.0.0.1")
			}
			var rules []varmor.NetworkProxyEgressRule
			for _, qualifiers := range tc.qualifiers {
				rules = append(rules, varmor.NetworkProxyEgressRule{Qualifiers: qualifiers, CIDR: tc.cidr})
			}
			result, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{
				DefaultAction: tc.defaultAction,
				Rules:         rules,
			}, 1, uint16(proxyPort), nil, profile.IPStackConfig{IPv4: true}, profile.AuditSinkConfig{ProfileName: "mapped-cidr", ALSUDSPath: socket})
			require.NoError(t, err)
			lds, cds := reloadTransport(t, result.LDS, result.CDS, proxyPort, upstream.Addr().(*net.TCPAddr).Port)
			var listeners map[string]any
			require.NoError(t, json.Unmarshal(lds, &listeners))
			listener := listeners["resources"].([]any)[0].(map[string]any)
			listener["address"].(map[string]any)["socket_address"].(map[string]any)["address"] = "127.0.0.1"
			delete(listener, "@type")
			var clusters map[string]any
			require.NoError(t, json.Unmarshal(cds, &clusters))
			for _, raw := range clusters["resources"].([]any) {
				delete(raw.(map[string]any), "@type")
			}
			config, err := json.Marshal(map[string]any{
				"node":             map[string]any{"id": "mapped-cidr", "cluster": "mapped-cidr"},
				"admin":            map[string]any{"address": socketAddress(adminPort)},
				"static_resources": map[string]any{"listeners": []any{listener}, "clusters": clusters["resources"]},
			})
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "bootstrap.json")
			atomicWrite(t, path, config)
			output := startEnvoy(t, binary, path)
			waitEnvoyReady(t, adminPort, output)
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			if tc.protocol == "http" {
				_, err := io.WriteString(conn, "GET /mapped HTTP/1.1\r\nHost: review.local\r\nConnection: close\r\n\r\n")
				require.NoError(t, err)
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				if tc.allowed {
					require.Equal(t, 200, response.StatusCode)
					require.Equal(t, "OK", string(body))
				} else {
					require.Equal(t, 403, response.StatusCode)
					require.True(t, strings.Contains(string(body), "RBAC: access denied"))
				}
			} else {
				_, writeErr := conn.Write([]byte("PING\r\n"))
				buf := make([]byte, 6)
				_, readErr := io.ReadFull(conn, buf)
				if tc.allowed {
					require.NoError(t, writeErr)
					require.NoError(t, readErr)
					require.Equal(t, "PING\r\n", string(buf))
				} else {
					require.Error(t, readErr)
					if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
						t.Fatal("denied connection timed out instead of closing")
					}
				}
			}
			require.NoError(t, conn.Close())
			if tc.action != "" {
				require.Eventually(t, func() bool { return len(events()) != 0 }, 3*time.Second, 20*time.Millisecond)
			}
			time.Sleep(300 * time.Millisecond)
			wantCalls := int32(0)
			if tc.allowed {
				wantCalls = 1
			}
			require.Equal(t, wantCalls, calls.Load())
			got := events()
			if tc.action == "" {
				require.Empty(t, got)
			} else {
				require.Len(t, got, 1)
				require.Equal(t, tc.action, got[0].Action)
				require.Equal(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), got[0].DstAddress)
			}
		})
	}
}
