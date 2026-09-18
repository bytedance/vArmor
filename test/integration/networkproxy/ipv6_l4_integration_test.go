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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	profile "github.com/bytedance/vArmor/internal/networkproxy/profile"
)

// Exercise network RBAC independently of HTTP RBAC. ::1 and ::2 share /32,
// so both erroneous allow and deny matches reproduce with the old renderer.
func TestIPv6L4HostEnvoyAudit(t *testing.T) {
	binary := envoyBinary(t)
	for _, tc := range []struct {
		name, defaultAction, qualifier, ip, cidr, action string
		allowed                                          bool
	}{
		{"allow_host", "deny", "allow", "::1", "", "AUDIT", true},
		{"allow_neighbor", "deny", "allow", "::2", "", "DENIED", false},
		{"allow_neighbor_cidr", "deny", "allow", "", "::2/128", "DENIED", false},
		{"deny_host", "allow", "deny", "::1", "", "DENIED", false},
		{"deny_neighbor", "allow", "deny", "::2", "", "", true},
		{"deny_neighbor_cidr", "allow", "deny", "", "::2/128", "", true},
	} {
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
				_, _ = io.Copy(conn, conn)
			}()
			t.Cleanup(func() { upstream.Close(); <-done })
			socket, events := startAuditCollector(t)
			proxyPort, adminPort := freePort(t, "::1"), freePort(t, "127.0.0.1")
			for proxyPort == adminPort {
				adminPort = freePort(t, "127.0.0.1")
			}
			result, err := profile.TranslateEgressRules(&varmor.NetworkProxyEgress{
				DefaultAction: tc.defaultAction,
				Rules:         []varmor.NetworkProxyEgressRule{{Qualifiers: []string{tc.qualifier, "audit"}, IP: tc.ip, CIDR: tc.cidr}},
			}, 1, uint16(proxyPort), nil, profile.IPStackConfig{IPv6: true}, profile.AuditSinkConfig{ProfileName: "ipv6-l4-host", ALSUDSPath: socket})
			require.NoError(t, err)
			lds, cds := reloadTransport(t, result.LDS, result.CDS, proxyPort, upstream.Addr().(*net.TCPAddr).Port)
			var listeners map[string]any
			require.NoError(t, json.Unmarshal(lds, &listeners))
			listener := listeners["resources"].([]any)[0].(map[string]any)
			listener["address"].(map[string]any)["socket_address"].(map[string]any)["address"] = "::1"
			delete(listener, "@type")
			var clusters map[string]any
			require.NoError(t, json.Unmarshal(cds, &clusters))
			for _, raw := range clusters["resources"].([]any) {
				delete(raw.(map[string]any), "@type")
			}
			config, err := json.Marshal(map[string]any{
				"node":             map[string]any{"id": "ipv6-l4-host", "cluster": "ipv6-l4-host"},
				"admin":            map[string]any{"address": socketAddress(adminPort)},
				"static_resources": map[string]any{"listeners": []any{listener}, "clusters": clusters["resources"]},
			})
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "bootstrap.json")
			atomicWrite(t, path, config)
			output := startEnvoy(t, binary, path)
			waitEnvoyReady(t, adminPort, output)
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("[::1]:%d", proxyPort), time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			_, writeErr := conn.Write([]byte("PING\r\n"))
			buf := make([]byte, 6)
			_, readErr := io.ReadFull(conn, buf)
			require.NoError(t, conn.Close())
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
				require.Equal(t, fmt.Sprintf("[::1]:%d", proxyPort), got[0].DstAddress)
			}
		})
	}
}
