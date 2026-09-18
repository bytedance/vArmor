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
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// Match policy methods literally across every HTTP chain and protocol. Each
// request checks enforcement, backend method preservation and raw ALS method.
func TestHTTPMethodCaseEnvoyAudit(t *testing.T) {
	envoyBinary(t)
	rows := []struct {
		name, defaultAction string
		qualifiers          [][]string
		status              int
		action              string
		unmatched           bool
	}{
		{"allow_unmatched", "allow", [][]string{{"deny", "audit"}}, 200, "", true},
		{"allow_deny_silent", "allow", [][]string{{"deny"}}, 403, "", false},
		{"allow_deny_audit", "allow", [][]string{{"deny", "audit"}}, 403, "DENIED", false},
		{"allow_audit", "allow", [][]string{{"audit"}}, 200, "AUDIT", false},
		{"deny_unmatched", "deny", [][]string{{"allow", "audit"}}, 403, "DENIED", true},
		{"deny_allow", "deny", [][]string{{"allow"}}, 200, "", false},
		{"deny_allow_audit", "deny", [][]string{{"allow", "audit"}}, 200, "AUDIT", false},
		{"deny_overlap", "deny", [][]string{{"deny"}, {"allow", "audit"}}, 403, "DENIED", false},
	}
	for _, mode := range customMethodModes {
		for _, policy := range []struct {
			name    string
			methods []string
		}{
			{"mixed", []string{"get", "MiXeD", "X-Custom!"}},
			{"variants", []string{"GET", "get", "Get"}},
		} {
			for _, row := range rows {
				t.Run(mode.name+"/"+policy.name+"/"+row.name, func(t *testing.T) {
					var calls atomic.Int32
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"method": r.Method, "path": r.URL.Path}))
					}))
					t.Cleanup(upstream.Close)
					e := &varmor.NetworkProxyEgress{DefaultAction: row.defaultAction, HTTPRules: []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"audit"}, Match: varmor.HTTPMatch{Paths: []varmor.HTTPPathMatch{{Exact: "/unmatched"}}}}}}
					prefix := "/method/"
					if row.unmatched {
						prefix = "/not-requested/"
					}
					for _, qualifiers := range row.qualifiers {
						e.HTTPRules = append(e.HTTPRules, varmor.NetworkProxyHTTPRule{Qualifiers: qualifiers, Match: varmor.HTTPMatch{Hosts: []string{mode.host}, Methods: policy.methods, Paths: []varmor.HTTPPathMatch{{Prefix: prefix}}}})
					}
					client, base, _, events := customMethodProxy(t, mode, e, upstream.Listener.Addr().(*net.TCPAddr).Port)
					expected := make(map[string]customMethodEvent)
					var wantCalls int32
					for i, method := range []string{"GET", "get", "Get", "gEt", "MiXeD", "X-Custom!", "x-custom!"} {
						path := fmt.Sprintf("/method/%d", i)
						t.Run(method, func(t *testing.T) {
							matches := false
							for _, declared := range policy.methods {
								if method == declared {
									matches = true
								}
							}
							status, action := row.status, row.action
							if row.unmatched || !matches {
								status, action = 200, ""
								if row.defaultAction == "deny" {
									status, action = 403, "DENIED"
								}
							}
							if action != "" {
								expected[path] = customMethodEvent{action: action, method: method}
							}
							if status == 200 {
								wantCalls++
							}
							req, err := http.NewRequest(method, base+path, nil)
							require.NoError(t, err)
							resp, err := client.Do(req)
							require.NoError(t, err)
							defer resp.Body.Close()
							require.Equal(t, status, resp.StatusCode)
							if status == 200 {
								var got map[string]string
								require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
								require.Equal(t, map[string]string{"method": method, "path": path}, got)
							}
						})
					}
					assert.Equal(t, wantCalls, calls.Load())
					checkCustomMethodEvents(t, events, expected, mode.chain)
				})
			}
		}
	}
}
