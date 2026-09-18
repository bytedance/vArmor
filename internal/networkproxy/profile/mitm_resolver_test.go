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

package profile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestResolveHeaderActionValue_SecretContents(t *testing.T) {
	for _, tc := range []struct {
		name      string
		data      map[string][]byte
		want      string
		errorText string
	}{
		{"empty bytes", map[string][]byte{"token": {}}, "", `secret test/credentials key "token" must not be empty`},
		{"nil bytes", map[string][]byte{"token": nil}, "", `secret test/credentials key "token" must not be empty`},
		{"missing key", map[string][]byte{"other": []byte("private-value")}, "", `has no key "token"`},
		{"nil data", nil, "", `has no key "token"`},
		{"credential", map[string][]byte{"token": []byte("Bearer test-token")}, "Bearer test-token", ""},
		{"preserve whitespace", map[string][]byte{"token": []byte(" test-token ")}, " test-token ", ""},
		{"preserve percent", map[string][]byte{"token": []byte("test%TOKEN%")}, "test%TOKEN%", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := varmor.HeaderAction{Name: "Authorization", SecretRef: &varmor.SecretKeyRef{Name: "credentials", Key: "token"}}
			value, err := resolveHeaderActionValue(nil, "test", h, map[string]map[string][]byte{"credentials": tc.data})
			if tc.errorText != "" {
				require.ErrorContains(t, err, tc.errorText)
				assert.NotContains(t, err.Error(), "private-value")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, value)
		})
	}
}

func TestResolveMITMInput_SecretHeaders(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     []byte
		wantError bool
	}{
		{"nonempty", []byte("Bearer fake-token"), false},
		{"empty", []byte{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/api/v1/namespaces/workload/secrets/credentials", r.URL.Path)
				gets.Add(1)
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "workload"},
					Data:       map[string][]byte{"first": []byte("private-first"), "token": tc.value},
				})
				assert.NoError(t, err)
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			require.NoError(t, err)
			cfg := &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{
				Domains: []string{"api.example.test"},
				HeaderMutations: []varmor.HeaderMutation{{Domain: "api.example.test", Headers: []varmor.HeaderAction{
					{Name: "X-First", SecretRef: &varmor.SecretKeyRef{Name: "credentials", Key: "first"}},
					{Name: "Authorization", SecretRef: &varmor.SecretKeyRef{Name: "credentials", Key: "token"}},
				}}},
			}}
			before := cfg.DeepCopy()
			input, err := ResolveMITMInput(client, "workload", cfg)
			if tc.wantError {
				require.ErrorContains(t, err, `resolve header "Authorization" on domain "api.example.test": secret workload/credentials key "token" must not be empty`)
				assert.NotContains(t, err.Error(), "private-first")
				assert.Nil(t, input, "a failure must not return partial header injections")
			} else {
				require.NoError(t, err)
				assert.Equal(t, []HeaderToAdd{{Name: "X-First", Value: "private-first"}, {Name: "Authorization", Value: string(tc.value)}}, input.HeadersByDomain["api.example.test"])
			}
			assert.Equal(t, int32(1), gets.Load(), "references in the same reconcile share one Secret read")
			assert.Equal(t, before, cfg, "resolution must not mutate the policy")
		})
	}
}
