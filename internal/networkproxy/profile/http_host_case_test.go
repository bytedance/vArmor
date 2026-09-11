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
	"regexp"
	"testing"

	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

// Decode the rendered YAML using Envoy's schema, including nested OR rules.
func decodeHostCasePermission(t *testing.T, rule PermissionRule) *rbacv3.Permission {
	t.Helper()
	data, err := yaml.YAMLToJSON([]byte(renderPermissionRuleYAML(rule, 0, "http")))
	if err != nil {
		t.Fatal(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("permissions=%d, want 1", len(items))
	}
	var permission rbacv3.Permission
	if err := protojson.Unmarshal(items[0], &permission); err != nil {
		t.Fatal(err)
	}
	if err := permission.ValidateAll(); err != nil {
		t.Fatal(err)
	}
	return &permission
}

func TestHTTPAuthorityCaseMatchers(t *testing.T) {
	tests := []struct {
		name, host string
		port       uint16
	}{
		{"exact_default", "Api.Example.COM", 80},
		{"exact_tls_default", "Api.Example.COM", 443},
		{"exact_nondefault", "Api.Example.COM", 8443},
		{"exact_and_prefix", "Api.Example.COM", 0},
		{"wildcard_default", "*.Example.COM", 80},
		{"wildcard_nondefault", "*.Example.COM", 8443},
		{"wildcard_regex", "*.Example.COM", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := authorityMatcherForHostPort(tt.host, tt.port)
			if tt.port == 0 {
				rule = portAgnosticHostRules([]string{tt.host})[0]
			}
			var check func(*rbacv3.Permission)
			check = func(p *rbacv3.Permission) {
				if or := p.GetOrRules(); or != nil {
					for _, child := range or.Rules {
						check(child)
					}
					return
				}
				h := p.GetHeader()
				if h == nil || h.Name != ":authority" {
					t.Fatalf("unexpected permission: %v", p)
				}
				m := h.GetStringMatch()
				if m == nil {
					t.Fatal("missing string matcher")
				}
				if r := m.GetSafeRegex(); r != nil {
					// ignore_case does not apply to safe_regex; verify its actual behavior.
					re, err := regexp.Compile(r.Regex)
					if err != nil {
						t.Fatal(err)
					}
					for _, host := range []string{"api.example.com", "API.EXAMPLE.COM", "Api.ExAmPlE.cOm:8443"} {
						assert.True(t, re.MatchString(host), "regex rejected %q", host)
					}
					for _, host := range []string{"example.com", "evilexample.com", "api.example.com.evil", "api.exampleXcom", "api.example.com:abc"} {
						assert.False(t, re.MatchString(host), "regex accepted unrelated authority %q", host)
					}
				} else {
					assert.True(t, m.IgnoreCase, "authority remains case-sensitive: %v", m)
				}
			}
			check(decodeHostCasePermission(t, rule))
		})
	}
}

func TestHTTPNonHostMatchersRemainCaseSensitive(t *testing.T) {
	for _, name := range []string{":method", "x-token"} {
		for _, kind := range []string{"exact_match", "prefix_match", "suffix_match", "safe_regex_match"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				value := "SeCrEt"
				p := decodeHostCasePermission(t, PermissionRule{Type: "header", Value: map[string]string{"name": name, kind: value}})
				m := p.GetHeader().GetStringMatch()
				if m.IgnoreCase {
					t.Fatal("non-host header became case-insensitive")
				}
				if r := m.GetSafeRegex(); r != nil && r.Regex != value {
					t.Fatalf("header regex changed: %q", r.Regex)
				}
			})
		}
	}
	for _, kind := range []string{"exact", "prefix"} {
		t.Run("path/"+kind, func(t *testing.T) {
			p := decodeHostCasePermission(t, PermissionRule{Type: "url_path", Value: map[string]string{kind: "/SeCrEt"}})
			m := p.GetUrlPath().GetPath()
			if m.IgnoreCase || (m.GetExact() != "/SeCrEt" && m.GetPrefix() != "/SeCrEt") {
				t.Fatalf("path matcher changed: %v", m)
			}
		})
	}
}
