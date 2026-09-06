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
	"fmt"
	"strings"
	"testing"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	grpcv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// TestAuditSelectionMatrix pins the rule buckets and logging predicate for all
// ten API semantics. Enforcement classification is intentionally unchanged.
func TestAuditSelectionMatrix(t *testing.T) {
	tests := []struct {
		name, defaultAction string
		qualifiers          []string
		denied, event       bool
	}{
		{"deny/unmatched", "deny", nil, true, true},
		{"deny/allow", "deny", []string{"allow"}, false, false},
		{"deny/allow-audit", "deny", []string{"allow", "audit"}, false, true},
		{"deny/deny", "deny", []string{"deny"}, true, true},
		{"deny/deny-audit", "deny", []string{"deny", "audit"}, true, true},
		{"allow/unmatched", "allow", nil, false, false},
		{"allow/deny", "allow", []string{"deny"}, true, false},
		{"allow/deny-audit", "allow", []string{"deny", "audit"}, true, true},
		{"allow/audit", "allow", []string{"audit"}, false, true},
		{"allow/allow-audit", "allow", []string{"allow", "audit"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &varmor.NetworkProxyEgress{DefaultAction: tt.defaultAction}
			if tt.qualifiers != nil {
				e.Rules = []varmor.NetworkProxyEgressRule{{Qualifiers: tt.qualifiers, IP: "10.0.0.1"}}
				e.HTTPRules = []varmor.NetworkProxyHTTPRule{{Qualifiers: tt.qualifiers, Match: varmor.HTTPMatch{Hosts: []string{"httpbin.org"}}}}
				action, audited := classifyRule(tt.qualifiers, tt.defaultAction == "deny")
				if (action == ruleActionDeny) != tt.denied || audited != tt.event {
					t.Fatalf("classification = %v/%v, want denied=%v/audit=%v", action, audited, tt.denied, tt.event)
				}
			}
			cls := classifyEgress(e)
			for _, l7 := range []bool{false, true} {
				shadowMatch := cls.auditCfg.HasShadowEgressRules()
				deny, shadow := computeListenerCELs(cls.defaultDeny, shadowMatch)
				if l7 {
					shadowMatch = cls.auditCfg.HasShadowHTTPRules()
					deny, shadow = computeHCMCELs(cls.defaultDeny, shadowMatch)
				}
				// No match has no rules; every supplied rule in this table matches.
				if deny == "" && shadow == "" {
					if tt.event {
						t.Fatal("missing required access logger")
					}
					continue
				}
				var sb strings.Builder
				renderAccessLogFilter(&sb, "", deny, shadow)
				log := decodeAuditLog(t, "name: test\n"+sb.String())
				got := selectedAuditFilter(t, log.Filter, tt.denied, shadowMatch)
				if got != tt.event {
					t.Errorf("L7=%v selected=%v, want %v", l7, got, tt.event)
				}
			}
		})
	}
}

// Evaluate each independently rendered child using controlled RBAC outcomes.
// This checks the filter tree, not Envoy's CEL runtime implementation.
func selectedAuditFilter(t *testing.T, f *accesslogv3.AccessLogFilter, denied, shadow bool) bool {
	t.Helper()
	if or := f.GetOrFilter(); or != nil {
		for _, child := range or.Filters {
			if selectedAuditFilter(t, child, denied, shadow) {
				return true
			}
		}
		return false
	}
	ext := f.GetExtensionFilter()
	if ext == nil {
		t.Fatal("expected CEL extension_filter")
	}
	var expr celv3.ExpressionFilter
	if err := ext.GetTypedConfig().UnmarshalTo(&expr); err != nil {
		t.Fatal(err)
	}
	switch expr.Expression {
	case celListenerDeny, celHCMDeny:
		return denied
	case celListenerShadow, celHCMShadow:
		return shadow
	default:
		t.Fatalf("unexpected CEL expression %q", expr.Expression)
		return false
	}
}

func decodeAuditLog(t *testing.T, input string) *accesslogv3.AccessLog {
	t.Helper()
	data, err := yaml.YAMLToJSON([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	var log accesslogv3.AccessLog
	if err := protojson.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if err := log.ValidateAll(); err != nil {
		t.Fatal(err)
	}
	return &log
}

func TestAuditFilterOverlapAndUnmatchedShadow(t *testing.T) {
	for _, l7 := range []bool{false, true} {
		for _, defaultDeny := range []bool{false, true} {
			deny, shadow := computeListenerCELs(defaultDeny, true)
			if l7 {
				deny, shadow = computeHCMCELs(defaultDeny, true)
			}
			var sb strings.Builder
			renderAccessLogFilter(&sb, "", deny, shadow)
			log := decodeAuditLog(t, "name: test\n"+sb.String())
			for _, denied := range []bool{false, true} {
				for _, matched := range []bool{false, true} {
					want := (defaultDeny && denied) || matched
					if got := selectedAuditFilter(t, log.Filter, denied, matched); got != want {
						t.Errorf("L7=%v defaultDeny=%v denied=%v shadow=%v selected=%v, want %v", l7, defaultDeny, denied, matched, got, want)
					}
				}
			}
		}
	}
}

func TestAuditLoggerLocations(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, mitmEnabled := range []bool{false, true} {
			for _, sink := range []string{"grpc"} {
				t.Run(fmt.Sprintf("enabled=%t/mitm=%t/sink=%s", enabled, mitmEnabled, sink), func(t *testing.T) {
					e := &varmor.NetworkProxyEgress{DefaultAction: "allow"}
					if enabled {
						e.DefaultAction = "deny"
						e.Rules = []varmor.NetworkProxyEgressRule{{Qualifiers: []string{"allow", "audit"}, IP: "10.0.0.1"}}
						e.HTTPRules = []varmor.NetworkProxyHTTPRule{{Qualifiers: []string{"allow", "audit"}, Match: varmor.HTTPMatch{Hosts: []string{"*"}}}}
					}
					var mitm *MITMInput
					if mitmEnabled {
						mitm = &MITMInput{Domains: []string{"httpbin.org", "10.0.0.2"}}
					}
					audit := AuditSinkConfig{ProfileName: "profile-a", ALSUDSPath: "/run/audit.sock"}
					res, err := TranslateEgressRules(e, 1, 15001, mitm, testIPStack, audit)
					if err != nil {
						t.Fatal(err)
					}
					var document interface{}
					if err := yaml.Unmarshal([]byte(res.LDS), &document); err != nil {
						t.Fatal(err)
					}
					locations := 0
					var walk func(interface{})
					walk = func(node interface{}) {
						switch v := node.(type) {
						case map[string]interface{}:
							for key, child := range v {
								if key == "access_log" {
									locations++
									logs, ok := child.([]interface{})
									if !ok || len(logs) != 1 {
										t.Fatalf("access_log must have one entry: %#v", child)
									}
									data, err := json.Marshal(logs[0])
									if err != nil {
										t.Fatal(err)
									}
									log := decodeAuditLog(t, string(data))
									if sink == "grpc" {
										var common *grpcv3.CommonGrpcAccessLogConfig
										if log.GetTypedConfig().MessageIs(&grpcv3.HttpGrpcAccessLogConfig{}) {
											var cfg grpcv3.HttpGrpcAccessLogConfig
											if err := log.GetTypedConfig().UnmarshalTo(&cfg); err != nil {
												t.Fatal(err)
											}
											if err := cfg.ValidateAll(); err != nil {
												t.Fatal(err)
											}
											common = cfg.CommonConfig
										} else {
											var cfg grpcv3.TcpGrpcAccessLogConfig
											if err := log.GetTypedConfig().UnmarshalTo(&cfg); err != nil {
												t.Fatal(err)
											}
											if err := cfg.ValidateAll(); err != nil {
												t.Fatal(err)
											}
											common = cfg.CommonConfig
										}
										if common.GetLogName() != "varmor_np_event:profile-a" {
											t.Fatalf("unexpected log name: %s", common.GetLogName())
										}
									}
								} else {
									walk(child)
								}
							}
						case []interface{}:
							for _, child := range v {
								walk(child)
							}
						}
					}
					walk(document)
					want := 0
					if enabled {
						want = 2
						if mitmEnabled {
							want = 4
						}
					}
					if locations != want {
						t.Errorf("logging locations=%d, want %d", locations, want)
					}
				})
			}
		}
	}
}

func TestAuditDenyWithCatchAllHTTP(t *testing.T) {
	// Regression: /secret is denied, while the independent catch-all audit
	// rule also matches. Shadow metadata must not label this denial AUDIT.
	e := &varmor.NetworkProxyEgress{
		DefaultAction: "allow",
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{Qualifiers: []string{"audit", "deny"}, Match: varmor.HTTPMatch{
				Hosts: []string{"httpbin.org"},
				Paths: []varmor.HTTPPathMatch{{Prefix: "/admin/"}, {Exact: "/secret"}},
			}},
			{Qualifiers: []string{"audit"}, Match: varmor.HTTPMatch{Hosts: []string{"*"}}},
		},
	}
	cls := classifyEgress(e)
	if cls.defaultDeny || len(cls.denyHTTPRules) != 1 || len(cls.auditCfg.AuditShadowHTTPRules) != 2 {
		t.Fatalf("enforcement/audit rule buckets changed: %+v", cls)
	}
	audit := AuditSinkConfig{ProfileName: "profile-a", ALSUDSPath: "/run/audit.sock"}
	for _, mitm := range []*MITMInput{nil, {Domains: []string{"httpbin.org"}}} {
		res, err := TranslateEgressRules(e, 1, 15001, mitm, testIPStack, audit)
		if err != nil {
			t.Fatal(err)
		}
		wantLocations := 2 // Listener and plaintext HTTP HCM.
		if mitm != nil {
			wantLocations++
		}
		if n := strings.Count(res.LDS, "log_name:"); n != wantLocations {
			t.Errorf("got %d loggers, want %d", n, wantLocations)
		}
		for _, absent := range []string{yamlCEL(celHCMDeny), yamlCEL(celListenerDeny), "or_filter:", "varmor_np_audit:", "varmor_np_deny:"} {
			if strings.Contains(res.LDS, absent) {
				t.Errorf("allow-default must keep only shadow selection, found %q", absent)
			}
		}
		for _, present := range []string{"action: DENY", "shadow_rules:", "/secret", yamlCEL(celHCMShadow), "varmor_np_event:profile-a"} {
			if !strings.Contains(res.LDS, present) {
				t.Errorf("missing %q", present)
			}
		}
	}
}
