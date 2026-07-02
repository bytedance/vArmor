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
	"strings"
	"testing"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	als "github.com/bytedance/vArmor/pkg/networkproxy/als"
)

// alsFixtureEgress builds a deny-default egress that exercises all four
// access_log entries: L4 deny + L4 shadow (listener) and L7 deny + L7 shadow
// (HCM). The deny default turns on the deny CEL on both layers; the allow+audit
// egress rule produces shadow_rules on the TLS/TCP path, and the allow+audit
// HTTP rule produces shadow_rules on the HTTP chain.
func alsFixtureEgress() *varmor.NetworkProxyEgress {
	return &varmor.NetworkProxyEgress{
		DefaultAction: "deny",
		Rules: []varmor.NetworkProxyEgressRule{
			{
				Qualifiers: []string{"allow", "audit"},
				IP:         "10.0.0.1",
				Ports:      []varmor.Port{{Port: 443}},
			},
		},
		HTTPRules: []varmor.NetworkProxyHTTPRule{
			{
				Qualifiers: []string{"allow", "audit"},
				Match: varmor.HTTPMatch{
					Hosts: []string{"api.openai.com"},
				},
			},
		},
	}
}

const alsTestProfile = "varmor-openclaw-shared"

// renderALSAudit translates the fixture egress with the supplied audit sink and
// returns the LDS + CDS YAML.
func renderALSAudit(t *testing.T, mitm *MITMInput, audit AuditSinkConfig) (lds, cds string) {
	t.Helper()
	res, err := TranslateEgressRules(alsFixtureEgress(), 1, varmorconfig.DefaultProxyPort, mitm,
		testIPStack, audit)
	if err != nil {
		t.Fatalf("TranslateEgressRules: %v", err)
	}
	return res.LDS, res.CDS
}

// TestAuditSink_GRPCALS_ListenerAndHCM verifies that the grpc_als sink renders
// TcpGrpcAccessLogConfig at the listener (L4) and HttpGrpcAccessLogConfig at
// the HCM (L7), each as two SEPARATE entries (deny + shadow) carrying the
// correct log_name class prefix and the ALS cluster_name.
func TestAuditSink_GRPCALS_ListenerAndHCM(t *testing.T) {
	audit := AuditSinkConfig{
		ALSUDSPath:  "/var/run/varmor/audit/als.sock",
		ProfileName: alsTestProfile,
	}
	lds, cds := renderALSAudit(t, nil, audit)

	// No stdout sink should remain anywhere in the LDS.
	if strings.Contains(lds, "StdoutAccessLog") {
		t.Errorf("grpc_als LDS must not contain any StdoutAccessLog")
	}

	// L4 uses TcpGrpcAccessLogConfig, L7 uses HttpGrpcAccessLogConfig.
	if !strings.Contains(lds, "access_loggers.grpc.v3.TcpGrpcAccessLogConfig") {
		t.Errorf("expected TcpGrpcAccessLogConfig (L4) in LDS")
	}
	if !strings.Contains(lds, "access_loggers.grpc.v3.HttpGrpcAccessLogConfig") {
		t.Errorf("expected HttpGrpcAccessLogConfig (L7) in LDS")
	}

	// log_name class prefixes with the profile suffix. Deny appears at L4+L7,
	// shadow/audit appears at L4+L7.
	wantDeny := `log_name: "varmor_np_deny:` + alsTestProfile + `"`
	wantAudit := `log_name: "varmor_np_audit:` + alsTestProfile + `"`
	if c := strings.Count(lds, wantDeny); c != 2 {
		t.Errorf("expected 2 deny log_name entries (L4+L7), got %d", c)
	}
	if c := strings.Count(lds, wantAudit); c != 2 {
		t.Errorf("expected 2 audit log_name entries (L4+L7), got %d", c)
	}

	// Every ALS entry must dial the shared cluster name (4 entries total).
	if c := strings.Count(lds, "cluster_name: "+als.DefaultALSClusterName); c != 4 {
		t.Errorf("expected 4 envoy_grpc cluster_name references, got %d", c)
	}

	// The CEL filters must be preserved on the ALS entries (deny + shadow,
	// not merged into one). Deny expressions contain double-quotes, so they
	// appear YAML-escaped in the rendered scalar; compare against that form.
	if !strings.Contains(lds, yamlCEL(celListenerDeny)) || !strings.Contains(lds, yamlCEL(celListenerShadow)) {
		t.Errorf("listener deny/shadow CEL filters not preserved on ALS entries")
	}
	if !strings.Contains(lds, yamlCEL(celHCMDeny)) || !strings.Contains(lds, yamlCEL(celHCMShadow)) {
		t.Errorf("HCM deny/shadow CEL filters not preserved on ALS entries")
	}

	// CDS must carry the STATIC UDS ALS cluster.
	for _, want := range []string{
		"name: " + als.DefaultALSClusterName,
		"type: STATIC",
		"connect_timeout: 1s",
		"lb_policy: ROUND_ROBIN",
		"http2_protocol_options: {}",
		`path: "/var/run/varmor/audit/als.sock"`,
	} {
		if !strings.Contains(cds, want) {
			t.Errorf("expected CDS to contain %q", want)
		}
	}
	// original_dst must still be present (ALS is additive).
	if !strings.Contains(cds, "name: original_dst") {
		t.Errorf("ALS CDS dropped the original_dst cluster")
	}
}

// TestAuditSink_CustomClusterName verifies that a non-default ALSClusterName is
// honoured in both the access_log entries and the emitted cluster.
func TestAuditSink_CustomClusterName(t *testing.T) {
	audit := AuditSinkConfig{
		ALSClusterName: "custom_als",
		ALSUDSPath:     "/tmp/x.sock",
		ProfileName:    alsTestProfile,
	}
	lds, cds := renderALSAudit(t, nil, audit)
	if !strings.Contains(lds, "cluster_name: custom_als") {
		t.Errorf("expected custom cluster_name in LDS")
	}
	if !strings.Contains(cds, "name: custom_als") {
		t.Errorf("expected custom cluster in CDS")
	}
	if strings.Contains(cds, "name: "+als.DefaultALSClusterName) {
		t.Errorf("default ALS cluster name must not appear when overridden")
	}
}

// TestAuditSink_AllowAll_EmitsALSCluster verifies that the allow-all path also
// emits the ALS cluster, so the envoy_grpc cluster_name referenced by other
// profiles' listeners resolves even on a permissive sidecar. The allow-all
// listener itself renders no access_log.
func TestAuditSink_AllowAll_EmitsALSCluster(t *testing.T) {
	audit := AuditSinkConfig{ALSUDSPath: "/tmp/a.sock", ProfileName: alsTestProfile}
	_, cds, err := GenerateAllowAllEgressRules(1, varmorconfig.DefaultProxyPort, testIPStack, audit)
	if err != nil {
		t.Fatalf("GenerateAllowAllEgressRules: %v", err)
	}
	if !strings.Contains(cds, "name: "+als.DefaultALSClusterName) {
		t.Errorf("allow-all CDS missing ALS cluster")
	}
}

// TestAuditSink_DenyAll_EmitsALSCluster mirrors the allow-all check for the
// deny-all path.
func TestAuditSink_DenyAll_EmitsALSCluster(t *testing.T) {
	audit := AuditSinkConfig{ALSUDSPath: "/tmp/d.sock", ProfileName: alsTestProfile}
	_, cds, err := GenerateDenyAllEgressRules(1, varmorconfig.DefaultProxyPort, testIPStack, audit)
	if err != nil {
		t.Fatalf("GenerateDenyAllEgressRules: %v", err)
	}
	if !strings.Contains(cds, "name: "+als.DefaultALSClusterName) {
		t.Errorf("deny-all CDS missing ALS cluster under grpc_als")
	}
}

// TestAuditSink_GRPCALS_MITMChain pins that the MITM TLS-terminating filter
// chain's HCM also routes its access_log to the gRPC ALS cluster. This is a
// regression guard: if buildMITMHCMFilter omitted the AuditSink field on its
// HTTPConnManagerConfig, the MITM chain would silently emit no gRPC ALS
// access_log. With MITM enabled there must be zero StdoutAccessLog anywhere in
// the LDS, and the decrypted-L7 entries must use HttpGrpcAccessLogConfig like
// the plaintext path.
func TestAuditSink_GRPCALS_MITMChain(t *testing.T) {
	audit := AuditSinkConfig{
		ALSUDSPath:  "/var/run/varmor/audit/als.sock",
		ProfileName: alsTestProfile,
	}
	mitm := &MITMInput{
		Domains:      []string{"httpbin.org"},
		LeafCertPath: "/etc/envoy/tls/leaf.crt",
		LeafKeyPath:  "/etc/envoy/tls/leaf.key",
	}
	lds, _ := renderALSAudit(t, mitm, audit)

	// The MITM chain must be present.
	if !strings.Contains(lds, als.FilterChainNameMITMTLSDNS) {
		t.Fatalf("expected MITM filter chain in LDS")
	}
	// No stdout sink may survive anywhere, including the MITM HCM.
	if strings.Contains(lds, "StdoutAccessLog") {
		t.Errorf("grpc_als LDS with MITM must not contain any StdoutAccessLog (MITM chain regressed to stdout)")
	}
	// The MITM HCM must emit HttpGrpcAccessLogConfig dialing the ALS cluster.
	if !strings.Contains(lds, "access_loggers.grpc.v3.HttpGrpcAccessLogConfig") {
		t.Errorf("expected HttpGrpcAccessLogConfig (L7) in MITM LDS")
	}
	if !strings.Contains(lds, "cluster_name: "+als.DefaultALSClusterName) {
		t.Errorf("expected MITM access_log to dial %s", als.DefaultALSClusterName)
	}
}

// TestAuditSink_GRPCALS_FilterChainCustomTag verifies that the gRPC ALS sink
// stamps each L7 (HCM) access_log entry with a filter_chain literal custom_tag
// naming its originating chain, and that the shared L4 listener-level access_log
// carries NO such tag (it cannot distinguish tls_chain from tcp_default_chain).
func TestAuditSink_GRPCALS_FilterChainCustomTag(t *testing.T) {
	audit := AuditSinkConfig{
		ALSUDSPath:  "/var/run/varmor/audit/als.sock",
		ProfileName: alsTestProfile,
	}
	mitm := &MITMInput{
		Domains:      []string{"httpbin.org"},
		LeafCertPath: "/etc/envoy/tls/leaf.crt",
		LeafKeyPath:  "/etc/envoy/tls/leaf.key",
	}
	lds, _ := renderALSAudit(t, mitm, audit)

	// L7 chains each get a filter_chain literal custom_tag. http_chain and
	// mitm_tls_dns_chain are both present in this fixture.
	wantTag := "- tag: " + als.ALSFilterChainTagKey
	if !strings.Contains(lds, wantTag) {
		t.Fatalf("expected filter_chain custom_tag in LDS, none found")
	}
	for _, chain := range []string{als.FilterChainNameHTTP, als.FilterChainNameMITMTLSDNS} {
		if !strings.Contains(lds, `value: "`+chain+`"`) {
			t.Errorf("expected filter_chain custom_tag value %q in LDS", chain)
		}
	}

	// The L4 listener-level access_log must NOT carry a chain tag: it is shared
	// across tls_chain and tcp_default_chain, so a static literal cannot tell
	// them apart. Assert no tag names an L4-only chain.
	for _, chain := range []string{als.FilterChainNameTLS, als.FilterChainNameTCPDefault} {
		if strings.Contains(lds, `value: "`+chain+`"`) {
			t.Errorf("L4 listener access_log must not carry a %q filter_chain tag", chain)
		}
	}
}

// TestAuditSink_ALSBufferConfig verifies that the Envoy ALS buffer bounds, when
// set on the AuditSinkConfig, are rendered into every gRPC access_log entry's
// common_config (buffer_flush_interval + buffer_size_bytes), and that an unset
// (zero-value) buffer omits both fields so Envoy applies its own defaults.
func TestAuditSink_ALSBufferConfig(t *testing.T) {
	withBuf := AuditSinkConfig{
		ALSUDSPath:             "/var/run/varmor/audit/als.sock",
		ProfileName:            alsTestProfile,
		ALSBufferFlushInterval: "1s",
		ALSBufferSizeBytes:     16384,
	}
	lds, _ := renderALSAudit(t, nil, withBuf)

	// Four access_log entries (L4 deny+shadow, L7 deny+shadow) each carry the
	// buffer bounds.
	if c := strings.Count(lds, "buffer_flush_interval: 1s"); c != 4 {
		t.Errorf("expected 4 buffer_flush_interval entries, got %d", c)
	}
	if c := strings.Count(lds, "buffer_size_bytes: 16384"); c != 4 {
		t.Errorf("expected 4 buffer_size_bytes entries, got %d", c)
	}

	// Zero-value buffer omits both fields entirely.
	noBuf := AuditSinkConfig{
		ALSUDSPath:  "/var/run/varmor/audit/als.sock",
		ProfileName: alsTestProfile,
	}
	ldsNoBuf, _ := renderALSAudit(t, nil, noBuf)
	if strings.Contains(ldsNoBuf, "buffer_flush_interval") {
		t.Errorf("unset flush interval must omit buffer_flush_interval")
	}
	if strings.Contains(ldsNoBuf, "buffer_size_bytes") {
		t.Errorf("unset buffer size must omit buffer_size_bytes")
	}
}
