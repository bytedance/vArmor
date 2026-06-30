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
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/networkproxy/profile"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
)

// newNetworkProxyPolicy builds a minimal namespace-scoped AlwaysAllow
// NetworkProxy policy. AlwaysAllow renders an allow-all listener that needs
// neither MITM material nor any apiserver lookup, so GenerateEnvoySecret can
// run with a nil clientset (ResolveMITMInput short-circuits to nil,nil and the
// MITM material branch is skipped because NetworkProxyConfig.MITM is nil).
func newNetworkProxyPolicy(namespace, name string) *varmor.VarmorPolicy {
	return &varmor.VarmorPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: varmor.VarmorPolicySpec{
			Target: varmor.Target{Kind: "Deployment", Name: "demo"},
			Policy: varmor.Policy{
				Enforcer: "NetworkProxy",
				Mode:     varmor.AlwaysAllowMode,
			},
		},
	}
}

// TestGenerateEnvoySecret_BootstrapNode verifies that the rendered bootstrap
// carries the node id/cluster but does NOT embed the Pod identity in
// node.metadata. The Pod identity is supplied at startup through the sidecar's
// Envoy "--config-yaml" overlay (kubelet-expanded Downward API env vars), not
// through the bootstrap document, because Envoy does not expand "%ENV()%"
// inside node.metadata. This guards against a regression to the old approach
// where literal "%ENV(POD_NAME)%" tokens leaked through to the audit agent.
func TestGenerateEnvoySecret_BootstrapNode(t *testing.T) {
	vp := newNetworkProxyPolicy("team-a", "egress-guard")

	secret, err := GenerateEnvoySecret(nil, vp, "team-a", false)
	if err != nil {
		t.Fatalf("GenerateEnvoySecret: %v", err)
	}
	if secret == nil {
		t.Fatal("expected a non-nil secret for an AlwaysAllow NetworkProxy policy")
	}

	bootstrap := secret.StringData[SecretKeyBootstrap]
	if bootstrap == "" {
		t.Fatalf("bootstrap document is empty")
	}

	for _, want := range []string{
		"id: varmor-network-proxy",
		"cluster: varmor-network-proxy",
	} {
		if !strings.Contains(bootstrap, want) {
			t.Errorf("bootstrap missing %q\n---\n%s", want, bootstrap)
		}
	}

	// The Pod identity must NOT be embedded in the bootstrap node.metadata: the
	// "%ENV()%" tokens are never expanded there, so their presence would mean
	// the agent receives literal placeholders instead of real values.
	for _, unwanted := range []string{
		"%ENV(",
		"pod_name:",
		"pod_namespace:",
		"pod_uid:",
	} {
		if strings.Contains(bootstrap, unwanted) {
			t.Errorf("bootstrap must not contain %q (Pod identity comes from the --config-yaml overlay)\n---\n%s", unwanted, bootstrap)
		}
	}

	// fmt.Sprintf must not have produced a format-verb artefact.
	if strings.Contains(bootstrap, "%!") {
		t.Errorf("bootstrap contains a fmt verb artefact: %q", bootstrap)
	}
}

// TestGenerateEnvoySecret_AllowAllNoALSLogName verifies that an AlwaysAllow
// policy renders an allow-all listener with no deny/audit ALS access_log
// entries, so no per-class gRPC ALS log_name leaks into the LDS. The profile
// name is still computed before rendering (the C4 forward-move) and only
// surfaces in log_name once deny/audit rules generate ALS access_log entries.
func TestGenerateEnvoySecret_AllowAllNoALSLogName(t *testing.T) {
	namespace, name := "team-a", "egress-guard"
	profileName := varmorprofile.GenerateArmorProfileName(namespace, name, false)
	if profileName != "varmor-team-a-egress-guard" {
		t.Fatalf("unexpected profile name: %q", profileName)
	}

	// An allow-all listener emits no deny/audit ALS access_log, so the
	// per-class log_name must NOT appear in the rendered document.
	vp := newNetworkProxyPolicy(namespace, name)
	secret, err := GenerateEnvoySecret(nil, vp, namespace, false)
	if err != nil {
		t.Fatalf("GenerateEnvoySecret: %v", err)
	}
	lds := secret.StringData[SecretKeyLDS]
	for _, denied := range []string{
		fmt.Sprintf("%s:%s", profile.LogNameClassDeny, profileName),
		fmt.Sprintf("%s:%s", profile.LogNameClassAudit, profileName),
	} {
		if strings.Contains(lds, denied) {
			t.Errorf("allow-all listener unexpectedly emitted log_name %q", denied)
		}
	}
}

// TestAuditSinkConfig_ConfigDriven verifies that auditSinkConfig derives the
// renderer's UDS path and buffer bounds from the installation-wide config and
// preserves the per-profile name. NetworkProxy violations always stream over
// gRPC ALS, so the UDS path is always populated.
func TestAuditSinkConfig_ConfigDriven(t *testing.T) {
	origFlush := varmorconfig.AuditNetworkProxyALSBufferFlushInterval
	origSize := varmorconfig.AuditNetworkProxyALSBufferSizeBytes
	defer func() {
		varmorconfig.AuditNetworkProxyALSBufferFlushInterval = origFlush
		varmorconfig.AuditNetworkProxyALSBufferSizeBytes = origSize
	}()

	// UDS path + buffer bounds are populated from config.
	varmorconfig.AuditNetworkProxyALSBufferFlushInterval = "1s"
	varmorconfig.AuditNetworkProxyALSBufferSizeBytes = 16384
	got := auditSinkConfig("varmor-team-a-x")
	if got.ALSUDSPath != varmorconfig.AuditNetworkProxySocketPath {
		t.Errorf("expected UDS path %q, got %q", varmorconfig.AuditNetworkProxySocketPath, got.ALSUDSPath)
	}
	if got.ALSBufferFlushInterval != "1s" || got.ALSBufferSizeBytes != 16384 {
		t.Errorf("buffer bounds not threaded: %+v", got)
	}
	if got.ProfileName != "varmor-team-a-x" {
		t.Errorf("profile name not preserved: %q", got.ProfileName)
	}
}
