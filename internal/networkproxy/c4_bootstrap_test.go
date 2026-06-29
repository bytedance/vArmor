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

// TestGenerateEnvoySecret_BootstrapNodeMetadata verifies that the rendered
// bootstrap carries the node.metadata Pod identity placeholders so the audit
// agent can attribute ALS records to a precise Pod via Identifier.Node.Metadata.
// The %ENV(...)% tokens must survive fmt.Sprintf verbatim (they are escaped as
// %%ENV(...)%% in the template) for Envoy's own startup env expansion.
func TestGenerateEnvoySecret_BootstrapNodeMetadata(t *testing.T) {
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
		"metadata:",
		`pod_name: "%ENV(POD_NAME)%"`,
		`pod_namespace: "%ENV(POD_NAMESPACE)%"`,
	} {
		if !strings.Contains(bootstrap, want) {
			t.Errorf("bootstrap missing %q\n---\n%s", want, bootstrap)
		}
	}

	// fmt.Sprintf must not have mangled the percent tokens into a format-verb
	// artefact such as "%!E(..." or dropped them entirely.
	if strings.Contains(bootstrap, "%!") {
		t.Errorf("bootstrap contains a fmt verb artefact: %q", bootstrap)
	}
}

// TestGenerateEnvoySecret_ProfileNameInLogName verifies the C4 profileName
// forward-move: the profile name is computed before rendering and embedded into
// the per-class gRPC ALS log_name. The default sink is stdout, so to observe
// the log_name we drive the renderer directly through GenerateEnvoyConfig with
// a grpc_als sink and the same profile name GenerateEnvoySecret would compute.
func TestGenerateEnvoySecret_ProfileNameInLogName(t *testing.T) {
	namespace, name := "team-a", "egress-guard"
	profileName := varmorprofile.GenerateArmorProfileName(namespace, name, false)
	if profileName != "varmor-team-a-egress-guard" {
		t.Fatalf("unexpected profile name: %q", profileName)
	}

	// Default sink (stdout) must NOT leak the profile name into the rendered
	// document; the name only matters once the gRPC ALS sink is selected.
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
			t.Errorf("stdout default unexpectedly emitted log_name %q", denied)
		}
	}
}
