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

package webhookconfig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/pkg/workload"
	"github.com/bytedance/vArmor/pkg/workload/workloadtest"
)

func testClientConfig() admissionregistrationapi.WebhookClientConfig {
	path := config.MutatingWebhookServicePath
	return admissionregistrationapi.WebhookClientConfig{
		Service: &admissionregistrationapi.ServiceReference{
			Namespace: config.Namespace,
			Name:      config.WebhookServiceName,
			Path:      &path,
		},
	}
}

func gameServerFake() workload.FakeAdapter {
	return workload.FakeAdapter{
		AdapterName: "gameserver-v1",
		AdapterGVK: schema.GroupVersionKind{
			Group: "gaming.example.com", Version: "v1", Kind: "GameServer",
		},
		AdapterGVR: schema.GroupVersionResource{
			Group: "gaming.example.com", Version: "v1", Resource: "gameservers",
		},
	}
}

// TestCustomAdapterWebhooks_NilOrEmptyReturnsNil covers the upstream build
// with no custom adapters: a nil registry yields no custom webhook entries.
// The empty-registry case is asserted separately as byte-identical output in
// TestGenerateMutatingWebhookConfig_AppendsCustomEntries.
func TestCustomAdapterWebhooks_NilOrEmptyReturnsNil(t *testing.T) {
	clientConfig := testClientConfig()
	wrc := &Register{timeoutSeconds: 10}
	assert.Nil(t, wrc.customAdapterWebhooks(clientConfig, admissionregistrationapi.IfNeededReinvocationPolicy))
}

func TestCustomAdapterWebhooks_RendersCustomEntry(t *testing.T) {
	clientConfig := testClientConfig()
	registry := workloadtest.NewRegistry(t, gameServerFake())
	wrc := &Register{registry: registry, timeoutSeconds: 10}

	entries := wrc.customAdapterWebhooks(clientConfig, admissionregistrationapi.IfNeededReinvocationPolicy)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "mutate-gameservers.gaming.example.com.varmor.org", entry.Name)
	assert.Equal(t, clientConfig, entry.ClientConfig)
	require.Len(t, entry.Rules, 1)

	rule := entry.Rules[0]
	assert.Equal(t, []admissionregistrationapi.OperationType{
		admissionregistrationapi.Create, admissionregistrationapi.Update,
	}, rule.Operations, "an adapter without explicit options defaults to CREATE+UPDATE")
	assert.Equal(t, []string{"gaming.example.com"}, rule.APIGroups)
	assert.Equal(t, []string{"v1"}, rule.APIVersions)
	assert.Equal(t, []string{"gameservers"}, rule.Resources)

	// Every custom entry stays fail-open and inherits the shared admission
	// settings of the built-in entries.
	require.NotNil(t, entry.FailurePolicy)
	assert.Equal(t, admissionregistrationapi.Ignore, *entry.FailurePolicy)
	require.NotNil(t, entry.SideEffects)
	assert.Equal(t, admissionregistrationapi.SideEffectClassNoneOnDryRun, *entry.SideEffects)
	require.NotNil(t, entry.TimeoutSeconds)
	assert.Equal(t, int32(10), *entry.TimeoutSeconds)
	assert.Equal(t, []string{"v1"}, entry.AdmissionReviewVersions)
	require.NotNil(t, entry.ReinvocationPolicy)
	assert.Equal(t, admissionregistrationapi.IfNeededReinvocationPolicy, *entry.ReinvocationPolicy)
	assert.Equal(t, &metav1.LabelSelector{MatchLabels: config.WebhookSelectorLabel}, entry.ObjectSelector)
	assert.Nil(t, entry.MatchConditions)
}

func TestCustomAdapterWebhooks_CustomOptionsAndMatchConditions(t *testing.T) {
	fake := workload.FakeAdapter{
		AdapterName: "widget-v1",
		AdapterGVK:  schema.GroupVersionKind{Group: "widgets.example.com", Version: "v1", Kind: "Widget"},
		AdapterGVR:  schema.GroupVersionResource{Group: "widgets.example.com", Version: "v1", Resource: "widgets"},
		Options: workload.WebhookOptions{
			Operations: []admissionregistrationapi.OperationType{admissionregistrationapi.Create},
			MatchConditions: []admissionregistrationapi.MatchCondition{
				{Name: "exclude-lease-objects", Expression: "!has(object.metadata.labels['lease'])"},
			},
		},
	}
	registry := workloadtest.NewRegistry(t, fake)
	wrc := &Register{registry: registry, timeoutSeconds: 5}

	entries := wrc.customAdapterWebhooks(testClientConfig(), admissionregistrationapi.NeverReinvocationPolicy)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "mutate-widgets.widgets.example.com.varmor.org", entry.Name)
	require.Len(t, entry.Rules, 1)
	assert.Equal(t, []admissionregistrationapi.OperationType{admissionregistrationapi.Create}, entry.Rules[0].Operations)
	assert.Equal(t, []string{"widgets.example.com"}, entry.Rules[0].APIGroups)
	assert.Equal(t, fake.Options.MatchConditions, entry.MatchConditions)
}

func TestCustomAdapterWebhooks_MultiVersionMergesOneEntry(t *testing.T) {
	v1 := workload.FakeAdapter{
		AdapterName: "widget-v1",
		AdapterGVK:  schema.GroupVersionKind{Group: "widgets.example.com", Version: "v1", Kind: "Widget"},
		AdapterGVR:  schema.GroupVersionResource{Group: "widgets.example.com", Version: "v1", Resource: "widgets"},
	}
	v2 := workload.FakeAdapter{
		AdapterName: "widget-v2",
		AdapterGVK:  schema.GroupVersionKind{Group: "widgets.example.com", Version: "v2", Kind: "Widget"},
		AdapterGVR:  schema.GroupVersionResource{Group: "widgets.example.com", Version: "v2", Resource: "widgets"},
	}
	registry := workloadtest.NewRegistry(t, v1, v2)
	wrc := &Register{registry: registry, timeoutSeconds: 10}

	entries := wrc.customAdapterWebhooks(testClientConfig(), admissionregistrationapi.IfNeededReinvocationPolicy)
	require.Len(t, entries, 1, "versions of one Kind share one entry instead of colliding names")

	entry := entries[0]
	assert.Equal(t, "mutate-widgets.widgets.example.com.varmor.org", entry.Name)
	require.Len(t, entry.Rules, 2)

	versions := []string{entry.Rules[0].APIVersions[0], entry.Rules[1].APIVersions[0]}
	assert.ElementsMatch(t, []string{"v1", "v2"}, versions)
	for _, rule := range entry.Rules {
		assert.Equal(t, []string{"widgets.example.com"}, rule.APIGroups)
		assert.Equal(t, []string{"widgets"}, rule.Resources)
	}
}

func TestCustomAdapterWebhooks_OverLongIdentityTruncated(t *testing.T) {
	// Max-length resource plus a 253-char group overflows the raw entry
	// name; the rendered entry is truncated, not rejected. The zero-value
	// logger exercises the warning path.
	resource := strings.Repeat("a", 63)
	group := strings.Repeat("b.", 126) + "b"
	fake := workload.FakeAdapter{
		AdapterName: "long-v1",
		AdapterGVK:  schema.GroupVersionKind{Group: group, Version: "v1", Kind: "Long"},
		AdapterGVR:  schema.GroupVersionResource{Group: group, Version: "v1", Resource: resource},
	}
	registry := workloadtest.NewRegistry(t, fake)
	wrc := &Register{registry: registry, timeoutSeconds: 10}

	entries := wrc.customAdapterWebhooks(testClientConfig(), admissionregistrationapi.IfNeededReinvocationPolicy)
	require.Len(t, entries, 1)

	name := entries[0].Name
	assert.LessOrEqual(t, len(name), validation.DNS1123SubdomainMaxLength)
	assert.Empty(t, validation.IsDNS1123Subdomain(name), "truncated entry name must pass the API server's own validator")
	assert.Empty(t, validation.IsFullyQualifiedName(field.NewPath("webhooks").Index(0).Child("name"), name),
		"truncated entry name must keep at least three dot-separated segments so the API server accepts the MutatingWebhookConfiguration")
	assert.True(t, strings.HasPrefix(name, "mutate-"), "truncated names retain the fixed mutate- prefix: %q", name)
	assert.True(t, strings.HasSuffix(name, ".varmor.org"), "truncated names retain the fixed .varmor.org suffix around the hash: %q", name)
	wantName, _ := workload.WebhookEntryName(fake)
	assert.Equal(t, wantName, name, "the shared helper and the renderer must agree")
}

func TestGenerateMutatingWebhookConfig_AppendsCustomEntries(t *testing.T) {
	clientConfig := testClientConfig()

	t.Run("empty custom registry stays byte-identical to a nil registry", func(t *testing.T) {
		withRegistry := &Register{registry: workloadtest.NewRegistry(t), timeoutSeconds: 10}
		withoutRegistry := &Register{timeoutSeconds: 10}

		got := withRegistry.generateMutatingWebhookConfig(
			config.MutatingWebhookConfigurationName, clientConfig, admissionregistrationapi.IfNeededReinvocationPolicy)
		want := withoutRegistry.generateMutatingWebhookConfig(
			config.MutatingWebhookConfigurationName, clientConfig, admissionregistrationapi.IfNeededReinvocationPolicy)

		require.Len(t, got.Webhooks, 2)
		assert.Equal(t, config.MutatingWorkloadWebhookName, got.Webhooks[0].Name)
		assert.Equal(t, config.MutatingPodWebhookName, got.Webhooks[1].Name)
		assert.Equal(t, want, got)
	})

	t.Run("custom adapters append after the built-in entries", func(t *testing.T) {
		wrc := &Register{registry: workloadtest.NewRegistry(t, gameServerFake()), timeoutSeconds: 10}
		cfg := wrc.generateMutatingWebhookConfig(
			config.MutatingWebhookConfigurationName, clientConfig, admissionregistrationapi.IfNeededReinvocationPolicy)

		require.Len(t, cfg.Webhooks, 3)
		assert.Equal(t, config.MutatingWorkloadWebhookName, cfg.Webhooks[0].Name)
		assert.Equal(t, config.MutatingPodWebhookName, cfg.Webhooks[1].Name)
		assert.Equal(t, "mutate-gameservers.gaming.example.com.varmor.org", cfg.Webhooks[2].Name)
		assert.Equal(t, config.MutatingWebhookConfigurationName, cfg.Name)
	})
}
