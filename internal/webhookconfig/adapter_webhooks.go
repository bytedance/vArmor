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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/go-logr/logr"
	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/pkg/workload"
)

func newAdapterDefaults(registry *workload.Registry, log logr.Logger) map[string]workload.WebhookOptions {
	defaults := make(map[string]workload.WebhookOptions)
	for _, a := range registry.List() {
		defaults[a.Name()] = config.WorkloadAdapterDefaults(a, log)
	}
	return defaults
}

// adapterWebhookName returns the deterministic webhook entry name for a custom
// adapter: mutate-<resource>.<group>.varmor.org.
func adapterWebhookName(a workload.Adapter) string {
	group := a.GVK().Group
	if group == "" {
		group = "core"
	}
	return fmt.Sprintf("mutate-%s.%s.varmor.org", a.GVR().Resource, group)
}

// adapterWebhookRule builds the admission Rule from the adapter's GVK/GVR. It
// targets the main resource only (never the status subresource) and lists the
// adapter's served version.
func adapterWebhookRule(a workload.Adapter) admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		APIGroups:   []string{a.GVK().Group},
		APIVersions: []string{a.GVK().Version},
		Resources:   []string{a.GVR().Resource},
	}
}

// customAdapterWebhooks groups the enabled custom adapters visible to this
// registry using the caller-supplied dynamic-config snapshot. It returns nil
// when the registry contains no custom adapters (the upstream default),
// leaving the generated configuration byte-identical to the historical
// two-entry form.
func (wrc *Register) customAdapterWebhooks(
	snapshot config.DynamicConfig,
	clientConfig admissionregistrationapi.WebhookClientConfig,
	reinvocationPolicy admissionregistrationapi.ReinvocationPolicyType,
) []admissionregistrationapi.MutatingWebhook {
	var webhooks []admissionregistrationapi.MutatingWebhook
	groups := make(map[string]int)

	// The registry holds only enabled adapters, so every listed custom
	// adapter contributes rules; adapters with identical webhook options are
	// coalesced into a shared entry below.
	for _, a := range wrc.registry.List() {
		if workload.IsBuiltin(a.GVK().GroupKind()) {
			continue
		}

		opts := config.ResolveWorkloadAdapterOptions(snapshot, a, wrc.adapterDefaults[a.Name()], wrc.timeoutSeconds)
		operations := append([]admissionregistrationapi.OperationType(nil), opts.Operations...)
		failurePolicy := opts.FailurePolicy
		timeout := opts.TimeoutSeconds

		selector := metav1.LabelSelector{MatchLabels: config.WebhookSelectorLabel}
		sideEffect := admissionregistrationapi.SideEffectClassNoneOnDryRun

		entry := admissionregistrationapi.MutatingWebhook{
			Name:         adapterWebhookName(a),
			ClientConfig: clientConfig,
			Rules: []admissionregistrationapi.RuleWithOperations{
				{
					Operations: operations,
					Rule:       adapterWebhookRule(a),
				},
			},
			FailurePolicy:           &failurePolicy,
			ObjectSelector:          &selector,
			SideEffects:             &sideEffect,
			TimeoutSeconds:          &timeout,
			AdmissionReviewVersions: []string{"v1"},
			ReinvocationPolicy:      &reinvocationPolicy,
			MatchConditions:         opts.MatchConditions,
		}
		// Resource identities belong in rules, not in the grouping key.
		// Sorted operations/conditions make equivalent option sets deterministic.
		sort.Slice(entry.Rules[0].Operations, func(i, j int) bool { return entry.Rules[0].Operations[i] < entry.Rules[0].Operations[j] })
		entry.MatchConditions = append([]admissionregistrationapi.MatchCondition(nil), entry.MatchConditions...)
		sort.Slice(entry.MatchConditions, func(i, j int) bool { return entry.MatchConditions[i].Name < entry.MatchConditions[j].Name })
		keyBytes, err := json.Marshal(struct {
			Policy     admissionregistrationapi.FailurePolicyType
			Timeout    int32
			Conditions []admissionregistrationapi.MatchCondition
			Operations []admissionregistrationapi.OperationType
			Selector   metav1.LabelSelector
		}{failurePolicy, timeout, entry.MatchConditions, entry.Rules[0].Operations, selector})
		if err != nil {
			wrc.log.Error(err, "failed to group adapter webhook", "adapter", a.Name())
			continue
		}
		key := string(keyBytes)
		if index, ok := groups[key]; ok {
			webhooks[index].Rules = append(webhooks[index].Rules, entry.Rules...)
		} else {
			groups[key] = len(webhooks)
			webhooks = append(webhooks, entry)
		}
	}

	return webhooks
}
