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
	"fmt"

	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/pkg/workload"
)

// adapterWebhookName returns the deterministic MutatingWebhook entry name for
// a custom adapter: mutate-<resource>.<group>.varmor.org. The core API group
// renders as "core" because an empty group segment would produce an invalid
// DNS-style name. Adapters serving different versions of one Kind share the
// same group and REST resource, therefore the same entry name; their rules
// are merged by customAdapterWebhooks.
func adapterWebhookName(a workload.Adapter) string {
	group := a.GVK().Group
	if group == "" {
		group = "core"
	}
	return fmt.Sprintf("mutate-%s.%s.varmor.org", a.GVR().Resource, group)
}

// adapterWebhookRule renders the admission Rule for one served adapter
// version from its GVK/GVR identity. It targets the main resource only,
// never the status subresource.
func adapterWebhookRule(a workload.Adapter) admissionregistrationapi.Rule {
	return admissionregistrationapi.Rule{
		APIGroups:   []string{a.GVK().Group},
		APIVersions: []string{a.GVK().Version},
		Resources:   []string{a.GVR().Resource},
	}
}

// adapterOperations resolves the admission operations an adapter subscribes
// to. An adapter that declares no operations defaults to CREATE+UPDATE, the
// same operation set as the built-in workload webhook entry.
func adapterOperations(a workload.Adapter) []admissionregistrationapi.OperationType {
	ops := a.DefaultWebhookOptions().Operations
	if len(ops) == 0 {
		return []admissionregistrationapi.OperationType{
			admissionregistrationapi.Create,
			admissionregistrationapi.Update,
		}
	}
	return append([]admissionregistrationapi.OperationType(nil), ops...)
}

// customAdapterWebhooks renders one MutatingWebhook entry per registered
// custom adapter, extending the historical two-entry configuration with the
// same service, /mutate route, selector and fail-open Ignore policy.
// Adapters of one Kind sharing an entry name (multi-version) are merged into
// one entry; a nil or empty registry returns nil to preserve the historical
// two-entry form.
func (wrc *Register) customAdapterWebhooks(
	clientConfig admissionregistrationapi.WebhookClientConfig,
	reinvocationPolicy admissionregistrationapi.ReinvocationPolicyType,
) []admissionregistrationapi.MutatingWebhook {
	if wrc.registry == nil {
		return nil
	}

	failurePolicy := admissionregistrationapi.Ignore
	selector := metav1.LabelSelector{MatchLabels: config.WebhookSelectorLabel}
	sideEffect := admissionregistrationapi.SideEffectClassNoneOnDryRun
	timeout := wrc.timeoutSeconds

	// entryOrder preserves first-seen ordering while the map merges adapters
	// that map to the same entry name (the multi-version single-Kind case).
	var entryOrder []string
	entries := make(map[string]*admissionregistrationapi.MutatingWebhook)

	for _, a := range wrc.registry.List() {
		name := adapterWebhookName(a)
		rule := admissionregistrationapi.RuleWithOperations{
			Operations: adapterOperations(a),
			Rule:       adapterWebhookRule(a),
		}

		if entry, ok := entries[name]; ok {
			entry.Rules = append(entry.Rules, rule)
			continue
		}

		entries[name] = &admissionregistrationapi.MutatingWebhook{
			Name:                    name,
			ClientConfig:            clientConfig,
			Rules:                   []admissionregistrationapi.RuleWithOperations{rule},
			FailurePolicy:           &failurePolicy,
			ObjectSelector:          &selector,
			SideEffects:             &sideEffect,
			TimeoutSeconds:          &timeout,
			AdmissionReviewVersions: []string{"v1"},
			ReinvocationPolicy:      &reinvocationPolicy,
			MatchConditions:         a.DefaultWebhookOptions().MatchConditions,
		}
		entryOrder = append(entryOrder, name)
	}

	if len(entryOrder) == 0 {
		return nil
	}

	webhooks := make([]admissionregistrationapi.MutatingWebhook, 0, len(entryOrder))
	for _, name := range entryOrder {
		webhooks = append(webhooks, *entries[name])
	}
	return webhooks
}
