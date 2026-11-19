// Copyright 2026 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/bytedance/vArmor/pkg/workload"
)

// validateMatchConditions checks the structure of match conditions. CEL
// expression semantics are validated by the API server when the
// MutatingWebhookConfiguration is applied, so we only enforce the shape that
// the API server requires and that we can check cheaply.
func validateMatchConditions(conditions []admissionv1.MatchCondition) error {
	if len(conditions) == 0 {
		return nil
	}
	if len(conditions) > 64 {
		return fmt.Errorf("at most 64 match conditions are allowed")
	}
	names := make(map[string]bool)
	for _, condition := range conditions {
		if len(validation.IsQualifiedName(condition.Name)) != 0 || names[condition.Name] {
			return fmt.Errorf("invalid or duplicate condition name %q", condition.Name)
		}
		names[condition.Name] = true
		if strings.TrimSpace(condition.Expression) == "" {
			return fmt.Errorf("empty expression for %q", condition.Name)
		}
	}
	return nil
}

func sanitizeAdapterConfig(entry WorkloadAdapterConfig, name string, log logr.Logger) WorkloadAdapterConfig {
	warn := func(field string) {
		log.Info("WARNING: ignoring invalid workload adapter option; using default", "adapter", name, "field", field)
	}
	if entry.FailurePolicy != nil && *entry.FailurePolicy != admissionv1.Ignore && *entry.FailurePolicy != admissionv1.Fail {
		warn("failurePolicy")
		entry.FailurePolicy = nil
	}
	if err := validateMatchConditions(entry.MatchConditions); err != nil {
		log.Info("WARNING: ignoring invalid workload adapter option; using default", "adapter", name, "field", "matchConditions", "error", err)
		entry.MatchConditions = nil
	}
	return entry
}

// WorkloadAdapterDefaults validates compiled defaults once when the webhook
// register is constructed. Overrides are validated when configuration loads.
func WorkloadAdapterDefaults(a workload.Adapter, log logr.Logger) workload.WebhookOptions {
	opts := a.DefaultWebhookOptions()
	if opts.FailurePolicy == "" {
		opts.FailurePolicy = admissionv1.Ignore
	}
	defaults := sanitizeAdapterConfig(WorkloadAdapterConfig{
		FailurePolicy: &opts.FailurePolicy, TimeoutSeconds: &opts.TimeoutSeconds,
		MatchConditions: opts.MatchConditions,
	}, a.Name(), log)
	if defaults.FailurePolicy == nil {
		opts.FailurePolicy = admissionv1.Ignore
	}
	if defaults.TimeoutSeconds == nil {
		opts.TimeoutSeconds = 0
	}
	opts.MatchConditions = defaults.MatchConditions
	if len(opts.Operations) == 0 {
		opts.Operations = []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}
	}
	return opts
}

// ResolveWorkloadAdapterOptions merges validated defaults and overrides from
// one snapshot. An explicit empty condition list clears the adapter defaults.
func ResolveWorkloadAdapterOptions(cfg DynamicConfig, a workload.Adapter, opts workload.WebhookOptions, globalTimeout int32) workload.WebhookOptions {
	entry := cfg.WorkloadAdapters[configKeyFor(a)]
	if entry.FailurePolicy != nil {
		opts.FailurePolicy = *entry.FailurePolicy
	}
	if entry.TimeoutSeconds != nil {
		opts.TimeoutSeconds = *entry.TimeoutSeconds
	}
	if entry.MatchConditions != nil {
		opts.MatchConditions = entry.MatchConditions
	}
	if opts.TimeoutSeconds == 0 {
		opts.TimeoutSeconds = globalTimeout
	}
	return opts
}
