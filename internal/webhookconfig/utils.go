// Copyright 2023 vArmor Authors
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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bytedance/vArmor/internal/config"
	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
)

// getResourceMutatingWebhookConfigName returns the webhook configuration name.
func getResourceMutatingWebhookConfigName(debug bool) string {
	if debug {
		return config.MutatingWebhookConfigurationDebugName
	}
	return config.MutatingWebhookConfigurationName
}

// debug mutating webhook
func generateDebugMutatingWebhook(
	name,
	url string,
	caData []byte,
	timeoutSeconds int32,
	rule admissionregistrationapi.Rule,
	operationTypes []admissionregistrationapi.OperationType,
	failurePolicy admissionregistrationapi.FailurePolicyType,
) admissionregistrationapi.MutatingWebhook {

	sideEffect := admissionregistrationapi.SideEffectClassNoneOnDryRun
	reinvocationPolicy := admissionregistrationapi.NeverReinvocationPolicy
	selector := metav1.LabelSelector{
		MatchLabels: config.WebhookSelectorLabel,
	}

	w := admissionregistrationapi.MutatingWebhook{
		ReinvocationPolicy: &reinvocationPolicy,
		Name:               name,
		ClientConfig: admissionregistrationapi.WebhookClientConfig{
			URL:      &url,
			CABundle: caData,
		},
		ObjectSelector:          &selector,
		SideEffects:             &sideEffect,
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          &timeoutSeconds,
		FailurePolicy:           &failurePolicy,
	}

	if !reflect.DeepEqual(rule, admissionregistrationapi.Rule{}) {
		w.Rules = []admissionregistrationapi.RuleWithOperations{
			{
				Operations: operationTypes,
				Rule:       rule,
			},
		}
	}

	return w
}

// mutating webhook
func generateMutatingWebhook(
	name,
	servicePath string,
	caData []byte,
	timeoutSeconds int32,
	rule admissionregistrationapi.Rule,
	operationTypes []admissionregistrationapi.OperationType,
	failurePolicy admissionregistrationapi.FailurePolicyType,
) admissionregistrationapi.MutatingWebhook {

	sideEffect := admissionregistrationapi.SideEffectClassNoneOnDryRun
	reinvocationPolicy := admissionregistrationapi.IfNeededReinvocationPolicy
	selector := metav1.LabelSelector{
		MatchLabels: config.WebhookSelectorLabel,
	}

	w := admissionregistrationapi.MutatingWebhook{
		ReinvocationPolicy: &reinvocationPolicy,
		Name:               name,
		ClientConfig: admissionregistrationapi.WebhookClientConfig{
			Service: &admissionregistrationapi.ServiceReference{
				Namespace: config.Namespace,
				Name:      config.WebhookServiceName,
				Path:      &servicePath,
			},
			CABundle: caData,
		},
		ObjectSelector:          &selector,
		SideEffects:             &sideEffect,
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          &timeoutSeconds,
		FailurePolicy:           &failurePolicy,
	}

	if !reflect.DeepEqual(rule, admissionregistrationapi.Rule{}) {
		w.Rules = []admissionregistrationapi.RuleWithOperations{
			{
				Operations: operationTypes,
				Rule:       rule,
			},
		}
	}
	return w
}
