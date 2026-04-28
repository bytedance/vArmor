// Copyright 2025 vArmor Authors
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

package webhooks

import (
	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorpolicy "github.com/bytedance/vArmor/internal/policy"
)

func (ws *WebhookServer) validatePolicy(request *admissionv1.AdmissionRequest, new, old interface{}, logger logr.Logger) *admissionv1.AdmissionResponse {
	switch request.Kind.Kind {
	case "VarmorClusterPolicy":
		switch request.Operation {
		case admissionv1.Create:
			logger.V(2).Info("policy validating", "new", new)

			valid, message := varmorpolicy.ValidateAddPolicy(new, ws.enableBehaviorModeling)
			if !valid {
				return failureResponse(request.UID, message)
			}

		case admissionv1.Update:
			logger.V(2).Info("policy validating", "new", new, "old", old)

			oldClusterPolicy := old.(*varmor.VarmorClusterPolicy)
			oldClusterProxyConfig := oldClusterPolicy.Spec.Policy.NetworkProxyConfig
			if oldClusterProxyConfig == nil {
				oldClusterProxyConfig = &varmor.NetworkProxyConfig{}
			}
			valid, message := varmorpolicy.ValidateUpdatePolicy(
				new,
				oldClusterPolicy.Spec.Policy.Enforcer,
				oldClusterPolicy.Spec.Target,
				oldClusterProxyConfig,
			)
			if !valid {
				return failureResponse(request.UID, message)
			}
		}
	case "VarmorPolicy":
		switch request.Operation {
		case admissionv1.Create:
			logger.V(2).Info("policy validating", "new", new)

			valid, message := varmorpolicy.ValidateAddPolicy(new, ws.enableBehaviorModeling)
			if !valid {
				return failureResponse(request.UID, message)
			}

		case admissionv1.Update:
			logger.V(2).Info("policy validating", "new", new, "old", old)

			oldPolicy := old.(*varmor.VarmorPolicy)
			oldProxyConfig := oldPolicy.Spec.Policy.NetworkProxyConfig
			if oldProxyConfig == nil {
				oldProxyConfig = &varmor.NetworkProxyConfig{}
			}
			valid, message := varmorpolicy.ValidateUpdatePolicy(
				new,
				oldPolicy.Spec.Policy.Enforcer,
				oldPolicy.Spec.Target,
				oldProxyConfig,
			)
			if !valid {
				return failureResponse(request.UID, message)
			}
		}
	}

	return successResponse(request.UID, nil)
}
