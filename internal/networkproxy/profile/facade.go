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

// Package profile implements Envoy proxy configuration rendering and
// translation for the vArmor network proxy enforcer.
package profile

// This file is the public entry point of the profile package. It exposes
// a mode-aware facade on top of TranslateEgressRules so that callers
// (primarily the Kubernetes-facing orchestrator in the parent
// internal/networkproxy package) can render LDS/CDS without having to
// reason about AlwaysAllow / RuntimeDefault / EnhanceProtect /
// DefenseInDepth branch logic themselves.
//
// Kept intentionally side-effect-free: no client-go, no time/file I/O.
// The Secret plumbing lives one level up so this package can be unit-tested
// with pure inputs.

import (
	"fmt"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

// GenerateEnvoyConfig renders the Envoy LDS/CDS for the supplied policy.
//
// The mitm parameter is optional: when nil (or MITMInput.Enabled() is
// false) the result is identical to the pre-MITM behaviour. When non-nil,
// its Domains / HeadersByDomain / leaf paths flow through to
// TranslateEgressRules so the emitted listener carries the MITM
// filter chains and per-:authority request_headers_to_add.
//
// MITM is ONLY consulted for Egress paths that can actually render MITM
// chains (EnhanceProtect/DefenseInDepth with concrete egress rules).
// Allow-all and deny-all short-circuits ignore mitm by construction.
func GenerateEnvoyConfig(policy varmor.Policy, version int64, mitm *MITMInput, ipStack IPStackConfig) (lds string, cds string, err error) {
	e := varmortypes.GetEnforcerType(policy.Enforcer)

	if e == varmortypes.Unknown {
		return "", "", fmt.Errorf("unknown enforcer")
	}

	// No need to generate envoy config if the NetworkProxy enforcer is not declared
	if (e & varmortypes.NetworkProxy) == 0 {
		return "", "", nil
	}

	// Get the proxy port from the policy. Default is 15001.
	proxyPort := varmorconfig.DefaultProxyPort
	if policy.NetworkProxyConfig != nil && policy.NetworkProxyConfig.ProxyPort != nil {
		proxyPort = *policy.NetworkProxyConfig.ProxyPort
	}

	switch policy.Mode {
	case varmor.AlwaysAllowMode:
		return GenerateAllowAllEgressRules(version, proxyPort, ipStack)
	case varmor.RuntimeDefaultMode:
		return GenerateAllowAllEgressRules(version, proxyPort, ipStack)
	case varmor.EnhanceProtectMode:
		if policy.EnhanceProtect == nil {
			return "", "", fmt.Errorf("the policy.enhanceProtect field cannot be nil")
		}

		if policy.EnhanceProtect.NetworkProxyRawRules != nil && policy.EnhanceProtect.NetworkProxyRawRules.Egress != nil {
			return GenerateNetworkProxyEgressRules(policy.EnhanceProtect.NetworkProxyRawRules.Egress, version, proxyPort, mitm, ipStack)
		} else {
			return GenerateAllowAllEgressRules(version, proxyPort, ipStack)
		}

	case varmor.BehaviorModelingMode:
		return "", "", fmt.Errorf("not supported by the NetworkProxy enforcer for now")
	case varmor.DefenseInDepthMode:
		if policy.DefenseInDepth == nil {
			return "", "", fmt.Errorf("the policy.defenseInDepth field cannot be nil")
		}

		if policy.DefenseInDepth.NetworkProxy != nil && policy.DefenseInDepth.NetworkProxy.Egress != nil {
			return GenerateNetworkProxyEgressRules(policy.DefenseInDepth.NetworkProxy.Egress, version, proxyPort, mitm, ipStack)
		} else {
			return GenerateDenyAllEgressRules(version, proxyPort, ipStack)
		}
	}

	return "", "", nil
}

// GenerateAllowAllEgressRules emits an Envoy configuration that forwards
// every connection straight through without policy checks, used for the
// AlwaysAllow and RuntimeDefault modes.
func GenerateAllowAllEgressRules(version int64, proxyPort uint16, ipStack IPStackConfig) (string, string, error) {
	return renderAllowAllListenerYAML(version, proxyPort, ipStack), renderClustersYAML(version, false), nil
}

// GenerateDenyAllEgressRules emits an Envoy configuration that rejects
// every connection, used when DefenseInDepth is enabled but no egress
// rules have been supplied yet.
func GenerateDenyAllEgressRules(version int64, proxyPort uint16, ipStack IPStackConfig) (string, string, error) {
	return renderDenyAllListenerYAML(version, proxyPort, ipStack), renderClustersYAML(version, false), nil
}

// GenerateNetworkProxyEgressRules renders LDS+CDS from an Egress plus an
// optional MITMInput. When mitm is nil/disabled the output is identical
// to the pre-MITM implementation, so all pre-existing callers and tests
// remain behaviorally unchanged.
func GenerateNetworkProxyEgressRules(egress *varmor.NetworkProxyEgress, version int64, proxyPort uint16, mitm *MITMInput, ipStack IPStackConfig) (string, string, error) {
	result, err := TranslateEgressRules(egress, version, proxyPort, mitm, ipStack)
	if err != nil {
		return "", "", err
	}
	return result.LDS, result.CDS, nil
}
