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

// This file lives on the controller side of the Phase 4 boundary: it reads
// MITMConfig off the policy, performs Secret lookups for any
// HeaderAction.SecretRef, and returns a *MITMInput that the translator can
// consume as a pure-data input.
//
// Keeping resolution here (NOT inside the translator) preserves the
// translator's property of being a deterministic, side-effect-free function
// of its inputs. It also makes it easy to unit-test with a fake clientset
// and avoids fanning out kube-apiserver access across multiple call sites.

import (
	"context"
	"fmt"

	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

// ResolveMITMInput transforms a policy-side MITMConfig into the
// translator-side MITMInput used by TranslateEgressRules.
//
// Responsibilities:
//   - Resolve every HeaderAction into a literal (Name, Value) HeaderToAdd,
//     reading referenced Secret keys in `namespace` when SecretRef is set.
//   - Drop HeaderMutation entries whose Domain is not present in
//     MITMConfig.Domains (spec invariant: every mutation targets a
//     declared MITM domain).
//   - Leave the leaf cert/key paths at their varmorconfig defaults so the
//     translator can reference them without another lookup.
//
// Returns (nil, nil) when MITM is not configured on the policy. Returns a
// disabled *MITMInput only if explicitly requested via an empty Domains
// slice (which the API-validation layer already forbids); callers should
// use MITMInput.Enabled() to guard.
//
// For unit testing, pass a fake kubernetes.Clientset; the function touches
// only the core/v1 Secret API.
func ResolveMITMInput(
	kubeClient *kubernetes.Clientset,
	namespace string,
	npc *varmor.NetworkProxyConfig,
) (*MITMInput, error) {
	if npc == nil || npc.MITM == nil || len(npc.MITM.Domains) == 0 {
		return nil, nil
	}
	cfg := npc.MITM

	// Build a set of declared domains for O(1) lookup while resolving
	// HeaderMutations. Any mutation targeting an undeclared domain is
	// skipped defensively (the CRD validator should already reject it).
	declared := make(map[string]struct{}, len(cfg.Domains))
	for _, d := range cfg.Domains {
		declared[d] = struct{}{}
	}

	// Per-namespace Secret cache so repeated SecretRefs to the same Secret
	// incur exactly one apiserver round-trip per reconcile.
	secretCache := make(map[string]map[string][]byte)

	headersByDomain := make(map[string][]HeaderToAdd, len(cfg.HeaderMutations))
	for _, hm := range cfg.HeaderMutations {
		if _, ok := declared[hm.Domain]; !ok {
			continue
		}
		headers := make([]HeaderToAdd, 0, len(hm.Headers))
		for _, h := range hm.Headers {
			value, err := resolveHeaderActionValue(kubeClient, namespace, h, secretCache)
			if err != nil {
				return nil, fmt.Errorf("resolve header %q on domain %q: %w", h.Name, hm.Domain, err)
			}
			headers = append(headers, HeaderToAdd{Name: h.Name, Value: value})
		}
		if len(headers) > 0 {
			// Merge rather than overwrite so multiple HeaderMutation
			// entries for the same domain are additive.
			headersByDomain[hm.Domain] = append(headersByDomain[hm.Domain], headers...)
		}
	}

	return &MITMInput{
		Domains:         append([]string(nil), cfg.Domains...),
		HeadersByDomain: headersByDomain,
		LeafCertPath:    varmorconfig.MITMLeafCertPath,
		LeafKeyPath:     varmorconfig.MITMLeafKeyPath,
	}, nil
}

// resolveHeaderActionValue returns the literal header value. Exactly one
// of Value / SecretRef must be set; API validation enforces mutual
// exclusion, but we defensively return an error if both are empty so a
// malformed object produces a descriptive reconciliation error instead
// of silently injecting an empty header.
func resolveHeaderActionValue(
	kubeClient *kubernetes.Clientset,
	namespace string,
	h varmor.HeaderAction,
	cache map[string]map[string][]byte,
) (string, error) {
	if h.SecretRef == nil {
		if h.Value == "" {
			return "", fmt.Errorf("header %q has neither value nor secretRef", h.Name)
		}
		return h.Value, nil
	}
	if h.Value != "" {
		return "", fmt.Errorf("header %q sets both value and secretRef", h.Name)
	}

	data, err := getSecretData(kubeClient, namespace, h.SecretRef.Name, cache)
	if err != nil {
		return "", err
	}
	raw, ok := data[h.SecretRef.Key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s has no key %q", namespace, h.SecretRef.Name, h.SecretRef.Key)
	}
	return string(raw), nil
}

// getSecretData returns the Data map for the named Secret, caching the
// result so that two SecretRef entries targeting distinct keys of the same
// Secret only trigger one GET per reconcile.
func getSecretData(
	kubeClient *kubernetes.Clientset,
	namespace, name string,
	cache map[string]map[string][]byte,
) (map[string][]byte, error) {
	if data, ok := cache[name]; ok {
		return data, nil
	}
	if kubeClient == nil {
		// Allow unit tests to exercise literal-value paths without
		// wiring up a fake client, while still hard-failing on any
		// request that actually needs a Secret lookup.
		return nil, fmt.Errorf("secret %s/%s requested but kubeClient is nil", namespace, name)
	}
	sec, err := kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s/%s not found", namespace, name)
		}
		return nil, fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
	}
	cache[name] = sec.Data
	return sec.Data, nil
}
