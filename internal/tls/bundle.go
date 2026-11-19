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

package tls

import (
	"bytes"
	"encoding/pem"
	"fmt"

	v1 "k8s.io/api/core/v1"
)

// BuildCABundle assembles the caBundle PEM written into the admission
// webhook configurations.
//
// During a root CA rotation the CA Secret holds both the retiring CA
// (PreviousRootCAKey) and the current CA (RootCAKey). Concatenating them lets
// the apiserver verify webhook leaf certificates signed by either CA, so the
// make-before-break handover does not break admission calls while replicas
// hot-reload the new leaf. The previous CA comes first so a parser that stops
// at the first certificate still prefers the current one only after
// retirement removes the old entry.
//
// Empty entries are skipped and duplicate certificates are collapsed. It is
// fail-closed: a missing or undecodable current CA returns an error rather
// than a bundle that cannot authenticate the webhook.
func BuildCABundle(caSecret *v1.Secret) ([]byte, error) {
	if caSecret == nil {
		return nil, fmt.Errorf("cannot build a CA bundle from a nil Secret")
	}

	var bundle bytes.Buffer
	seen := make(map[string]struct{})

	for _, key := range []string{PreviousRootCAKey, RootCAKey} {
		raw := caSecret.Data[key]
		if len(raw) == 0 {
			continue
		}

		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			if key == RootCAKey {
				return nil, fmt.Errorf("current root CA in %q is not a valid PEM certificate", key)
			}
			// A corrupt retired CA must not block admission on the current CA.
			continue
		}

		fingerprint := string(block.Bytes)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		bundle.Write(pem.EncodeToMemory(block))
	}

	if bundle.Len() == 0 {
		return nil, fmt.Errorf("CA Secret %q contains no usable root CA certificate", caSecret.Name)
	}
	return bundle.Bytes(), nil
}
