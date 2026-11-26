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

package workload

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// coreGroupName renders the empty core API group, since an empty group
	// segment would yield an invalid name ("mutate-pods..varmor.org").
	coreGroupName = "core"
	// webhookNameHashHexLen is the SHA-256 prefix (64 bits) appended when a
	// raw entry name overflows; the registry guard covers hash collisions.
	webhookNameHashHexLen = 16
)

// rawWebhookEntryName renders mutate-<resource>.<group>.varmor.org without
// any length handling.
func rawWebhookEntryName(a Adapter) string {
	group := a.GVK().Group
	if group == "" {
		group = coreGroupName
	}
	return fmt.Sprintf("mutate-%s.%s.varmor.org", a.GVR().Resource, group)
}

// WebhookEntryName renders the adapter's MutatingWebhook entry name,
// guaranteed to pass validation.IsDNS1123Subdomain (the API server's own
// rule, capped at 253 chars). Names that fit are returned unchanged;
// over-long names keep their prefix plus a deterministic SHA-256 suffix of
// the full raw name. The boolean reports whether truncation fired. The
// result is pure and stable, as the name is both persisted and used as the
// multi-version merge key.
func WebhookEntryName(a Adapter) (string, bool) {
	full := rawWebhookEntryName(a)
	if len(full) <= validation.DNS1123SubdomainMaxLength {
		return full, false
	}

	sum := sha256.Sum256([]byte(full))
	hashSuffix := "-" + hex.EncodeToString(sum[:])[:webhookNameHashHexLen]
	kept := validation.DNS1123SubdomainMaxLength - len(hashSuffix)

	// Strip trailing separators so the suffix follows an alphanumeric char.
	return strings.TrimRight(full[:kept], ".-") + hashSuffix, true
}
