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
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// coreGroupName stands in for the empty core API group so the rendered
	// name never contains an empty segment ("mutate-pods..varmor.org").
	coreGroupName = "core"
	// webhookNameHashHexLen is the SHA-256 prefix (64 bits) appended on
	// overflow; the registry rejects the unlikely collision.
	webhookNameHashHexLen = 16
	// webhookNamePrefix and webhookNameSuffix frame every entry name and
	// preserve the three-segment FQDN shape required by
	// validation.IsFullyQualifiedName.
	webhookNamePrefix = "mutate-"
	webhookNameSuffix = ".varmor.org"
)

// adapterGroup returns the adapter's group, substituting coreGroupName for
// the empty core group so it renders as a non-empty DNS label.
func adapterGroup(a Adapter) string {
	if g := a.GVK().Group; g != "" {
		return g
	}
	return coreGroupName
}

// rawWebhookEntryName renders mutate-<resource>.<group>.varmor.org.
func rawWebhookEntryName(a Adapter) string {
	return webhookNamePrefix + a.GVR().Resource + "." + adapterGroup(a) + webhookNameSuffix
}

// WebhookEntryName renders the adapter's MutatingWebhook entry name. Names up
// to the 253-char DNS-1123 limit return unchanged. Longer names keep the full
// resource and the group's leading labels and append a SHA-256 prefix of the
// full raw name: mutate-<resource>.<group...>-<hash>.varmor.org. The fixed
// suffix keeps the three dot-separated segments required by the API server's
// IsFullyQualifiedName validation, while hashing the full raw name keeps
// distinct identities distinct. The boolean reports whether overflow fired.
// The result is pure and stable, as the name is persisted and used as the
// multi-version merge key.
func WebhookEntryName(a Adapter) (string, bool) {
	full := rawWebhookEntryName(a)
	if len(full) <= validation.DNS1123SubdomainMaxLength {
		return full, false
	}

	sum := sha256.Sum256([]byte(full))
	hash := hex.EncodeToString(sum[:])[:webhookNameHashHexLen]

	group := adapterGroup(a)
	// The output adds a "-<hash>" junction to the raw name. Shrink the group
	// by the overflow plus that junction so the result fits 253 chars; trim
	// separator endings so the hash follows an alphanumeric char. The
	// registry-validated resource label (max 63 chars) is never shortened,
	// which keeps the budget positive (at least 154 chars).
	groupBudget := validation.DNS1123SubdomainMaxLength -
		(len(full) - len(group)) - 1 - webhookNameHashHexLen
	group = strings.TrimRight(group[:groupBudget], ".-")

	return webhookNamePrefix + a.GVR().Resource + "." + group + "-" + hash + webhookNameSuffix, true
}
