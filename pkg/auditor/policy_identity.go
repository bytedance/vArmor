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

package audit

import (
	"github.com/rs/zerolog"
)

// PolicyIdentity is the authoritative identity of the VarmorPolicy or
// VarmorClusterPolicy that a violation event is attributed to. It is derived
// from the owning ArmorProfile's metadata (never by string-parsing the profile
// name, which is ambiguous because both namespace and name may contain "-"),
// and is embedded into each violation event as the policyKind/policyName/
// policyNamespace fields so users can immediately tell which policy caused a
// violation.
type PolicyIdentity struct {
	// Kind is "VarmorPolicy" or "VarmorClusterPolicy".
	Kind string
	// Name is the policy's metadata.name.
	Name string
	// Namespace is the policy's namespace for a namespaced VarmorPolicy, and
	// an empty string for a cluster-scoped VarmorClusterPolicy.
	Namespace string
}

// UpsertPolicyIdentity registers or updates the authoritative identity for the
// given ArmorProfile name. It is intended to be called by the agent from its
// ArmorProfile watch add/update handlers. It is safe for concurrent use.
func (auditor *Auditor) UpsertPolicyIdentity(profileName string, id PolicyIdentity) {
	auditor.policyIdentityMu.Lock()
	defer auditor.policyIdentityMu.Unlock()
	auditor.policyIdentityCache[profileName] = id
}

// DeletePolicyIdentity removes the identity registered for the given
// ArmorProfile name. It is intended to be called by the agent from its
// ArmorProfile watch delete handler. It is safe for concurrent use.
func (auditor *Auditor) DeletePolicyIdentity(profileName string) {
	auditor.policyIdentityMu.Lock()
	defer auditor.policyIdentityMu.Unlock()
	delete(auditor.policyIdentityCache, profileName)
}

// lookupPolicyIdentity returns the identity registered for the given
// ArmorProfile name. The boolean result reports whether an entry was found;
// callers treat a miss as best-effort and emit empty policy fields. It is safe
// for concurrent use.
func (auditor *Auditor) lookupPolicyIdentity(profileName string) (PolicyIdentity, bool) {
	auditor.policyIdentityMu.RLock()
	defer auditor.policyIdentityMu.RUnlock()
	id, ok := auditor.policyIdentityCache[profileName]
	return id, ok
}

// withPolicyIdentity returns a zerolog field-injector that embeds the
// policyKind/policyName/policyNamespace fields for the given ArmorProfile name
// into a violation event. It is chained into every emission path via
// (*zerolog.Event).Func. On a cache miss the three fields are emitted as empty
// strings, so attribution is best-effort and never blocks or drops an event.
func (auditor *Auditor) withPolicyIdentity(profileName string) func(*zerolog.Event) {
	id, _ := auditor.lookupPolicyIdentity(profileName)
	return func(e *zerolog.Event) {
		e.Str("policyKind", id.Kind).
			Str("policyName", id.Name).
			Str("policyNamespace", id.Namespace)
	}
}
