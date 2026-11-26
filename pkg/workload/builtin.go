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

import "slices"

// builtInKinds are the four native workload Kinds (core/v1 Pod and the
// apps/v1 Deployment, StatefulSet and DaemonSet) served by hard-coded
// dispatch. It is the single source of truth for the built-in membership
// gates in registry admission, policy validation and mutation; the
// behavioral switches in internal/webhooks enumerate their own cases,
// pinned to this set by coverage tests.
var builtInKinds = map[string]struct{}{
	"Pod":         {},
	"Deployment":  {},
	"StatefulSet": {},
	"DaemonSet":   {},
}

// IsBuiltInKind reports whether kind is a native workload Kind. The match
// is exact-case, like the dispatch switches themselves.
func IsBuiltInKind(kind string) bool {
	_, ok := builtInKinds[kind]
	return ok
}

// BuiltInKinds returns the native Kind names in sorted order, for
// dispatch-coverage tests that must iterate the authoritative set.
func BuiltInKinds() []string {
	out := make([]string, 0, len(builtInKinds))
	for kind := range builtInKinds {
		out = append(out, kind)
	}
	slices.Sort(out)
	return out
}
