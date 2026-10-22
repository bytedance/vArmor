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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnforcerTypeRejectsMalformedValues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enforcer string
	}{
		{name: "empty", enforcer: ""},
		{name: "unknown", enforcer: "unsupported"},
		{name: "recognized token followed by junk", enforcer: "BPFunsupported"},
		{name: "duplicate token", enforcer: "BPFBPF"},
		{name: "separator", enforcer: "AppArmor-BPF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, Unknown, GetEnforcerType(tc.enforcer))
		})
	}
}

func TestGetEnforcerTypeAcceptsSupportedCombinations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enforcer string
		want     Enforcer
	}{
		{name: "single", enforcer: "AppArmor", want: AppArmor},
		{name: "documented combination", enforcer: "AppArmorBPF", want: AppArmor | BPF},
		{name: "network proxy combination", enforcer: "NetworkProxyBPFSeccomp", want: NetworkProxy | BPF | Seccomp},
		{name: "alternate order", enforcer: "SeccompAppArmorBPF", want: Seccomp | AppArmor | BPF},
		{name: "case insensitive", enforcer: "bpfNetworkProxy", want: BPF | NetworkProxy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, GetEnforcerType(tc.enforcer))
		})
	}
}
