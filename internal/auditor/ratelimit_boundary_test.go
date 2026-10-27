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
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
)

func TestRateLimit_AuditSubscriptionTransitions(t *testing.T) {
	for _, name := range []string{
		"duplicate audit registration",
		"BPF-only registration with audit subscriber",
		"multiple audit subscribers",
		"redundant removal after external change",
		"BPF-only registration without audit subscribers",
	} {
		t.Run(name, func(t *testing.T) {
			// Keep all sysctl access in memory and observe redundant reads/writes.
			value := uint64(5)
			reads, writes := 0, 0
			checkState := func(stage string, wantValue uint64, wantReads, wantWrites int) {
				t.Helper()
				assert.Equal(t, wantValue, value, "%s: rate limit", stage)
				assert.Equal(t, wantReads, reads, "%s: sysctl reads", stage)
				assert.Equal(t, wantWrites, writes, "%s: sysctl writes", stage)
			}
			originalRead, originalWrite := sysctlRead, sysctlWrite
			t.Cleanup(func() {
				sysctlRead, sysctlWrite = originalRead, originalWrite
			})
			sysctlRead = func(string) (string, error) {
				reads++
				return fmt.Sprint(value), nil
			}
			sysctlWrite = func(_ string, next uint64) error {
				writes++
				value = next
				return nil
			}

			auditor := &Auditor{
				auditEventChs: make(map[string]chan<- string),
				bpfEventChs:   make(map[string]chan<- BpfEvent),
				log:           logr.Discard(),
			}
			auditCh := make(chan string, 1)
			bpfCh := make(chan BpfEvent, 1)
			if name == "BPF-only registration without audit subscribers" {
				auditor.AddBehaviorEventNotifyChs("bpf", nil, &bpfCh)
				auditor.DeleteBehaviorEventNotifyCh("bpf")
				auditor.DeleteBehaviorEventNotifyCh("missing")
				checkState("BPF-only cycle", 5, 0, 0)
				return
			}

			auditor.AddBehaviorEventNotifyChs("audit", &auditCh, nil)
			switch name {
			case "duplicate audit registration":
				auditor.AddBehaviorEventNotifyChs("audit", &auditCh, nil)
			case "BPF-only registration with audit subscriber":
				auditor.AddBehaviorEventNotifyChs("bpf", nil, &bpfCh)
				auditor.DeleteBehaviorEventNotifyCh("bpf")
			case "multiple audit subscribers":
				auditor.AddBehaviorEventNotifyChs("second", &auditCh, nil)
				auditor.DeleteBehaviorEventNotifyCh("second")
			}
			checkState("active audit subscriber", 0, 1, 1)
			auditor.DeleteBehaviorEventNotifyCh("audit")
			checkState("last audit subscriber removed", 5, 1, 2)

			expectedValue := uint64(5)
			if name == "redundant removal after external change" {
				// A completed subscription cycle no longer owns this setting.
				value = 7
				expectedValue = 7
				auditor.DeleteBehaviorEventNotifyCh("audit")
				auditor.DeleteBehaviorEventNotifyCh("missing")
				checkState("redundant removals", expectedValue, 1, 2)
			}

			// A new cycle must save and restore the current system setting.
			auditor.AddBehaviorEventNotifyChs("next", &auditCh, nil)
			auditor.DeleteBehaviorEventNotifyCh("next")
			checkState("second cycle", expectedValue, 2, 4)
		})
	}
}
