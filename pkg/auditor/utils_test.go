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

package audit

import (
	"reflect"
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
	"gotest.tools/assert"
)

func getSyscallName(syscall int) string {
	name, _ := seccomp.ScmpSyscall(syscall).GetName()
	return name
}

func Test_parseSeccompLineByte(t *testing.T) {
	testCases := []struct {
		name          string
		line          string
		expectedEvent SeccompEvent
	}{
		{
			name: "test_1",
			line: `Dec 21 15:35:05 n57-061-048 kernel: [26083697.716609][   T55] audit: type=1326 audit(1734766505.185:6623933): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==unconfined pid=699016 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=72 compat=0 ip=0x7fb83dc5e92e code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1734766505.185:6623933",
				Epoch:   1734766505,
				Subj:    "unconfined",
				PID:     699016,
				Comm:    "runc:[2:INIT]",
				Exe:     "/",
				Syscall: getSyscallName(72),
			},
		},
		{
			name: "test_2",
			line: `Dec 21 15:35:04 n87-043-070 kernel: [26083697.172104][   T55] audit: type=1326 audit(1734766503.316:6623924): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==varmor-cluster-varmor-demo-4//null-/bin/sleep (complain) pid=698839 comm="sleep" exe="/bin/sleep" sig=0 arch=c000003e syscall=11 compat=0 ip=0x7f24913a87b7 code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1734766503.316:6623924",
				Epoch:   1734766503,
				Subj:    "varmor-cluster-varmor-demo-4//null-/bin/sleep (complain)",
				PID:     698839,
				Comm:    "sleep",
				Exe:     "/bin/sleep",
				Syscall: getSyscallName(11),
			},
		},
		{
			name: "test_3",
			line: `type=SECCOMP msg=audit(1740535410.396:1727850): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==cri-containerd.apparmor.d (enforce) pid=3315793 comm="chmod" exe="/bin/chmod" sig=0 arch=c000003e syscall=268 compat=0 ip=0x7fd8c219ef24 code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1740535410.396:1727850",
				Epoch:   1740535410,
				Subj:    "cri-containerd.apparmor.d (enforce)",
				PID:     3315793,
				Comm:    "chmod",
				Exe:     "/bin/chmod",
				Syscall: getSyscallName(268),
			},
		},
		{
			name: "test_4",
			line: `<5>Jan 15 16:27:18 n37-031-068 kernel: [22734288.221628][   T55] audit: type=1326 audit(1705307237.424:9332888): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==unconfined pid=2684228 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=439 compat=0 ip=0x7f0ef217692e code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1705307237.424:9332888",
				Epoch:   1705307237,
				Subj:    "unconfined",
				PID:     2684228,
				Comm:    "runc:[2:INIT]",
				Exe:     "/",
				Syscall: getSyscallName(439),
			},
		},
		{
			name: "test_5",
			line: `Feb 27 15:08:27 aks-nodepool-83529136-vmss000005 kernel: [28000740.608619] audit: type=1326 audit(1740668907.734:6970): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=? pid=2045941 comm="chmod" exe="/usr/bin/chmod" sig=0 arch=c000003e syscall=268 compat=0 ip=0x7ff84e0733c7 code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1740668907.734:6970",
				Epoch:   1740668907,
				Subj:    "?",
				PID:     2045941,
				Comm:    "chmod",
				Exe:     "/usr/bin/chmod",
				Syscall: getSyscallName(268),
			},
		},
		{
			name: "test_6",
			line: `Feb 27 15:22:58 aks-nodepool-83529136-vmss000000 kernel: [9983249.522470] audit: type=1326 audit(1740669778.647:6964): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=? pid=2159619 comm="unshare" exe="/usr/bin/unshare" sig=0 arch=c000003e syscall=272 compat=0 ip=0x7f3a2617de1b code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1740669778.647:6964",
				Epoch:   1740669778,
				Subj:    "?",
				PID:     2159619,
				Comm:    "unshare",
				Exe:     "/usr/bin/unshare",
				Syscall: getSyscallName(272),
			},
		},
		{
			name: "test_7",
			line: `type=SECCOMP msg=audit(1740670474.406:2766278): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=6412 comm="chmod" exe="/usr/bin/chmod" sig=0 arch=c000003e syscall=268 compat=0 ip=0x7f5c0fae83c7 code=0x7ffc0000`,
			expectedEvent: SeccompEvent{
				AuditID: "1740670474.406:2766278",
				Epoch:   1740670474,
				Subj:    "",
				PID:     6412,
				Comm:    "chmod",
				Exe:     "/usr/bin/chmod",
				Syscall: getSyscallName(268),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event, err := ParseSeccompAuditEvent(tc.line)
			assert.NilError(t, err)
			ret := reflect.DeepEqual(*event, tc.expectedEvent)
			assert.Equal(t, ret, true)
		})
	}
}

func Test_parseVarmorProfileName(t *testing.T) {
	testCases := []struct {
		name                string
		eventType           string
		line                string
		expectedProfileName string
	}{
		{
			name:                "test_1",
			eventType:           "AppArmor",
			line:                `type=AVC msg=audit(1704362546.390:8945691): apparmor="ALLOWED" operation="file_mmap" profile="varmor-demo-demo-4//null-/bin/ping" name="/usr/lib/x86_64-linux-gnu/libidn2.so.0.3.4" pid=3711187 comm="ping" requested_mask="rm" denied_mask="rm" fsuid=0 ouid=0`,
			expectedProfileName: "varmor-demo-demo-4",
		},
		{
			name:                "test_2",
			eventType:           "AppArmor",
			line:                `type=AVC msg=audit(1748416464.448:4290914): apparmor="AUDIT" operation="getattr" profile="varmor-demo-demo-1" name="/run/secrets/kubernetes.io/serviceaccount/..2025_05_28_06_46_38.392375317/token" pid=1032907 comm="cat" requested_mask="r" fsuid=0 ouid=0`,
			expectedProfileName: "varmor-demo-demo-1",
		},
		{
			name:                "test_3",
			eventType:           "AppArmor",
			line:                `type=AVC msg=audit(1748416438.970:4290903): apparmor="DENIED" operation="open" profile="varmor-demo-demo-1" name="/run/secrets/kubernetes.io/serviceaccount/..2025_05_28_06_46_38.392375317/token" pid=1032243 comm="cat" requested_mask="r" denied_mask="r" fsuid=0 ouid=0`,
			expectedProfileName: "varmor-demo-demo-1",
		},
		{
			name:                "test_4",
			eventType:           "AppArmor",
			line:                `type=AVC msg=audit(1748416438.970:4290903): apparmor="DENIED" operation="open" profile="cri-containerd.apparmor.d" name="/run/secrets/kubernetes.io/serviceaccount/..2025_05_28_06_46_38.392375317/token" pid=1032243 comm="cat" requested_mask="r" denied_mask="r" fsuid=0 ouid=0`,
			expectedProfileName: "cri-containerd.apparmor.d",
		},
		{
			name:                "test_5",
			eventType:           "Seccomp",
			line:                `Dec 21 15:35:05 n57-061-048 kernel: [26083697.716609][   T55] audit: type=1326 audit(1734766505.185:6623933): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==unconfined pid=699016 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=72 compat=0 ip=0x7fb83dc5e92e code=0x7ffc0000`,
			expectedProfileName: "unconfined",
		},
		{
			name:                "test_6",
			eventType:           "Seccomp",
			line:                `Dec 21 15:35:04 n87-043-070 kernel: [26083697.172104][   T55] audit: type=1326 audit(1734766503.316:6623924): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==varmor-cluster-varmor-demo-4//null-/bin/sleep (complain) pid=698839 comm="sleep" exe="/bin/sleep" sig=0 arch=c000003e syscall=11 compat=0 ip=0x7f24913a87b7 code=0x7ffc0000`,
			expectedProfileName: "varmor-cluster-varmor-demo-4",
		},
		{
			name:                "test_7",
			eventType:           "Seccomp",
			line:                `type=SECCOMP msg=audit(1740535410.396:1727850): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==cri-containerd.apparmor.d (enforce) pid=3315793 comm="chmod" exe="/bin/chmod" sig=0 arch=c000003e syscall=268 compat=0 ip=0x7fd8c219ef24 code=0x7ffc0000`,
			expectedProfileName: "cri-containerd.apparmor.d",
		},
		{
			name:                "test_8",
			eventType:           "Seccomp",
			line:                `<5>Jan 15 16:27:18 n37-031-068 kernel: [22734288.221628][   T55] audit: type=1326 audit(1705307237.424:9332888): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==unconfined pid=2684228 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=439 compat=0 ip=0x7f0ef217692e code=0x7ffc0000`,
			expectedProfileName: "unconfined",
		},
		{
			name:                "test_9",
			eventType:           "Seccomp",
			line:                `Feb 27 15:08:27 aks-nodepool-83529136-vmss000005 kernel: [28000740.608619] audit: type=1326 audit(1740668907.734:6970): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=? pid=2045941 comm="chmod" exe="/usr/bin/chmod" sig=0 arch=c000003e syscall=268 compat=0 ip=0x7ff84e0733c7 code=0x7ffc0000`,
			expectedProfileName: "",
		},
		{
			name:                "test_10",
			eventType:           "Seccomp",
			line:                `Feb 27 15:22:58 aks-nodepool-83529136-vmss000000 kernel: [9983249.522470] audit: type=1326 audit(1740669778.647:6964): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=? pid=2159619 comm="unshare" exe="/usr/bin/unshare" sig=0 arch=c000003e syscall=272 compat=0 ip=0x7f3a2617de1b code=0x7ffc0000`,
			expectedProfileName: "",
		},
		{
			name:                "test_11",
			eventType:           "Seccomp",
			line:                `type=SECCOMP msg=audit(1740670474.406:2766278): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=6412 comm="chmod" exe="/usr/bin/chmod" sig=0 arch=c000003e syscall=268 compat=0 ip=0x7f5c0fae83c7 code=0x7ffc0000`,
			expectedProfileName: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.eventType {
			case "AppArmor":
				e, err := ParseAppArmorEvent(tc.line)
				assert.NilError(t, err)
				profileName := ParseVarmorProfileName(e.Profile)
				assert.Equal(t, profileName, tc.expectedProfileName)
			case "Seccomp":
				e, err := ParseSeccompAuditEvent(tc.line)
				assert.NilError(t, err)
				profileName := ParseVarmorProfileName(e.Subj)
				assert.Equal(t, profileName, tc.expectedProfileName)
			}
		})
	}
}
