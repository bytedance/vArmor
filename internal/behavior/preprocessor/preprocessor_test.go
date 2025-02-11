// Copyright 2024 vArmor Authors
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

package preprocessor

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
	log "sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_parseAppArmorEvent(t *testing.T) {
	targetPIDs := make(map[uint32]struct{}, 10)
	targetMnts := make(map[uint32]struct{}, 10)

	p := NewDataPreprocessor(
		"LOCALHOST",
		"test",
		"/",
		"test",
		"AppArmor",
		targetPIDs,
		targetMnts,
		"127.0.0.1",
		0,
		true,
		true,
		log.Log.WithName("TEST"))

	event, err := parseAppArmorEvent(`<5>Jan  4 18:02:26 n37-031-068 kernel: [21789599.565170][   T55] audit: type=1400 audit(1704362546.390:8945691): apparmor="ALLOWED" operation="file_mmap" profile="varmor-demo-demo-4//null-/bin/ping" name="/usr/lib/x86_64-linux-gnu/libidn2.so.0.3.4" pid=3711187 comm="ping" requested_mask="rm" denied_mask="rm" fsuid=0 ouid=0`)
	assert.NilError(t, err)
	err = p.parseAppArmorEventForTree(event)
	assert.NilError(t, err)
}

func Test_parseSeccompEvent(t *testing.T) {
	targetPIDs := make(map[uint32]struct{}, 10)
	targetMnts := make(map[uint32]struct{}, 10)

	p := NewDataPreprocessor(
		"LOCALHOST",
		"test",
		"/",
		"test",
		"Seccomp",
		targetPIDs,
		targetMnts,
		"127.0.0.1",
		0,
		true,
		true,
		log.Log.WithName("TEST"))

	event, err := parseSeccompEvent(`<5>Jan 15 16:27:18 n37-031-068 kernel: [22734288.221628][   T55] audit: type=1326 audit(1705307237.424:9332888): auid=4294967295 uid=0 gid=0 ses=4294967295 subj==unconfined pid=2684228 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=439 compat=0 ip=0x7f0ef217692e code=0x7ffc0000`)
	assert.NilError(t, err)
	fmt.Println(event)
	p.log.Info("print event", "event", event)
	err = p.parseSeccompEventForTree(event)
	assert.NilError(t, err)
}
