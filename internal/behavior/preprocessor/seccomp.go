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
	"regexp"
	"strconv"
	"strings"

	seccomp "github.com/seccomp/libseccomp-golang"

	varmortypes "github.com/bytedance/vArmor/internal/types"
)

var (
	seccompLineRegex = regexp.MustCompile(
		`(type=SECCOMP|audit:.+type=1326).+audit\((.+)\).+pid=(\b\d+\b).+comm="(.+)".+exe="(.+)".+syscall=(\b\d+\b).*`,
	)
	expectedNum = 7
)

func parseSeccompEvent(line string) (*varmortypes.SeccompLogRecord, error) {
	captures := seccompLineRegex.FindStringSubmatch(line)
	if len(captures) != expectedNum {
		return nil, fmt.Errorf("unable to extract the expected field")
	}

	timeString := strings.Split(captures[2], ":")[0]
	timestampFloat, err := strconv.ParseFloat(timeString, 64)
	if err != nil {
		return nil, fmt.Errorf("extract TIMESTAMP failed")
	}

	pid, err := strconv.Atoi(captures[3])
	if err != nil {
		return nil, fmt.Errorf("extract PID failed")
	}

	syscall, err := strconv.Atoi(captures[6])
	if err != nil {
		return nil, fmt.Errorf("extract SYSCALL failed")
	}
	syscallName, err := seccomp.ScmpSyscall(syscall).GetName()
	if err != nil {
		return nil, err
	}

	r := varmortypes.SeccompLogRecord{
		Time:    int64(timestampFloat),
		Pid:     uint64(pid),
		Exe:     captures[5],
		Comm:    captures[4],
		Syscall: syscallName,
	}

	return &r, nil
}

func (p *DataPreprocessor) parseSeccompEventForTree(event *varmortypes.SeccompLogRecord) error {
	if _, exists := p.syscall[event.Syscall]; exists {
		return nil
	}

	p.syscall[event.Syscall] = struct{}{}
	p.behaviorData.DynamicResult.Seccomp.Syscalls = append(p.behaviorData.DynamicResult.Seccomp.Syscalls, event.Syscall)

	return nil
}
