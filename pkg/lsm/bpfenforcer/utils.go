// Copyright 2023 vArmor Authors
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

package bpfenforcer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type bpfPathRule struct {
	Permissions uint32
	Flags       uint32
	Prefix      [64]byte
	Suffix      [64]byte
}

type bpfNetworkRule struct {
	Flags   uint32
	Address [16]byte
	Mask    [16]byte
	Port    uint32
}

func readMntNsID(pid uint32) (uint32, error) {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	realPath, err := os.Readlink(path)
	if err != nil {
		return 0, err
	}

	index := strings.Index(realPath, "[")
	if index == -1 {
		return 0, fmt.Errorf(fmt.Sprintf("fatel error: can not parser mnt ns id from: %s", realPath))
	}

	id := realPath[index+1 : len(realPath)-1]
	u64, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, fmt.Errorf(fmt.Sprintf("fatel error: can not transform mnt ns id (%s) to uint64 type", realPath))
	}

	return uint32(u64), nil
}
