// Copyright 2024 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable lwriter or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

/*
#cgo CFLAGS: -I /usr/include/ -Wall
#cgo LDFLAGS: -L /usr/lib/ -lapparmor
#include "aalogparse/aalogparse.h"
#include "stdlib.h"
*/
import "C"

import (
	"strings"
	"unsafe"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/go-logr/logr"

	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

type AuditWriter struct {
	auditor *Auditor
	log     logr.Logger
}

func (writer *AuditWriter) Write(p []byte) (int, error) {
	content := string(p)
	if strings.Contains(content, "type=1400") || strings.Contains(content, "type=AVC") {
		index := strings.Index(content, "type=1400 audit")
		if index != -1 {
			content = strings.Replace(content[index:], "type=1400 audit", "type=AVC msg=audit", 1)
		}

		writer.log.V(3).Info("receive an AppArmor audit event", "content", content)

		// Call parse_record() of libapparmor.so to parse the event
		msg := C.CString(content)
		defer C.free(unsafe.Pointer(msg))
		record := C.parse_record(msg)
		defer C.free_record(record)
		pid := uint32(record.pid)

		// Try to read the process' mnt ns id from the proc filesystem.
		// Note:
		//   This might fail if the process has already been destroyed.
		//   If so, we can't associate container information for violations.
		var mntNsID uint32
		var ok bool
		if mntNsID, ok = writer.auditor.mntNsIDCache[pid]; !ok {
			mntNsID, _ = varmorutils.ReadMntNsID(pid)
		}

		info := writer.auditor.containerCache[mntNsID]
		writer.log.Info("audit event",
			"container id", info.ContainerID,
			"container name", info.ContainerName,
			"pod name", info.PodName,
			"pod namespace", info.PodNamespace,
			"pod uid", info.PodUID,
			"pid", pid, "content", content)
	}
	return len(p), nil
}

func (auditor *Auditor) readFromSystemdJournald() {
	auditor.log.Info("start reading from systemd-journald")

	writer := &AuditWriter{
		auditor: auditor,
		log:     auditor.log,
	}

	err := auditor.journalReader.Follow(auditor.journalReaderTimeout, writer)
	if err != sdjournal.ErrExpired {
		auditor.log.Error(err, "auditor.sdjournalReader.Follow()")
	}
}
