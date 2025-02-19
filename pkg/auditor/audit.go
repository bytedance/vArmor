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
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

func (auditor *Auditor) convertAppArmorEvent(e string) (*AppArmorEvent, error) {
	msg := C.CString(e)
	defer C.free(unsafe.Pointer(msg))
	record := C.parse_record(msg)
	defer C.free_record(record)

	if record == nil {
		return nil, fmt.Errorf("C.parse_record(msg) failed")
	}

	event := AppArmorEvent{
		Version:        uint32(record.version),
		Event:          uint32(record.event),
		PID:            uint64(record.pid),
		PeerPID:        uint64(record.peer_pid),
		Task:           uint64(record.task),
		MagicToken:     uint64(record.magic_token),
		Epoch:          int64(record.epoch),
		AuditSubId:     uint32(record.audit_sub_id),
		BitMask:        int32(record.bitmask),
		AuditId:        C.GoString(record.audit_id),
		Operation:      C.GoString(record.operation),
		DeniedMask:     C.GoString(record.denied_mask),
		RequestedMask:  C.GoString(record.requested_mask),
		Fsuid:          uint64(record.fsuid),
		Ouid:           uint64(record.ouid),
		Profile:        C.GoString(record.profile),
		PeerProfile:    C.GoString(record.peer_profile),
		Comm:           C.GoString(record.comm),
		Name:           C.GoString(record.name),
		Name2:          C.GoString(record.name2),
		Namespace:      C.GoString(record.namespace),
		Attribute:      C.GoString(record.attribute),
		Parent:         uint64(record.parent),
		Info:           C.GoString(record.info),
		PeerInfo:       C.GoString(record.peer_info),
		ErrorCode:      int32(record.error_code),
		ActiveHat:      C.GoString(record.active_hat),
		NetFamily:      C.GoString(record.net_family),
		NetProtocol:    C.GoString(record.net_protocol),
		NetSockType:    C.GoString(record.net_sock_type),
		NetLocalAddr:   C.GoString(record.net_local_addr),
		NetLocalPort:   uint64(record.net_local_port),
		NetForeignAddr: C.GoString(record.net_foreign_addr),
		NetForeignPort: uint64(record.net_foreign_port),
		DbusBus:        C.GoString(record.dbus_bus),
		DbusPath:       C.GoString(record.dbus_path),
		DbusInterface:  C.GoString(record.dbus_interface),
		DbusMember:     C.GoString(record.dbus_member),
		Signal:         C.GoString(record.signal),
		Peer:           C.GoString(record.peer),
		FsType:         C.GoString(record.fs_type),
		Flags:          C.GoString(record.flags),
		SrcName:        C.GoString(record.src_name),
	}

	return &event, nil
}

func (auditor *Auditor) processAuditEvent(event string) {
	// AppArmor audit event
	if strings.Contains(event, "type=1400") || strings.Contains(event, "type=AVC") {
		auditor.log.V(2).Info("receive an AppArmor audit event", "event", strings.TrimSpace(event))

		eventForEnforceMode := strings.Contains(event, "apparmor=\"DENIED\"")
		eventForAuditMode := strings.Contains(event, "apparmor=\"AUDIT\"")

		if eventForEnforceMode || eventForAuditMode {
			// Write the violation event into the log file
			index := strings.Index(event, "type=1400 audit")
			if index != -1 {
				event = strings.Replace(event[index:], "type=1400 audit", "type=AVC msg=audit", 1)
			}

			// Call parse_record() of libapparmor.so to parse the event,
			// and convert it to AppArmorEvent object
			e, err := auditor.convertAppArmorEvent(event)
			if err != nil {
				auditor.log.Error(err, "writer.auditor.convertAppArmorEvent() failed")
				return
			}

			// Try to read the process' mnt ns id from the proc filesystem.
			// Note:
			//   This might fail if the process has already been destroyed.
			//   If so, we can't associate container information for violations.
			var mntNsID uint32
			var ok bool
			if mntNsID, ok = auditor.mntNsIDCache[uint32(e.PID)]; !ok {
				mntNsID, _ = varmorutils.ReadMntNsID(uint32(e.PID))
			}

			info := auditor.containerCache[mntNsID]
			auditor.log.V(2).Info("audit event",
				"container id", info.ContainerID,
				"container name", info.ContainerName,
				"pod name", info.PodName,
				"pod namespace", info.PodNamespace,
				"pod uid", info.PodUID,
				"pid", e.PID, "time", int64(e.Epoch), "event", strings.TrimSpace(event))

			if eventForEnforceMode {
				auditor.violationLogger.Warn().
					Str("nodeName", auditor.nodeName).
					Str("containerID", info.ContainerID).
					Str("containerName", info.ContainerName).
					Str("podName", info.PodName).
					Str("podNamespace", info.PodNamespace).
					Str("podUID", info.PodUID).
					Uint32("pid", uint32(e.PID)).
					Uint32("mntNsID", mntNsID).
					Uint64("eventTimestamp", uint64(e.Epoch)).
					Str("eventType", "AppArmor").
					Interface("event", e).Msg("violation event")
			} else {
				auditor.violationLogger.Debug().
					Str("nodeName", auditor.nodeName).
					Str("containerID", info.ContainerID).
					Str("containerName", info.ContainerName).
					Str("podName", info.PodName).
					Str("podNamespace", info.PodNamespace).
					Str("podUID", info.PodUID).
					Uint32("pid", uint32(e.PID)).
					Uint32("mntNsID", mntNsID).
					Uint64("eventTimestamp", uint64(e.Epoch)).
					Str("eventType", "AppArmor").
					Interface("event", e).Msg("violation event")
			}

		} else {
			// Send behavior event to subscribers
			for _, ch := range auditor.auditEventChs {
				ch <- event
			}
		}
	}

	// Seccomp audit event
	if strings.Contains(event, "type=1326") || strings.Contains(event, "type=SECCOMP") {
		auditor.log.V(2).Info("receive a Seccomp audit event", "event", strings.TrimSpace(event))

		// Send behavior event to subscribers
		for _, ch := range auditor.auditEventChs {
			ch <- event
		}
	}
}

func (auditor *Auditor) readFromAuditLogFile() {
	auditor.log.Info("start reading from audit logs", "path", auditor.auditLogPath)

	for line := range auditor.auditLogTail.Lines {
		auditor.processAuditEvent(line.Text)
	}
}

// setRateLimit set the printk_ratelimit to 0 for recording the audit logs of AppArmor and Seccomp.
func (auditor *Auditor) setRateLimit() error {
	rateLimit, err := sysctl_read(ratelimitSysctl)
	if err != nil {
		return err
	}
	auditor.savedRateLimit, err = strconv.ParseUint(rateLimit, 10, 0)
	if err != nil {
		return err
	}
	if auditor.savedRateLimit != 0 {
		return sysctl_write(ratelimitSysctl, 0)
	}
	return nil
}

// restoreRateLimit recover the printk_ratelimit to previous value.
func (auditor *Auditor) restoreRateLimit() error {
	if auditor.savedRateLimit != 0 {
		return sysctl_write(ratelimitSysctl, auditor.savedRateLimit)
	}
	return nil
}
