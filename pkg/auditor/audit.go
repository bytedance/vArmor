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

import (
	"strconv"
	"strings"

	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

func (auditor *Auditor) processAuditEvent(event string) {
	// AppArmor audit event
	if strings.Contains(event, "type=1400") || strings.Contains(event, "type=AVC") {
		auditor.log.V(2).Info("receive an AppArmor audit event", "event", strings.TrimSpace(event))

		// Events of AppArmor profile in the enforce mode
		deniedEvent := strings.Contains(event, "apparmor=\"DENIED\"")
		auditEvent := strings.Contains(event, "apparmor=\"AUDIT\"")
		// Events of AppArmor profile in the complain mode
		allowedEvent := strings.Contains(event, "apparmor=\"ALLOWED\"")

		action := ""
		if deniedEvent {
			action = "DENIED"
		} else if auditEvent || allowedEvent {
			action = "ALLOWED"
		} else {
			return
		}

		// Write the violation event into the log file
		index := strings.Index(event, "type=1400 audit")
		if index != -1 {
			event = strings.Replace(event[index:], "type=1400 audit", "type=AVC msg=audit", 1)
		}

		// Call parse_record() of libapparmor.so to parse the event,
		// and convert it to AppArmorEvent object
		e, err := ParseAppArmorEvent(event)
		if err != nil {
			auditor.log.Error(err, "ParseAppArmorEvent() failed", "event", event)
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
			"pid", e.PID, "time", e.Epoch, "event", strings.TrimSpace(event))

		// Try to parse the AppArmor profile name from the event
		profileName := ParseProfileName(e.Profile)

		if deniedEvent {
			auditor.violationLogger.Warn().
				Interface("metadata", auditor.auditEventMetadata).
				Str("nodeName", auditor.nodeName).
				Str("podUID", info.PodUID).
				Str("podName", info.PodName).
				Str("podNamespace", info.PodNamespace).
				Str("containerID", info.ContainerID).
				Str("containerName", info.ContainerName).
				Uint32("pid", uint32(e.PID)).
				Uint32("mntNsID", mntNsID).
				Uint64("eventTimestamp", uint64(e.Epoch)).
				Str("eventType", "AppArmor").
				Str("action", action).
				Str("profileName", profileName).
				Interface("event", e).Msg("violation event")
		}

		// Only record the allowed event when there is no policy in the BehaviorModeling mode.
		// This can reduce the noise in the violation log.
		if auditEvent || (allowedEvent && len(auditor.auditEventChs) == 0) {
			auditor.violationLogger.Debug().
				Interface("metadata", auditor.auditEventMetadata).
				Str("nodeName", auditor.nodeName).
				Str("podUID", info.PodUID).
				Str("podName", info.PodName).
				Str("podNamespace", info.PodNamespace).
				Str("containerID", info.ContainerID).
				Str("containerName", info.ContainerName).
				Uint32("pid", uint32(e.PID)).
				Uint32("mntNsID", mntNsID).
				Uint64("eventTimestamp", uint64(e.Epoch)).
				Str("eventType", "AppArmor").
				Str("action", action).
				Str("profileName", profileName).
				Interface("event", e).Msg("violation event")
		}

		// Send behavior event to subscribers
		for _, ch := range auditor.auditEventChs {
			ch <- event
		}
	}

	// Seccomp audit event
	if strings.Contains(event, "type=1326") || strings.Contains(event, "type=SECCOMP") {
		auditor.log.V(2).Info("receive a Seccomp audit event", "event", strings.TrimSpace(event))

		action := "ALLOWED"

		// Only record the allowed event when there is no policy in the BehaviorModeling mode.
		// This can reduce the noise in the violation log.
		if len(auditor.auditEventChs) == 0 {
			e, err := ParseSeccompAuditEvent(event)
			if err != nil {
				auditor.log.Error(err, "ParseSeccompAuditEvent() failed", "event", event)
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
				"pid", e.PID, "time", e.Epoch, "event", strings.TrimSpace(event))

			// Try to parse the AppArmor profile name from the event
			// Note:
			// Some systems will output the AppArmor security context of the task in the Subj
			// field of the Seccomp audit event. So people might see the profile name in the
			// Seccomp event if they use both AppArmor and Seccomp enforcer.
			// We can utilize this feature to extract the profile name from the Seccomp event.
			profileName := ParseProfileName(e.Subj)
			if profileName == "" {
				// If the profile name is not found in the event, we can also try to get it from
				// the container cache.
				profileName = info.ProfileName
			}

			auditor.violationLogger.Debug().
				Interface("metadata", auditor.auditEventMetadata).
				Str("nodeName", auditor.nodeName).
				Str("podUID", info.PodUID).
				Str("podName", info.PodName).
				Str("podNamespace", info.PodNamespace).
				Str("containerID", info.ContainerID).
				Str("containerName", info.ContainerName).
				Uint32("pid", uint32(e.PID)).
				Uint32("mntNsID", mntNsID).
				Uint64("eventTimestamp", e.Epoch).
				Str("eventType", "Seccomp").
				Str("action", action).
				Str("profileName", profileName).
				Interface("event", e).Msg("violation event")
		}

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
