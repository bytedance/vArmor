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

package audit

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func (auditor *Auditor) convertBpfEvent(t bpfenforcer.EventType, e interface{}) interface{} {
	switch t {
	case bpfenforcer.CapabilityType:
		event := e.(*bpfenforcer.BpfCapabilityEvent)

		var capability string
		if c, ok := bpfenforcer.CapabilityMap[event.Capability]; ok {
			capability = c
		} else {
			capability = "unknown"
		}

		return &BpfCapabilityEvent{
			Operation:  bpfenforcer.EventTypeMap[t],
			Capability: capability,
		}
	case bpfenforcer.FileType:
		event := e.(*bpfenforcer.BpfPathEvent)

		permissions := []string{}
		for perm, name := range bpfenforcer.PathPermissionMap {
			if perm&event.Permissions == perm {
				permissions = append(permissions, name)
			}
		}

		return &BpfPathEvent{
			Operation:   bpfenforcer.EventTypeMap[t],
			Path:        unix.ByteSliceToString(event.Path[:]),
			Permissions: permissions,
		}
	case bpfenforcer.BprmType:
		event := e.(*bpfenforcer.BpfPathEvent)
		return &BpfPathEvent{
			Operation:   bpfenforcer.EventTypeMap[t],
			Path:        unix.ByteSliceToString(event.Path[:]),
			Permissions: []string{bpfenforcer.PathPermissionMap[event.Permissions]},
		}
	case bpfenforcer.NetworkType:
		event := e.(*bpfenforcer.BpfNetworkEvent)

		switch event.Type {
		case bpfenforcer.SocketType:
			return &BpfNetworkEvent{
				Operation: bpfenforcer.EventTypeMap[t],
				Type:      bpfenforcer.NetworkEventTypeMap[event.Type],
				Socket: BpfNetworkSocket{
					Domain:   bpfenforcer.SocketDomainMap[event.Socket.Domain],
					Type:     bpfenforcer.SocketTypeMap[event.Socket.Type],
					Protocol: bpfenforcer.SocketProtocolMap[event.Socket.Protocol],
				},
			}
		case bpfenforcer.ConnectType:
			var ip string
			if event.Addr.SaFamily == unix.AF_INET {
				ip = net.IPv4(byte(event.Addr.SinAddr), byte(event.Addr.SinAddr>>8), byte(event.Addr.SinAddr>>16), byte(event.Addr.SinAddr>>24)).String()
			} else {
				ip = net.IP(event.Addr.Sin6Addr[:]).String()
			}

			return &BpfNetworkEvent{
				Operation: bpfenforcer.EventTypeMap[t],
				Type:      bpfenforcer.NetworkEventTypeMap[event.Type],
				Address: BpfNetworkSockAddr{
					IP:   ip,
					Port: event.Addr.Port,
				},
			}
		}
		return nil

	case bpfenforcer.PtraceType:
		event := e.(*bpfenforcer.BpfPtraceEvent)

		return &BpfPtraceEvent{
			Operation:  bpfenforcer.EventTypeMap[t],
			Permission: bpfenforcer.PtracePermissionMap[event.Permission],
			External:   event.External,
		}

	case bpfenforcer.MountType:
		event := e.(*bpfenforcer.BpfMountEvent)

		flags := []string{}
		for flag, name := range bpfenforcer.MountFlagsMap {
			if event.Flags&flag != 0 {
				flags = append(flags, name)
			}
		}

		for flag, name := range bpfenforcer.MountBindFlagsMap {
			if event.Flags&flag == flag {
				flags = append(flags, name)
				break
			}
		}

		return &BpfMountEvent{
			Operation: bpfenforcer.EventTypeMap[t],
			Path:      unix.ByteSliceToString(event.Path[:]),
			Type:      unix.ByteSliceToString(event.Type[:]),
			Flags:     flags,
		}
	}
	return nil
}

func (auditor *Auditor) readFromAuditEventRingBuf() {
	rd, err := ringbuf.NewReader(auditor.auditRbMap)
	if err != nil {
		auditor.log.Error(err, "ringbuf.NewReader() failed")
		return
	}

	auditor.log.Info("start reading from bpf ringbuf")

	var eventHeader bpfenforcer.BpfEventHeader
	for {
		// Read audit event from the bpf ringbuf
		record, err := rd.Read()
		if err != nil {
			if err != os.ErrClosed {
				auditor.log.Error(err, "rd.Read() failed")
			}
			break
		}

		auditor.log.V(2).Info("received an BPF audit event", "remaining bytes", record.Remaining)

		// Parse the header of audit event
		if err := binary.Read(bytes.NewBuffer(record.RawSample[:bpfenforcer.EventHeaderSize]), binary.LittleEndian, &eventHeader); err != nil {
			auditor.log.Error(err, "parsing event header failed", "event", record.RawSample)
			continue
		}

		// Process the body of audit event
		var e interface{}
		switch eventHeader.Type {
		case bpfenforcer.CapabilityType:
			// Parse the event body of capability
			var event bpfenforcer.BpfCapabilityEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing capability event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.CapabilityType, &event)
			if e == nil {
				continue
			}

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"capability", e.(*BpfCapabilityEvent).Capability)

		case bpfenforcer.FileType:
			// Parse the event body of file operation
			var event bpfenforcer.BpfPathEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing file operation event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.FileType, &event)
			if e == nil {
				continue
			}

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"path", e.(*BpfPathEvent).Path, "permissions", e.(*BpfPathEvent).Permissions)

		case bpfenforcer.BprmType:
			// Parse the event body of execution file
			var event bpfenforcer.BpfPathEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing execution file event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.BprmType, &event)
			if e == nil {
				continue
			}

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"path", e.(*BpfPathEvent).Path, "permissions", e.(*BpfPathEvent).Permissions)

		case bpfenforcer.NetworkType:
			// Parse the event body of network egress
			var event bpfenforcer.BpfNetworkEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing network egress event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.NetworkType, &event)
			if e == nil {
				continue
			}

			switch event.Type {
			case bpfenforcer.SocketType:
				auditor.log.V(2).Info("audit event",
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"image", auditor.containerCache[eventHeader.MntNs].Image,
					"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
					"domain", e.(*BpfNetworkEvent).Socket.Domain,
					"type", e.(*BpfNetworkEvent).Socket.Type,
					"protocol", e.(*BpfNetworkEvent).Socket.Protocol)
			case bpfenforcer.ConnectType:
				auditor.log.V(2).Info("audit event",
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"image", auditor.containerCache[eventHeader.MntNs].Image,
					"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
					"dest ip", e.(*BpfNetworkEvent).Address.IP, "dest port", e.(*BpfNetworkEvent).Address.Port)
			}

		case bpfenforcer.PtraceType:
			// Parse the event body of ptrace operation
			var event bpfenforcer.BpfPtraceEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing ptrace operation event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.PtraceType, &event)
			if e == nil {
				continue
			}

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"permission", e.(*BpfPtraceEvent).Permission, "external", e.(*BpfPtraceEvent).External)

		case bpfenforcer.MountType:
			// Parse the event body of mount operation
			var event bpfenforcer.BpfMountEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing mount operation event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.MountType, &event)
			if e == nil {
				continue
			}

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"path", e.(*BpfMountEvent).Path,
				"file system type", e.(*BpfMountEvent).Type,
				"flags", e.(*BpfMountEvent).Flags)
		}

		switch eventHeader.Action {
		case bpfenforcer.DeniedAction:
			// Write the violation event that is denied by vArmor into the log file
			auditor.violationLogger.Warn().
				Interface("metadata", auditor.auditEventMetadata).
				Str("nodeName", auditor.nodeName).
				Str("podUID", auditor.containerCache[eventHeader.MntNs].PodUID).
				Str("podName", auditor.containerCache[eventHeader.MntNs].PodName).
				Str("podNamespace", auditor.containerCache[eventHeader.MntNs].PodNamespace).
				Str("containerID", auditor.containerCache[eventHeader.MntNs].ContainerID).
				Str("containerName", auditor.containerCache[eventHeader.MntNs].ContainerName).
				Str("image", auditor.containerCache[eventHeader.MntNs].Image).
				Uint32("pid", eventHeader.Tgid).
				Uint32("mntNsID", eventHeader.MntNs).
				Uint64("eventTimestamp", eventHeader.Ktime/uint64(time.Second)+auditor.bootTimestamp).
				Str("enforcer", "BPF").
				Str("action", "DENIED").
				Str("profileName", auditor.containerCache[eventHeader.MntNs].ProfileName).
				Interface("event", e).Msg("violation event")

		case bpfenforcer.AuditAction:
			// Write the violation event into the log file
			auditor.violationLogger.Debug().
				Interface("metadata", auditor.auditEventMetadata).
				Str("nodeName", auditor.nodeName).
				Str("podUID", auditor.containerCache[eventHeader.MntNs].PodUID).
				Str("podName", auditor.containerCache[eventHeader.MntNs].PodName).
				Str("podNamespace", auditor.containerCache[eventHeader.MntNs].PodNamespace).
				Str("containerID", auditor.containerCache[eventHeader.MntNs].ContainerID).
				Str("containerName", auditor.containerCache[eventHeader.MntNs].ContainerName).
				Str("image", auditor.containerCache[eventHeader.MntNs].Image).
				Uint32("pid", eventHeader.Tgid).
				Uint32("mntNsID", eventHeader.MntNs).
				Uint64("eventTimestamp", eventHeader.Ktime/uint64(time.Second)+auditor.bootTimestamp).
				Str("enforcer", "BPF").
				Str("action", "AUDIT").
				Str("profileName", auditor.containerCache[eventHeader.MntNs].ProfileName).
				Interface("event", e).Msg("violation event")

		case bpfenforcer.AllowedAction:
			// Send behavior event to the corresponding subscriber
			profileName := auditor.containerCache[eventHeader.MntNs].ProfileName
			if ch, ok := auditor.bpfEventChs[profileName]; ok {
				ch <- BpfEvent{
					Header: BpfEventHeader{
						Action: bpfenforcer.EnforcementActionMap[eventHeader.Action],
						Type:   bpfenforcer.EventTypeMap[eventHeader.Type],
						MntNs:  eventHeader.MntNs,
						Tgid:   eventHeader.Tgid,
						Ktime:  eventHeader.Ktime,
					},
					Body: e,
				}
			}
		}
	}
}
