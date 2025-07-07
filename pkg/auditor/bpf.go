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
		object := BpfCapabilityEvent{}

		if c, ok := auditor.capabilityMap[event.Capability]; ok {
			object.Capability = c
		} else {
			object.Capability = "unknown"
		}

		return &object

	case bpfenforcer.FileType, bpfenforcer.BprmType:
		event := e.(*bpfenforcer.BpfPathEvent)

		object := BpfPathEvent{
			Path: unix.ByteSliceToString(event.Path[:]),
		}

		for k, v := range auditor.filePermissionMap {
			if k&event.Permissions == k {
				object.Permissions = append(object.Permissions, v)
			}
		}

		return &object

	case bpfenforcer.NetworkType:
		event := e.(*bpfenforcer.BpfNetworkEvent)

		switch event.Type {
		case bpfenforcer.SocketType:
			return &BpfNetworkCreateEvent{
				Domain:   event.Socket.Domain,
				Type:     event.Socket.Type,
				Protocol: event.Socket.Protocol,
			}
		case bpfenforcer.ConnectType:
			object := BpfNetworkConnectEvent{
				Port: int(event.Addr.Port),
			}

			if event.Addr.SaFamily == unix.AF_INET {
				object.IP = net.IPv4(byte(event.Addr.SinAddr), byte(event.Addr.SinAddr>>8), byte(event.Addr.SinAddr>>16), byte(event.Addr.SinAddr>>24)).String()
			} else {
				object.IP = net.IP(event.Addr.Sin6Addr[:]).String()
			}
			return &object
		}
		return nil

	case bpfenforcer.PtraceType:
		event := e.(*bpfenforcer.BpfPtraceEvent)

		object := BpfPtraceEvent{
			External: event.External,
		}

		if p, ok := auditor.ptracePermissionMap[event.Permissions]; ok {
			object.Permissions = append(object.Permissions, p)
		} else {
			object.Permissions = append(object.Permissions, "unknown")
		}

		return &object

	case bpfenforcer.MountType:
		event := e.(*bpfenforcer.BpfMountEvent)

		object := BpfMountEvent{
			DevName: unix.ByteSliceToString(event.DevName[:]),
			Type:    unix.ByteSliceToString(event.Type[:]),
		}

		for k, v := range auditor.mountFlagMap {
			if k&event.Flags == k {
				object.Flags = append(object.Flags, v)
			}
		}

		return &object
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

		auditor.log.V(2).Info("receive an BPF audit event", "remaining bytes", record.Remaining)

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

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"capability", event.Capability)

		case bpfenforcer.FileType:
			// Parse the event body of file operation
			var event bpfenforcer.BpfPathEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing file operation event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.FileType, &event)

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"path", unix.ByteSliceToString(event.Path[:]), "permissions", event.Permissions)

		case bpfenforcer.BprmType:
			// Parse the event body of execution file
			var event bpfenforcer.BpfPathEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing execution file event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.BprmType, &event)

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"path", unix.ByteSliceToString(event.Path[:]), "permissions", event.Permissions)

		case bpfenforcer.NetworkType:
			// Parse the event body of network egress
			var event bpfenforcer.BpfNetworkEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing network egress event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.NetworkType, &event)

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
					"domain", e.(*BpfNetworkCreateEvent).Domain,
					"type", e.(*BpfNetworkCreateEvent).Type,
					"protocol", e.(*BpfNetworkCreateEvent).Protocol)
			case bpfenforcer.ConnectType:
				auditor.log.V(2).Info("audit event",
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"image", auditor.containerCache[eventHeader.MntNs].Image,
					"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
					"address", e.(*BpfNetworkConnectEvent).IP, "port", e.(*BpfNetworkConnectEvent).Port)
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

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"permissions", event.Permissions, "externel", event.External)

		case bpfenforcer.MountType:
			// Parse the event body of mount operation
			var event bpfenforcer.BpfMountEvent
			err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
			if err != nil {
				auditor.log.Error(err, "parsing mount operation event failed", "event", record.RawSample)
				continue
			}

			e = auditor.convertBpfEvent(bpfenforcer.MountType, &event)

			auditor.log.V(2).Info("audit event",
				"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
				"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
				"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
				"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
				"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
				"image", auditor.containerCache[eventHeader.MntNs].Image,
				"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
				"Device Name:", unix.ByteSliceToString(event.DevName[:]),
				"FileSystem Type:", unix.ByteSliceToString(event.Type[:]), "Flags:", event.Flags)
		}

		switch eventHeader.Mode {
		case bpfenforcer.EnforceMode | bpfenforcer.AuditMode:
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
				Str("eventType", "BPF").
				Str("action", "DENIED").
				Str("profileName", auditor.containerCache[eventHeader.MntNs].ProfileName).
				Interface("event", e).Msg("violation event")

		case bpfenforcer.AuditMode:
			// Write the violation event into log the file
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
				Str("eventType", "BPF").
				Str("action", "ALLOWED").
				Str("profileName", auditor.containerCache[eventHeader.MntNs].ProfileName).
				Interface("event", e).Msg("violation event")

		case bpfenforcer.ComplainMode:
			// Send behavior event to subscribers
			for _, ch := range auditor.bpfEventChs {
				ch <- bpfenforcer.BpfEvent{
					Header: eventHeader,
					Body:   e,
				}
			}
		}
	}
}
