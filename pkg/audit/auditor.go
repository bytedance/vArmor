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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-logr/logr"

	"golang.org/x/sys/unix"

	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

type Auditor struct {
	auditRbMap       *ebpf.Map
	TaskCreateCh     chan varmortypes.ContainerInfo
	TaskDeleteCh     chan varmortypes.ContainerInfo
	TaskDeleteSyncCh chan bool
	mntNsIDCache     map[uint32]uint32                    // key: The init PID of contaienr
	containerCache   map[uint32]varmortypes.ContainerInfo // key: The mnt ns id of container
	log              logr.Logger
}

// NewAuditor creates an auditor to audit the violations of target containers
func NewAuditor(log logr.Logger) (*Auditor, error) {
	m, err := ebpf.LoadPinnedMap(bpfenforcer.AuditRingBufPinPath, nil)
	if err != nil {
		return nil, err
	}

	auditor := Auditor{
		auditRbMap:       m,
		TaskCreateCh:     make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteCh:     make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteSyncCh: make(chan bool, 1),
		mntNsIDCache:     make(map[uint32]uint32, 100),
		containerCache:   make(map[uint32]varmortypes.ContainerInfo, 100),
		log:              log,
	}
	return &auditor, nil
}

func (auditor *Auditor) Run(stopCh <-chan struct{}) {
	go auditor.eventHandler(stopCh)
	auditor.readFromAuditEventRingBuf()
}

func (auditor *Auditor) Close() {
	auditor.auditRbMap.Close()
}

func (auditor *Auditor) eventHandler(stopCh <-chan struct{}) {
	logger := auditor.log.WithName("eventHandler()")
	logger.Info("start handle the containerd events")

	for {
		select {
		case info := <-auditor.TaskCreateCh:
			// Handle the creation event of target container
			auditor.mntNsIDCache[info.PID] = info.MntNsID
			auditor.containerCache[info.MntNsID] = info
		case info := <-auditor.TaskDeleteCh:
			// Handle the deletion event of target container
			if mntNsID, ok := auditor.mntNsIDCache[info.PID]; ok {
				delete(auditor.containerCache, mntNsID)
				delete(auditor.mntNsIDCache, info.PID)
			}
		case <-auditor.TaskDeleteSyncCh:
			// Handle those containers that exit while the monitor was offline
			for pid, mntNsID := range auditor.mntNsIDCache {
				id, err := varmorutils.ReadMntNsID(pid)
				if err != nil || mntNsID != id {
					// maybe the container had already exited
					logger.Info("the target container exited while the monitor was offline",
						"container id", auditor.containerCache[mntNsID].ContainerID,
						"container name", auditor.containerCache[mntNsID].ContainerName,
						"pod name", auditor.containerCache[mntNsID].PodName,
						"pod namespace", auditor.containerCache[mntNsID].PodNamespace,
						"pod uid", auditor.containerCache[mntNsID].PodUID,
						"pid", auditor.containerCache[mntNsID].PID)
					delete(auditor.containerCache, mntNsID)
					delete(auditor.mntNsIDCache, pid)
				}
			}
		case <-stopCh:
			logger.Info("stop handle the containerd events")
			return
		}
	}
}

func (auditor *Auditor) readFromAuditEventRingBuf() {
	rd, err := ringbuf.NewReader(auditor.auditRbMap)
	if err != nil {
		auditor.log.Error(err, "ringbuf.NewReader() failed")
		return
	}

	auditor.log.V(1).Info("waiting for audit events...")

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
		auditor.log.V(3).Info("read success", "remaining bytes", record.Remaining)

		// Parse the header of audit event
		if err := binary.Read(bytes.NewBuffer(record.RawSample[:bpfenforcer.EventHeaderSize]), binary.LittleEndian, &eventHeader); err != nil {
			auditor.log.Error(err, "parsing event header failed", "event", record.RawSample)
			continue
		}

		// Process the body of audit event
		if eventHeader.Mode == bpfenforcer.AuditMode {
			switch eventHeader.Type {
			case bpfenforcer.CapabilityType:
				// Parse the event body of capability
				var event bpfenforcer.BpfCapabilityEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					auditor.log.Error(err, "parsing capability event failed", "event", record.RawSample)
					continue
				}

				auditor.log.V(3).Info("audit event",
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
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

				auditor.log.V(3).Info("audit event",
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
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

				auditor.log.V(3).Info("audit event",
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
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

				var ip net.IP
				if event.SaFamily == unix.AF_INET {
					ip = net.IPv4(byte(event.SinAddr), byte(event.SinAddr>>8), byte(event.SinAddr>>16), byte(event.SinAddr>>24))
				} else {
					ip = net.IP(event.Sin6Addr[:])
				}
				auditor.log.V(3).Info("audit event",
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
					"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
					"address", ip.String(), "port", event.Port)

			case bpfenforcer.PtraceType:
				// Parse the event body of ptrace operation
				var event bpfenforcer.BpfPtraceEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[bpfenforcer.EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					auditor.log.Error(err, "parsing ptrace operation event failed", "event", record.RawSample)
					continue
				}

				auditor.log.V(3).Info("audit event",
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
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

				auditor.log.V(3).Info("audit event",
					"container id", auditor.containerCache[eventHeader.MntNs].ContainerID,
					"container name", auditor.containerCache[eventHeader.MntNs].ContainerName,
					"pod name", auditor.containerCache[eventHeader.MntNs].PodName,
					"pod namespace", auditor.containerCache[eventHeader.MntNs].PodNamespace,
					"pod uid", auditor.containerCache[eventHeader.MntNs].PodUID,
					"pid", eventHeader.Tgid, "ktime", eventHeader.Ktime, "mnt ns", eventHeader.MntNs,
					"Device Name:", unix.ByteSliceToString(event.DevName[:]),
					"FileSystem Type:", unix.ByteSliceToString(event.Type[:]), "Flags:", event.Flags)
			}
		}
	}
}
