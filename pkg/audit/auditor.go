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
	"time"

	"github.com/cilium/ebpf"
	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/go-logr/logr"

	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

type Auditor struct {
	appArmorSupported    bool
	bpfLsmSupported      bool
	journalReader        *sdjournal.JournalReader
	journalReaderTimeout chan time.Time
	auditRbMap           *ebpf.Map
	TaskStartCh          chan varmortypes.ContainerInfo
	TaskDeleteCh         chan varmortypes.ContainerInfo
	TaskDeleteSyncCh     chan bool
	mntNsIDCache         map[uint32]uint32                    // key: The init PID of contaienr
	containerCache       map[uint32]varmortypes.ContainerInfo // key: The mnt ns id of container
	log                  logr.Logger
}

// NewAuditor creates an auditor to audit the violations of target containers
func NewAuditor(appArmorSupported, bpfLsmSupported bool, log logr.Logger) (*Auditor, error) {
	auditor := Auditor{
		appArmorSupported: appArmorSupported,
		bpfLsmSupported:   bpfLsmSupported,
		TaskStartCh:       make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteCh:      make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteSyncCh:  make(chan bool, 1),
		mntNsIDCache:      make(map[uint32]uint32, 100),
		containerCache:    make(map[uint32]varmortypes.ContainerInfo, 100),
		log:               log,
	}

	if appArmorSupported {
		r, err := sdjournal.NewJournalReader(sdjournal.JournalReaderConfig{
			Since: time.Duration(-5) * time.Second,
			Matches: []sdjournal.Match{
				{
					Field: sdjournal.SD_JOURNAL_FIELD_TRANSPORT,
					Value: "kernel",
				},
			}})
		if err != nil {
			return nil, err
		}
		auditor.journalReader = r
		auditor.journalReaderTimeout = make(chan time.Time)
	}

	if bpfLsmSupported {
		m, err := ebpf.LoadPinnedMap(bpfenforcer.AuditRingBufPinPath, nil)
		if err != nil {
			return nil, err
		}
		auditor.auditRbMap = m
	}

	return &auditor, nil
}

func (auditor *Auditor) eventHandler(stopCh <-chan struct{}) {
	logger := auditor.log.WithName("eventHandler()")
	logger.Info("start handling the containerd events")

	for {
		select {
		case info := <-auditor.TaskStartCh:
			// Handle the creation event of target container
			auditor.log.Info("auditor.TaskStartCh", "info", info)
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
			logger.Info("stop handling the containerd events")
			return
		}
	}
}

func (auditor *Auditor) Run(stopCh <-chan struct{}) {
	if auditor.appArmorSupported {
		go auditor.readFromSystemdJournald()
	}
	if auditor.bpfLsmSupported {
		go auditor.readFromAuditEventRingBuf()
	}
	auditor.eventHandler(stopCh)
}

func (auditor *Auditor) Close() {
	if auditor.appArmorSupported {
		auditor.journalReaderTimeout <- time.Now()
		auditor.journalReader.Close()
	}
	if auditor.bpfLsmSupported {
		auditor.auditRbMap.Close()
	}
}
