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

// Package audit is used to audit the violations of target containers, and
// send the audit event to subscribers.
package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
	"github.com/nxadm/tail"
	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"

	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

const (
	logDirectory    = "/var/log/varmor"
	ratelimitSysctl = "/proc/sys/kernel/printk_ratelimit"
)

type Auditor struct {
	nodeName               string
	bootTimestamp          uint64
	appArmorSupported      bool
	bpfLsmSupported        bool
	enableBehaviorModeling bool
	TaskStartCh            chan varmortypes.ContainerInfo
	TaskDeleteCh           chan varmortypes.ContainerInfo
	TaskDeleteSyncCh       chan bool
	mntNsIDCache           map[uint32]uint32                    // key: The init PID of contaienr, value: The mnt ns id
	containerCache         map[uint32]varmortypes.ContainerInfo // key: The mnt ns id of container, value: The container information
	auditEventChs          map[string]chan<- string             // auditEventChs used for sending apparmor & seccomp behavior event to subscribers, key: profile name, value: audit event channel
	bpfEventChs            map[string]chan<- BpfEvent           // bpfEventChs used for sending bpf behavior event to subscribers, key: profile name, value: bpf event channel
	auditLogPath           string
	auditLogTail           *tail.Tail
	savedRateLimit         uint64
	auditRbMap             *ebpf.Map
	auditEventMetadata     map[string]interface{} // auditEventMetadata used for storing additional information of the violation event
	violationLogger        zerolog.Logger
	log                    logr.Logger
}

// NewAuditor creates an auditor to audit the violations of target containers
func NewAuditor(nodeName string, appArmorSupported, bpfLsmSupported, enableBehaviorModeling bool, auditLogPaths string, auditEventMetadata map[string]interface{}, log logr.Logger) (*Auditor, error) {
	auditor := Auditor{
		nodeName:               nodeName,
		appArmorSupported:      appArmorSupported,
		bpfLsmSupported:        bpfLsmSupported,
		enableBehaviorModeling: enableBehaviorModeling,
		TaskStartCh:            make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteCh:           make(chan varmortypes.ContainerInfo, 100),
		TaskDeleteSyncCh:       make(chan bool, 1),
		mntNsIDCache:           make(map[uint32]uint32, 100),
		containerCache:         make(map[uint32]varmortypes.ContainerInfo, 100),
		auditEventChs:          make(map[string]chan<- string),
		bpfEventChs:            make(map[string]chan<- BpfEvent),
		savedRateLimit:         0,
		auditEventMetadata:     auditEventMetadata,
		log:                    log,
	}

	// Create a tail reader to read the audit events
	if appArmorSupported || enableBehaviorModeling {
		for _, path := range strings.Split(auditLogPaths, "|") {
			_, err := os.Stat(path)
			if err == nil {
				auditor.auditLogPath = path
				break
			}
		}
		if auditor.auditLogPath == "" {
			return nil, fmt.Errorf("please use --auditLogPaths command line parameter to specify the correct file paths that stores the audit logs for AppArmor and Seccomp")
		}
		t, err := tail.TailFile(auditor.auditLogPath,
			tail.Config{
				Location:      &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
				ReOpen:        true,
				Follow:        true,
				CompleteLines: true,
			})
		if err != nil {
			return nil, err
		}
		auditor.auditLogTail = t
		auditor.log.Info("start tailing audit log", "path", auditor.auditLogPath)
	}

	// Load the ringbuf map of BPF enforcer
	if bpfLsmSupported {
		m, err := ebpf.LoadPinnedMap(bpfenforcer.AuditRingBufPinPath, nil)
		if err != nil {
			return nil, err
		}
		auditor.auditRbMap = m
	}

	// Retrieve the boot timestamp of host
	btime, err := readBootTime()
	if err != nil {
		return nil, err
	}
	auditor.bootTimestamp = btime

	// Initialize the log file for saving the violation events
	if err := os.MkdirAll(logDirectory, os.ModePerm); err != nil {
		return nil, err
	}
	auditor.violationLogger = zerolog.New(&lumberjack.Logger{
		Filename:   filepath.Join(logDirectory, "violations.log"),
		MaxSize:    10,
		MaxBackups: 3,
	}).With().Timestamp().Logger()

	return &auditor, nil
}

func (auditor *Auditor) eventHandler(stopCh <-chan struct{}) {
	logger := auditor.log.WithName("eventHandler()")
	logger.Info("start handling the containerd events")

	for {
		select {
		case info := <-auditor.TaskStartCh:
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
			logger.Info("stop handling the containerd events")
			return
		}
	}
}

// AddBehaviorEventNotifyChs add the audit event channel and bpf event channel for the subscriber
// The subscriber parameter is the name of profile
func (auditor *Auditor) AddBehaviorEventNotifyChs(subscriber string, auditEventCh *chan string, bpfEventCh *chan BpfEvent) {
	if bpfEventCh != nil {
		auditor.bpfEventChs[subscriber] = *bpfEventCh
	}
	if auditEventCh != nil {
		auditor.auditEventChs[subscriber] = *auditEventCh
	}

	if len(auditor.auditEventChs) == 1 {
		err := auditor.setRateLimit()
		if err != nil {
			auditor.log.Error(err, "auditor.setRateLimit()")
		}
	}
}

// DeleteBehaviorEventNotifyCh delete the audit event channel and bpf event channel for the subscriber
// The subscriber parameter is the name of profile
func (auditor *Auditor) DeleteBehaviorEventNotifyCh(subscriber string) {
	delete(auditor.bpfEventChs, subscriber)
	delete(auditor.auditEventChs, subscriber)

	if len(auditor.auditEventChs) == 0 {
		err := auditor.restoreRateLimit()
		if err != nil {
			auditor.log.Error(err, "auditor.restoreRateLimit()")
		}
	}
}

func (auditor *Auditor) Run(stopCh <-chan struct{}) {
	if auditor.appArmorSupported || auditor.enableBehaviorModeling {
		go auditor.readFromAuditLogFile()
	}
	if auditor.bpfLsmSupported {
		go auditor.readFromAuditEventRingBuf()
	}
	auditor.eventHandler(stopCh)
}

func (auditor *Auditor) Close() {
	if auditor.appArmorSupported || auditor.enableBehaviorModeling {
		auditor.auditLogTail.Stop()
		auditor.auditLogTail.Cleanup()
	}
	if auditor.bpfLsmSupported {
		auditor.auditRbMap.Close()
	}
}
