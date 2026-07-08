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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
	"github.com/nxadm/tail"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
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
	// cacheMu guards mntNsIDCache and containerCache. They are written only
	// by eventHandler on the containerd-event goroutine, but read from the
	// audit-log tail goroutine (processAuditEvent) and the BPF ringbuf
	// goroutine (readFromAuditEventRingBuf), so every access must hold this
	// lock to avoid a data race.
	cacheMu sync.RWMutex
	// policyIdentityCache maps an ArmorProfile name to the authoritative
	// identity of the VarmorPolicy/VarmorClusterPolicy that owns it. It is
	// written by the agent from its ArmorProfile watch and read by every
	// violation emission path, so it is guarded by policyIdentityMu.
	policyIdentityCache map[string]PolicyIdentity // key: profile name
	policyIdentityMu    sync.RWMutex
	// chsMu guards auditEventChs and bpfEventChs. They are mutated by
	// BehaviorModeller.Run/stop on the modeller goroutine when subscribers
	// are dynamically added/removed, but read from the audit-log tail
	// goroutine (processAuditEvent) and the BPF ringbuf goroutine
	// (readFromAuditEventRingBuf), so every access must hold this lock to
	// avoid a concurrent map read/write fatal error.
	chsMu              sync.RWMutex
	auditEventChs      map[string]chan<- string   // auditEventChs used for sending apparmor & seccomp behavior event to subscribers, key: profile name, value: audit event channel
	bpfEventChs        map[string]chan<- BpfEvent // bpfEventChs used for sending bpf behavior event to subscribers, key: profile name, value: bpf event channel
	auditLogPath       string
	auditLogTail       *tail.Tail
	savedRateLimit     uint64
	auditRbMap         *ebpf.Map
	auditEventMetadata map[string]interface{} // auditEventMetadata used for storing additional information of the violation event
	violationLogger    zerolog.Logger
	// alsSocketPath is the host-side UDS path the NetworkProxy ALS gRPC
	// server listens on. It is injected by the caller (the agent); an empty
	// path disables the ALS collector.
	alsSocketPath string
	alsListener   net.Listener
	alsServer     *grpc.Server
	// alsWg tracks the ALS serve goroutine so Close can wait for it to
	// return after the gRPC server is stopped.
	alsWg sync.WaitGroup
	log   logr.Logger
}

// NewAuditor creates an auditor to audit the violations of target containers
func NewAuditor(nodeName string, appArmorSupported, bpfLsmSupported, enableBehaviorModeling bool, auditLogPaths string, alsSocketPath string, auditEventMetadata map[string]interface{}, log logr.Logger) (*Auditor, error) {
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
		policyIdentityCache:    make(map[string]PolicyIdentity),
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

	// Enable the NetworkProxy ALS collector: violations always stream over
	// gRPC ALS, so the auditor listens on the caller-provided UDS socket path.
	auditor.alsSocketPath = alsSocketPath

	return &auditor, nil
}

func (auditor *Auditor) eventHandler(stopCh <-chan struct{}) {
	logger := auditor.log.WithName("eventHandler()")
	logger.Info("start handling the containerd events")

	for {
		select {
		case info := <-auditor.TaskStartCh:
			// Handle the creation event of target container
			auditor.cacheMu.Lock()
			auditor.mntNsIDCache[info.PID] = info.MntNsID
			auditor.containerCache[info.MntNsID] = info
			auditor.cacheMu.Unlock()
		case info := <-auditor.TaskDeleteCh:
			// Handle the deletion event of target container
			auditor.cacheMu.Lock()
			if mntNsID, ok := auditor.mntNsIDCache[info.PID]; ok {
				delete(auditor.containerCache, mntNsID)
				delete(auditor.mntNsIDCache, info.PID)
			}
			auditor.cacheMu.Unlock()
		case <-auditor.TaskDeleteSyncCh:
			// Handle those containers that exit while the monitor was offline
			auditor.cacheMu.Lock()
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
			auditor.cacheMu.Unlock()
		case <-stopCh:
			logger.Info("stop handling the containerd events")
			return
		}
	}
}

// containerByMntNsID returns the cached container information for the given
// mnt namespace id. containerCache is written by eventHandler on the
// containerd-event goroutine and read here from the audit-log tail and BPF
// ringbuf goroutines, so access is guarded by cacheMu. A miss returns the
// zero ContainerInfo (attribution is best-effort). Safe for concurrent use.
func (auditor *Auditor) containerByMntNsID(mntNsID uint32) varmortypes.ContainerInfo {
	auditor.cacheMu.RLock()
	defer auditor.cacheMu.RUnlock()
	return auditor.containerCache[mntNsID]
}

// mntNsIDByPID returns the cached mnt namespace id for the given container
// init PID. The boolean reports whether an entry was found. Safe for
// concurrent use.
func (auditor *Auditor) mntNsIDByPID(pid uint32) (uint32, bool) {
	auditor.cacheMu.RLock()
	defer auditor.cacheMu.RUnlock()
	id, ok := auditor.mntNsIDCache[pid]
	return id, ok
}

// auditEventChByProfile returns the audit-event channel registered for the
// given profile and whether one exists. Guarded by chsMu so it is safe to
// call from the audit-log tail and BPF ringbuf goroutines concurrently with
// AddBehaviorEventNotifyChs/DeleteBehaviorEventNotifyCh. The channel is
// returned by value so the caller can send on it after releasing the lock.
func (auditor *Auditor) auditEventChByProfile(profileName string) (chan<- string, bool) {
	auditor.chsMu.RLock()
	defer auditor.chsMu.RUnlock()
	ch, ok := auditor.auditEventChs[profileName]
	return ch, ok
}

// bpfEventChByProfile returns the bpf-event channel registered for the given
// profile and whether one exists. Guarded by chsMu. Safe for concurrent use.
func (auditor *Auditor) bpfEventChByProfile(profileName string) (chan<- BpfEvent, bool) {
	auditor.chsMu.RLock()
	defer auditor.chsMu.RUnlock()
	ch, ok := auditor.bpfEventChs[profileName]
	return ch, ok
}

// snapshotAuditEventChs returns a snapshot of all registered audit-event
// channels taken under chsMu. Callers broadcast to the returned slice after
// releasing the lock so a blocking send never stalls subscriber updates.
func (auditor *Auditor) snapshotAuditEventChs() []chan<- string {
	auditor.chsMu.RLock()
	defer auditor.chsMu.RUnlock()
	chs := make([]chan<- string, 0, len(auditor.auditEventChs))
	for _, ch := range auditor.auditEventChs {
		chs = append(chs, ch)
	}
	return chs
}

// AddBehaviorEventNotifyChs add the audit event channel and bpf event channel for the subscriber
// The subscriber parameter is the name of profile
func (auditor *Auditor) AddBehaviorEventNotifyChs(subscriber string, auditEventCh *chan string, bpfEventCh *chan BpfEvent) {
	auditor.chsMu.Lock()
	if bpfEventCh != nil {
		auditor.bpfEventChs[subscriber] = *bpfEventCh
	}
	if auditEventCh != nil {
		auditor.auditEventChs[subscriber] = *auditEventCh
	}
	auditEventChCount := len(auditor.auditEventChs)
	auditor.chsMu.Unlock()

	if auditEventChCount == 1 {
		err := auditor.setRateLimit()
		if err != nil {
			auditor.log.Error(err, "auditor.setRateLimit()")
		}
	}
}

// DeleteBehaviorEventNotifyCh delete the audit event channel and bpf event channel for the subscriber
// The subscriber parameter is the name of profile
func (auditor *Auditor) DeleteBehaviorEventNotifyCh(subscriber string) {
	auditor.chsMu.Lock()
	delete(auditor.bpfEventChs, subscriber)
	delete(auditor.auditEventChs, subscriber)
	auditEventChCount := len(auditor.auditEventChs)
	auditor.chsMu.Unlock()

	if auditEventChCount == 0 {
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
	auditor.startALSConsumer()
	auditor.eventHandler(stopCh)
}

func (auditor *Auditor) Close() {
	auditor.closeALSConsumer()
	if auditor.appArmorSupported || auditor.enableBehaviorModeling {
		auditor.auditLogTail.Stop()
		auditor.auditLogTail.Cleanup()
	}
	if auditor.bpfLsmSupported {
		auditor.auditRbMap.Close()
	}
}
