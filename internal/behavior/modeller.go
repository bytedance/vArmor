// Copyright 2022 vArmor Authors
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

// Package behavior is used to process the behavior data of targets
package behavior

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"

	varmorpreprocessor "github.com/bytedance/vArmor/internal/behavior/preprocessor"
	varmorrecorder "github.com/bytedance/vArmor/internal/behavior/recorder"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
	varmorptracer "github.com/bytedance/vArmor/pkg/processtracer"
	varmormonitor "github.com/bytedance/vArmor/pkg/runtime"
	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

type BehaviorModeller struct {
	auditor         *varmorauditor.Auditor
	ptracer         *varmorptracer.ProcessTracer
	monitor         *varmormonitor.RuntimeMonitor
	nodeName        string
	namespace       string // namespace of the ArmorProfile
	name            string // name of the ArmorProfile (profile name)
	enforcer        string
	startTime       time.Time
	duration        time.Duration
	modeling        bool
	TaskStartCh     chan varmortypes.ContainerInfo
	targetPIDs      map[uint32]struct{}
	targetMnts      map[uint32]struct{}
	auditRecorder   *varmorrecorder.AuditRecorder
	processRecorder *varmorrecorder.ProcessRecorder
	ModellerStopCh  chan bool
	stopCh          <-chan struct{}
	svcAddresses    map[string]string
	debug           bool
	inContainer     bool
	log             logr.Logger
}

func NewBehaviorModeller(
	auditor *varmorauditor.Auditor,
	ptracer *varmorptracer.ProcessTracer,
	monitor *varmormonitor.RuntimeMonitor,
	nodeName string,
	namespace string,
	name string,
	enforcer string,
	startTime time.Time,
	duration time.Duration,
	stopCh <-chan struct{},
	svcAddresses map[string]string,
	debug bool,
	inContainer bool,
	log logr.Logger) *BehaviorModeller {

	log.Info("create a behavior modeller", "start time", startTime,
		"duration", duration.String(), "profile name", name)

	return &BehaviorModeller{
		auditor:         auditor,
		ptracer:         ptracer,
		monitor:         monitor,
		nodeName:        nodeName,
		namespace:       namespace,
		name:            name,
		enforcer:        enforcer,
		startTime:       startTime,
		duration:        duration,
		modeling:        false,
		TaskStartCh:     make(chan varmortypes.ContainerInfo, 100),
		targetPIDs:      make(map[uint32]struct{}, 500),
		targetMnts:      make(map[uint32]struct{}, 30),
		auditRecorder:   varmorrecorder.NewAuditRecorder(varmorconfig.AuditDataDirectory, name, stopCh, debug, log.WithName("AUDIT-RECORDER")),
		processRecorder: varmorrecorder.NewProcessRecorder(varmorconfig.AuditDataDirectory, name, stopCh, debug, log.WithName("BPF-RECORDER")),
		ModellerStopCh:  make(chan bool, 1),
		stopCh:          stopCh,
		svcAddresses:    svcAddresses,
		debug:           debug,
		inContainer:     inContainer,
		log:             log,
	}
}

func (modeller *BehaviorModeller) PreprocessAndSendBehaviorData() {
	preprocessor := varmorpreprocessor.NewDataPreprocessor(
		modeller.nodeName,
		modeller.namespace,
		varmorconfig.AuditDataDirectory,
		modeller.name,
		modeller.enforcer,
		modeller.targetPIDs,
		modeller.targetMnts,
		modeller.svcAddresses,
		modeller.debug,
		modeller.inContainer,
		modeller.log.WithName("DATA-PREPROCESSOR"))
	if preprocessor == nil {
		return
	}

	data := preprocessor.Process()
	if data != nil {
		modeller.log.Info("send preprocess result to manager")
		address := modeller.svcAddresses[varmorconfig.StatusServiceName]
		err := varmorutils.HTTPSPostWithRetryAndToken(address, varmorconfig.DataSyncPath, data, modeller.inContainer)
		if err != nil {
			modeller.log.Error(err, "HTTPSPostWithRetryAndToken() failed")
		}
	}
}

func (modeller *BehaviorModeller) UpdateDuration(duration time.Duration) {
	modeller.log.Info("update the duration of behavior modeller",
		"start time", modeller.startTime,
		"old duration", modeller.duration.String(),
		"new duration", duration.String(),
		"profile name", modeller.name)

	modeller.duration = duration
}

func (modeller *BehaviorModeller) IsModeling() bool {
	return modeller.modeling
}

func (modeller *BehaviorModeller) shouldCacheContainer(info varmortypes.ContainerInfo) bool {
	keys := []string{
		fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", info.ContainerName),
		fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", info.ContainerName),
		fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", info.ContainerName),
	}
	for _, key := range keys {
		if value, ok := info.PodAnnotations[key]; ok {
			if strings.HasPrefix(value, "localhost/") {
				profileName := value[len("localhost/"):]
				if profileName == modeller.name {
					return true
				}
			}
		}
	}
	return false
}

func (modeller *BehaviorModeller) eventHandler() {
	stopAndCleanup := func() {
		modeller.stop()
		modeller.auditRecorder.Close()
		modeller.auditRecorder.CleanUp()
		modeller.processRecorder.Close()
		modeller.processRecorder.CleanUp()
		modeller.log.Info("behavioral data collection is stopped", "profile name", modeller.name)
	}

	ticker := time.NewTicker(30 * time.Second)

	for {
		select {
		case <-ticker.C:
			if time.Now().After(modeller.startTime.Add(modeller.duration)) {
				modeller.log.Info("behavioral data collection is completed",
					"profile name", modeller.name,
					"start time", modeller.startTime,
					"duration", modeller.duration.String(),
					"target pids", modeller.targetPIDs,
					"target mnts", modeller.targetMnts,
				)
				modeller.stop()
				modeller.auditRecorder.Close()
				modeller.processRecorder.Close()

				// Sync data to manager after modeling completed.
				modeller.PreprocessAndSendBehaviorData()
				modeller.targetPIDs = make(map[uint32]struct{}, 0)
				modeller.targetMnts = make(map[uint32]struct{}, 0)
				modeller.auditRecorder.CleanUp()
				modeller.processRecorder.CleanUp()
				return
			}

		case info := <-modeller.TaskStartCh:
			if modeller.shouldCacheContainer(info) {
				modeller.log.Info("the init process of the target container is created",
					"pid", info.PID, "profile name", modeller.name, "profile namespace", modeller.namespace)
				modeller.targetPIDs[info.PID] = struct{}{}
				modeller.targetMnts[info.MntNsID] = struct{}{}
			}

		case <-modeller.stopCh:
			stopAndCleanup()
			return

		case <-modeller.ModellerStopCh:
			stopAndCleanup()
			return
		}
	}
}

func (modeller *BehaviorModeller) Run() {
	modeller.log.Info("start behavioral data collection", "profile name", modeller.name)

	err := modeller.auditRecorder.Init()
	if err != nil {
		modeller.log.Error(err, "modeller.auditRecorder.Init()")
		return
	}

	err = modeller.processRecorder.Init()
	if err != nil {
		modeller.log.Error(err, "modeller.ProcessRecorder.Init()")
		return
	}

	modeller.auditRecorder.Run()
	modeller.processRecorder.Run()
	go modeller.eventHandler()

	modeller.monitor.AddTaskNotifyChs(modeller.name, &modeller.TaskStartCh, nil, nil)
	modeller.ptracer.AddProcessEventNotifyCh(modeller.name, modeller.processRecorder.ProcessEventCh)
	modeller.auditor.AddBehaviorEventNotifyChs(modeller.name, &modeller.auditRecorder.AuditEventCh, nil)
	modeller.modeling = true
}

func (modeller *BehaviorModeller) stop() {
	modeller.monitor.DeleteTaskNotifyChs(modeller.name)
	modeller.ptracer.DeleteProcessEventNotifyCh(modeller.name)
	modeller.auditor.DeleteBehaviorEventNotifyCh(modeller.name)
	modeller.modeling = false
}
