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

package behavior

import (
	"time"

	"github.com/go-logr/logr"

	varmorrecorder "github.com/bytedance/vArmor/internal/behavior/recorder"
	varmortracer "github.com/bytedance/vArmor/internal/behavior/tracer"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmormonitor "github.com/bytedance/vArmor/pkg/runtime"
	"github.com/bytedance/vArmor/pkg/utils"
)

type BehaviorModeller struct {
	tracer         *varmortracer.Tracer
	monitor        *varmormonitor.RuntimeMonitor
	nodeName       string
	namespace      string
	name           string
	startTime      time.Time
	duration       time.Duration
	modeling       bool
	initPIDsCh     chan uint32
	targetPIDs     map[uint32]struct{}
	targetMnts     map[uint32]struct{}
	auditRecorder  *varmorrecorder.AuditRecorder
	bpfRecorder    *varmorrecorder.BpfRecorder
	ModellerStopCh chan bool
	stopCh         <-chan struct{}
	managerIP      string
	managerPort    int
	classifierPort int
	debug          bool
	log            logr.Logger
}

func NewBehaviorModeller(
	tracer *varmortracer.Tracer,
	monitor *varmormonitor.RuntimeMonitor,
	nodeName string,
	namespace string,
	name string,
	startTime time.Time,
	duration time.Duration,
	stopCh <-chan struct{},
	managerIP string,
	managerPort int,
	classifierPort int,
	debug bool,
	log logr.Logger) *BehaviorModeller {

	log.Info("create a behavior modeller", "start time", startTime,
		"duration", duration.String(), "profile name", name)

	modeller := BehaviorModeller{
		tracer:         tracer,
		monitor:        monitor,
		nodeName:       nodeName,
		namespace:      namespace,
		name:           name,
		startTime:      startTime,
		duration:       duration,
		modeling:       false,
		initPIDsCh:     make(chan uint32, 30),
		targetPIDs:     make(map[uint32]struct{}, 500),
		targetMnts:     make(map[uint32]struct{}, 30),
		ModellerStopCh: make(chan bool, 1),
		stopCh:         stopCh,
		managerIP:      managerIP,
		managerPort:    managerPort,
		classifierPort: classifierPort,
		debug:          debug,
		log:            log,
	}

	auditRecorder := varmorrecorder.NewAuditRecorder(name, stopCh, debug, log.WithName("AUDIT-RECORDER"))
	if auditRecorder != nil {
		modeller.auditRecorder = auditRecorder
	} else {
		return nil
	}

	bpfRecorder := varmorrecorder.NewBpfRecorder(name, stopCh, debug, log.WithName("BPF-RECORDER"))
	if bpfRecorder != nil {
		modeller.bpfRecorder = bpfRecorder
	} else {
		return nil
	}

	return &modeller
}

func (modeller *BehaviorModeller) PreprocessAndSendBehaviorData() {
	preprocessor := NewDataPreprocessor(
		modeller.nodeName,
		modeller.namespace,
		modeller.name,
		modeller.targetPIDs,
		modeller.targetMnts,
		modeller.managerIP,
		modeller.classifierPort,
		modeller.debug,
		modeller.log.WithName("DATA-PREPROCESSOR"))
	if preprocessor == nil {
		return
	}

	preprocessor.GatherTargetPIDs()
	data := preprocessor.Process()
	if data != nil {
		modeller.log.Info("send preprocess result to manager")
		err := varmorutils.PostDataToStatusService(data, modeller.debug, modeller.managerIP, modeller.managerPort)
		if err != nil {
			modeller.log.Error(err, "PostDataToStatusService()")
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

func (modeller *BehaviorModeller) eventHandler() {
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
				modeller.bpfRecorder.Close()

				// Sync data to manager after modeling completed.
				modeller.PreprocessAndSendBehaviorData()
				modeller.targetPIDs = make(map[uint32]struct{}, 0)
				modeller.targetMnts = make(map[uint32]struct{}, 0)
				modeller.auditRecorder.CleanUp()
				modeller.bpfRecorder.CleanUp()
				return
			}

		case pid := <-modeller.initPIDsCh:
			modeller.log.Info("the init process of the target container is created",
				"pid", pid, "profile name", modeller.name, "profile namespace", modeller.namespace)
			modeller.targetPIDs[pid] = struct{}{}
			nsID, err := utils.ReadMntNsID(pid)
			if err == nil {
				modeller.targetMnts[nsID] = struct{}{}
			}

		case <-modeller.stopCh:
			modeller.stop()
			modeller.log.Info("behavioral data collection is stopped", "profile name", modeller.name)
			return

		case <-modeller.ModellerStopCh:
			modeller.stop()
			modeller.auditRecorder.Close()
			modeller.auditRecorder.CleanUp()
			modeller.bpfRecorder.Close()
			modeller.bpfRecorder.CleanUp()
			modeller.log.Info("behavioral data collection is stopped", "profile name", modeller.name)
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

	err = modeller.bpfRecorder.Init()
	if err != nil {
		modeller.log.Error(err, "modeller.bpfRecorder.Init()")
		return
	}

	modeller.auditRecorder.Run()
	modeller.bpfRecorder.Run()
	go modeller.eventHandler()

	modeller.monitor.AddModellerChs(modeller.name, modeller.initPIDsCh)
	modeller.tracer.AddEventCh(modeller.name, modeller.bpfRecorder.BpfEventCh, modeller.auditRecorder.AuditEventCh)

	modeller.modeling = true
}

func (modeller *BehaviorModeller) stop() {
	modeller.monitor.DeleteModellerChs(modeller.name)
	modeller.tracer.DeleteEventCh(modeller.name)
	modeller.modeling = false
}
