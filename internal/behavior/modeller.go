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
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"

	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

type BehaviorModeller struct {
	tracer         *Tracer
	nodeName       string
	uniqueID       string
	namespace      string
	profileName    string
	env            string
	startTime      time.Time
	duration       time.Duration
	bpfEventCh     chan bpfEvent
	file           *os.File
	writer         *bufio.Writer
	modeling       bool
	targetPIDs     []uint32
	recorder       *AuditRecorder
	ModellerStopCh chan bool
	stopCh         <-chan struct{}
	managerIP      string
	managerPort    int
	mlPort         int
	debug          bool
	log            logr.Logger
}

func NewBehaviorModeller(
	tracer *Tracer,
	nodeName string,
	uniqueID string,
	namespace string,
	name string,
	startTime time.Time,
	duration time.Duration,
	stopCh <-chan struct{},
	managerIP string,
	managerPort int,
	mlPort int,
	debug bool,
	log logr.Logger) *BehaviorModeller {

	log.Info("create a behavior modeller", "start time", startTime,
		"duration", duration.String(), "unique id", uniqueID)

	modeller := BehaviorModeller{
		tracer:         tracer,
		nodeName:       nodeName,
		uniqueID:       uniqueID,
		namespace:      namespace,
		profileName:    name,
		env:            fmt.Sprintf("VARMOR=%s", uniqueID),
		startTime:      startTime,
		duration:       duration,
		modeling:       false,
		targetPIDs:     make([]uint32, 0, 500),
		bpfEventCh:     make(chan bpfEvent, 200),
		ModellerStopCh: make(chan bool, 1),
		stopCh:         stopCh,
		managerIP:      managerIP,
		managerPort:    managerPort,
		mlPort:         mlPort,
		debug:          debug,
		log:            log,
	}

	recorder := newAuditRecorder(uniqueID, stopCh, debug, log.WithName("AUDIT-RECORDER"))
	if recorder != nil {
		modeller.recorder = recorder
	} else {
		return nil
	}

	return &modeller
}

func (modeller *BehaviorModeller) PreprocessAndSendBehaviorData() {
	preprocessor := NewDataPreprocessor(
		modeller.nodeName,
		modeller.uniqueID,
		modeller.namespace,
		modeller.profileName,
		modeller.targetPIDs,
		modeller.managerIP,
		modeller.mlPort,
		modeller.debug,
		modeller.log.WithName("DATA-PREPROCESSOR"))
	if preprocessor == nil {
		return
	}

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
		"unique id", modeller.uniqueID)

	modeller.duration = duration
}

func (modeller *BehaviorModeller) IsModeling() bool {
	return modeller.modeling
}

func (modeller *BehaviorModeller) inTargetPIDs(pid uint32) bool {
	for _, v := range modeller.targetPIDs {
		if pid == v {
			return true
		}
	}

	return false
}

func (modeller *BehaviorModeller) eventHandler() {
	ticker := time.NewTicker(30 * time.Second)

	for {
		select {
		case <-ticker.C:
			if time.Now().After(modeller.startTime.Add(modeller.duration)) {
				modeller.log.Info("behavioral data collection is completed",
					"unique id", modeller.uniqueID,
					"start time", modeller.startTime,
					"duration", modeller.duration.String(),
					"target pids", modeller.targetPIDs,
				)
				modeller.stop()
				modeller.recorder.stop()
				// Sync data to manager after modeling completed.
				modeller.PreprocessAndSendBehaviorData()
				modeller.targetPIDs = make([]uint32, 0)
				modeller.recorder.cleanUp()

				return
			}

		case event := <-modeller.bpfEventCh:
			len := indexOfZero(event.Env[:])
			env := string(event.Env[:len])

			len = indexOfZero(event.ParentTask[:])
			parentTask := string(event.ParentTask[:len])

			len = indexOfZero(event.ChildTask[:])
			childTask := string(event.ChildTask[:len])

			len = indexOfZero(event.Filename[:])
			fileName := string(event.Filename[:len])

			if modeller.debug {
				eventType := ""
				if event.Type == 1 {
					eventType = "sched_process_fork"
				} else {
					eventType = "sched_process_exec"
				}
				output := fmt.Sprintf("%-24s |%-12d %-12d %-20s | %-12d %-12d %-20s | %-20s %-12d %s\n",
					eventType,
					event.ParentPid, event.ParentTgid, parentTask,
					event.ChildPid, event.ChildTgid, childTask,
					env, event.Num, fileName,
				)
				modeller.writer.WriteString(output)
			}

			if event.Type == 1 { /* process sched_process_fork() event */

				if event.ChildTgid != event.ParentTgid { /* new process has been created */
					// clone, fork() without following exec*()
					if modeller.inTargetPIDs(event.ParentTgid) {
						if !modeller.inTargetPIDs(event.ChildTgid) {
							modeller.targetPIDs = append(modeller.targetPIDs, event.ChildTgid)
						}
						break
					}

					// clone, fork(), vfork() inherit the environment variable of parent process
					if modeller.env == env {
						if !modeller.inTargetPIDs(event.ChildTgid) {
							modeller.targetPIDs = append(modeller.targetPIDs, event.ChildTgid)
						}
						if !modeller.inTargetPIDs(event.ParentTgid) {
							modeller.targetPIDs = append(modeller.targetPIDs, event.ParentTgid)
						}
						break
					}
				} else { /* new thread has been created */
					// clone() child_tgid == parent_tgid, so we doesn't care it.
					break
				}

			} else { /* process sched_process_exec() event */

				// The executable program in the target container has been executed.
				if modeller.env == env {
					if !modeller.inTargetPIDs(event.ChildTgid) {
						modeller.targetPIDs = append(modeller.targetPIDs, event.ChildTgid)
					}
					break
				}

				// If the parent of this process is in the target container.
				if modeller.inTargetPIDs(event.ParentTgid) {
					if !modeller.inTargetPIDs(event.ChildTgid) {
						modeller.targetPIDs = append(modeller.targetPIDs, event.ChildTgid)
					}
					break
				}
			}

		case <-modeller.stopCh:
			modeller.stop()
			modeller.log.Info("behavioral data collection is stopped", "unique id", modeller.uniqueID)
			return

		case <-modeller.ModellerStopCh:
			modeller.stop()
			modeller.recorder.stop()
			modeller.recorder.cleanUp()
			modeller.log.Info("behavioral data collection is stopped", "unique id", modeller.uniqueID)
			return
		}
	}
}

func (modeller *BehaviorModeller) Run() {
	modeller.log.Info("start behavioral data collection", "unique id", modeller.uniqueID)

	err := modeller.recorder.init()
	if err != nil {
		modeller.log.Error(err, "modeller.recorder.init()")
		return
	}

	go modeller.recorder.eventHandler()
	go modeller.eventHandler()

	if modeller.debug {
		modeller.file, err = os.Create(modeller.uniqueID + ".trace_debug.log")
		if err != nil {
			modeller.log.Error(err, "os.Create() has failed")
			return
		}
		modeller.writer = bufio.NewWriter(modeller.file)
	}

	modeller.tracer.AddEventCh(modeller.uniqueID, modeller.bpfEventCh, modeller.recorder.auditEventCh)
	modeller.modeling = true
}

func (modeller *BehaviorModeller) stop() {
	modeller.tracer.DeleteEventCh(modeller.uniqueID)

	if modeller.debug && modeller.writer != nil {
		modeller.writer.Flush()
	}

	if modeller.debug && modeller.file != nil {
		modeller.file.Close()
	}
	modeller.modeling = false
}
