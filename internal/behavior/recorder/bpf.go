// Copyright 2023 vArmor Authors
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

package recorder

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"

	"github.com/go-logr/logr"

	varmortypes "github.com/bytedance/vArmor/internal/types"
)

type BpfRecorder struct {
	profileName           string
	stopCh                <-chan struct{}
	BpfEventCh            chan varmortypes.BpfTraceEvent
	recordPath            string
	recordDebugPath       string
	recordFile            *os.File
	recordDebugFile       *os.File
	recordFileEncoder     *gob.Encoder
	recordDebugFileWriter *bufio.Writer
	auditLogMark          string
	debug                 bool
	log                   logr.Logger
}

func NewBpfRecorder(profileName string, stopCh <-chan struct{}, debug bool, log logr.Logger) *BpfRecorder {
	r := BpfRecorder{
		profileName:     profileName,
		stopCh:          stopCh,
		BpfEventCh:      make(chan varmortypes.BpfTraceEvent, 500),
		recordPath:      fmt.Sprintf("%s_bpf_records.log", profileName),
		recordDebugPath: fmt.Sprintf("%s_bpf_records_debug.log", profileName),
		debug:           debug,
		log:             log,
	}

	return &r
}

// Init create the record file to save AppArmor audit event
func (r *BpfRecorder) Init() error {
	var err error

	r.recordFile, err = os.Create(r.recordPath)
	if err != nil {
		r.log.Error(err, "os.Create() failed")
		return err
	}
	r.recordFileEncoder = gob.NewEncoder(r.recordFile)

	if r.debug {
		r.recordDebugFile, err = os.Create(r.recordDebugPath)
		if err != nil {
			r.log.Error(err, "os.Create() failed")
			return err
		}
		r.recordDebugFileWriter = bufio.NewWriter(r.recordDebugFile)
	}

	return nil
}

func (r *BpfRecorder) Close() {
	if r.recordFile != nil {
		r.recordFile.Close()
	}

	if r.debug {
		if r.recordDebugFileWriter != nil {
			r.recordDebugFileWriter.Flush()
		}

		if r.recordDebugFile != nil {
			r.recordDebugFile.Close()
		}
	}
}

func indexOfZero(array []uint8) int {
	for i, value := range array {
		if value == 0 {
			return i
		}
	}
	return 0
}

// EventHandler records the bpf event that comes from the BPF tracer
func (r *BpfRecorder) eventHandler() {
	for {
		select {
		case event := <-r.BpfEventCh:
			r.recordFileEncoder.Encode(event)

			if r.debug {
				eventType := ""
				if event.Type == varmortypes.SchedProcessFork {
					eventType = "sched_process_fork"
				} else {
					eventType = "sched_process_exec"
				}

				len := indexOfZero(event.ParentTask[:])
				parentTask := string(event.ParentTask[:len])

				len = indexOfZero(event.ChildTask[:])
				childTask := string(event.ChildTask[:len])

				len = indexOfZero(event.Filename[:])
				fileName := string(event.Filename[:len])

				output := fmt.Sprintf("%-24s |%-12d %-12d %-20s | %-12d %-12d %-20s | %-12d %s\n",
					eventType,
					event.ParentPid, event.ParentTgid, parentTask,
					event.ChildPid, event.ChildTgid, childTask,
					event.MntNsId, fileName,
				)
				r.recordDebugFileWriter.WriteString(output)
			}

		case <-r.stopCh:
			r.Close()
			return
		}
	}
}

func (r *BpfRecorder) Run() {
	go r.eventHandler()
}

func (r *BpfRecorder) CleanUp() {
	_, err := os.Stat(r.recordPath)
	if err == nil {
		os.Remove(r.recordPath)
	}
}
