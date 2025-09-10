// Copyright 2025 vArmor Authors
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

// Package recorder records the events of AppArmor, Seccomp, BPF profiles and process creation events.
package recorder

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"path"

	"github.com/go-logr/logr"

	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
)

// BpfRecorder caches security audit events of a BPF profile into a local file.
type BpfRecorder struct {
	profileName           string
	stopCh                <-chan struct{}
	BpfEventCh            chan varmorauditor.BpfEvent
	recordPath            string
	recordDebugPath       string
	recordFile            *os.File
	recordDebugFile       *os.File
	recordFileEncoder     *gob.Encoder
	recordDebugFileWriter *bufio.Writer
	debug                 bool
	log                   logr.Logger
}

func NewBpfRecorder(directory string, profileName string, stopCh <-chan struct{}, debug bool, log logr.Logger) *BpfRecorder {
	r := BpfRecorder{
		profileName:     profileName,
		stopCh:          stopCh,
		BpfEventCh:      make(chan varmorauditor.BpfEvent, 500),
		recordPath:      path.Join(directory, fmt.Sprintf("%s_bpf_records.log", profileName)),
		recordDebugPath: path.Join(directory, fmt.Sprintf("%s_bpf_records_debug.log", profileName)),
		debug:           debug,
		log:             log,
	}

	return &r
}

// Init create the record file to save the process creation events for the Seccomp enforcer
func (r *BpfRecorder) Init() error {
	var err error

	r.recordFile, err = os.Create(r.recordPath)
	if err != nil {
		return err
	}
	r.recordFileEncoder = gob.NewEncoder(r.recordFile)
	gob.Register(&varmorauditor.BpfPathEvent{})
	gob.Register(&varmorauditor.BpfCapabilityEvent{})
	gob.Register(&varmorauditor.BpfNetworkEvent{})
	gob.Register(&varmorauditor.BpfPtraceEvent{})
	gob.Register(&varmorauditor.BpfMountEvent{})

	if r.debug {
		r.recordDebugFile, err = os.Create(r.recordDebugPath)
		if err != nil {
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

// EventHandler records the bpf event that comes from the auditor
func (r *BpfRecorder) eventHandler() {
	for {
		select {
		case event := <-r.BpfEventCh:
			err := r.recordFileEncoder.Encode(event)
			if err != nil {
				r.log.Error(err, "encode process event failed")
				continue
			}

			if r.debug {
				r.recordDebugFileWriter.WriteString(fmt.Sprintf("%+v %+v\n", event.Header, event.Body))
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
