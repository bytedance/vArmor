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

	"github.com/go-logr/logr"
)

type AuditRecorder struct {
	uniqueID              string
	stopCh                <-chan struct{}
	auditEventCh          chan string
	recordPath            string
	recordDebugPath       string
	recordFile            *os.File
	recordDebugFile       *os.File
	recordFileWriter      *bufio.Writer
	recordDebugFileWriter *bufio.Writer
	auditLogMark          string
	debug                 bool
	log                   logr.Logger
}

func newAuditRecorder(uniqueID string, stopCh <-chan struct{}, debug bool, log logr.Logger) *AuditRecorder {
	recorder := AuditRecorder{
		uniqueID:        uniqueID,
		stopCh:          stopCh,
		auditEventCh:    make(chan string, 500),
		recordPath:      fmt.Sprintf("%s.records.log", uniqueID),
		recordDebugPath: fmt.Sprintf("%s.records_debug.log", uniqueID),
		debug:           debug,
		log:             log,
	}

	return &recorder
}

// InitRecordFile create the record file to save AppArmor audit event
func (recorder *AuditRecorder) init() error {
	var err error

	recorder.recordFile, err = os.Create(recorder.recordPath)
	if err != nil {
		recorder.log.Error(err, "os.Create() failed")
		return err
	}
	recorder.recordFileWriter = bufio.NewWriter(recorder.recordFile)

	if recorder.debug {
		recorder.recordDebugFile, err = os.Create(recorder.recordDebugPath)
		if err != nil {
			recorder.log.Error(err, "os.Create() failed")
			return err
		}
		recorder.recordDebugFileWriter = bufio.NewWriter(recorder.recordDebugFile)
	}

	return nil
}

func (recorder *AuditRecorder) stop() {
	if recorder.recordFileWriter != nil {
		recorder.recordFileWriter.Flush()
	}

	if recorder.recordFile != nil {
		recorder.recordFile.Close()
	}

	if recorder.debug {
		if recorder.recordDebugFileWriter != nil {
			recorder.recordDebugFileWriter.Flush()
		}

		if recorder.recordDebugFile != nil {
			recorder.recordDebugFile.Close()
		}
	}
}

// EventHandler save the audit event of AppArmor that comes from rsyslog
func (recorder *AuditRecorder) eventHandler() {
	for {
		select {
		case event := <-recorder.auditEventCh:
			recorder.recordFileWriter.WriteString(event + "\n")
			if recorder.debug {
				recorder.recordDebugFileWriter.WriteString(event + "\n")
			}
		case <-recorder.stopCh:
			recorder.stop()
			return
		}
	}
}

func (recorder *AuditRecorder) cleanUp() {
	_, err := os.Stat(recorder.recordPath)
	if err == nil {
		os.Remove(recorder.recordPath)
	}
}
