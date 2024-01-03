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
	profileName           string
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

func newAuditRecorder(profileName string, stopCh <-chan struct{}, debug bool, log logr.Logger) *AuditRecorder {
	r := AuditRecorder{
		profileName:     profileName,
		stopCh:          stopCh,
		auditEventCh:    make(chan string, 500),
		recordPath:      fmt.Sprintf("%s_audit_records.log", profileName),
		recordDebugPath: fmt.Sprintf("%s_audit_records_debug.log", profileName),
		debug:           debug,
		log:             log,
	}

	return &r
}

// init create the record file to save AppArmor audit event
func (r *AuditRecorder) init() error {
	var err error

	r.recordFile, err = os.Create(r.recordPath)
	if err != nil {
		r.log.Error(err, "os.Create() failed")
		return err
	}
	r.recordFileWriter = bufio.NewWriter(r.recordFile)

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

func (r *AuditRecorder) stop() {
	if r.recordFileWriter != nil {
		r.recordFileWriter.Flush()
	}

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

// EventHandler save the audit event of AppArmor that comes from rsyslog
func (r *AuditRecorder) eventHandler() {
	for {
		select {
		case event := <-r.auditEventCh:
			r.recordFileWriter.WriteString(event + "\n")
			if r.debug {
				r.recordDebugFileWriter.WriteString(event + "\n")
			}
		case <-r.stopCh:
			r.stop()
			return
		}
	}
}

func (r *AuditRecorder) cleanUp() {
	_, err := os.Stat(r.recordPath)
	if err == nil {
		os.Remove(r.recordPath)
	}
}
