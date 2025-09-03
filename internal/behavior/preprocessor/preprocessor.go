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

// Package preprocessor processes the audit events of AppArmor and Seccomp
package preprocessor

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/go-logr/logr"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
	varmortracer "github.com/bytedance/vArmor/pkg/processtracer"
)

type DataPreprocessor struct {
	nodeName        string
	namespace       string
	profileName     string
	enforcer        varmortypes.Enforcer
	targetPIDs      map[uint32]struct{}
	targetMnts      map[uint32]struct{}
	auditRecordPath string
	bpfRecordPath   string
	syscall         map[string]struct{}
	behaviorData    varmortypes.BehaviorData
	svcAddresses    map[string]string
	debug           bool
	inContainer     bool
	debugFilePath   string
	debugFile       *os.File
	debugFileWriter *bufio.Writer
	log             logr.Logger
}

func NewDataPreprocessor(
	nodeName string,
	namespace string,
	directory string,
	name string,
	enforcer string,
	targetPIDs map[uint32]struct{},
	targetMnts map[uint32]struct{},
	svcAddresses map[string]string,
	debug bool,
	inContainer bool,
	log logr.Logger) *DataPreprocessor {

	p := DataPreprocessor{
		nodeName:        nodeName,
		namespace:       namespace,
		profileName:     name,
		enforcer:        varmortypes.GetEnforcerType(enforcer),
		targetPIDs:      targetPIDs,
		targetMnts:      targetMnts,
		auditRecordPath: path.Join(directory, fmt.Sprintf("%s_audit_records.log", name)),
		bpfRecordPath:   path.Join(directory, fmt.Sprintf("%s_process_records.log", name)),
		debugFilePath:   path.Join(directory, fmt.Sprintf("%s_preprocessor_debug.log", name)),
		syscall:         make(map[string]struct{}, 0),
		svcAddresses:    svcAddresses,
		debug:           debug,
		inContainer:     inContainer,
		log:             log,
	}

	if p.enforcer&varmortypes.AppArmor != 0 {
		p.behaviorData.DynamicResult.AppArmor = &varmor.AppArmor{}
	}
	if p.enforcer&varmortypes.Seccomp != 0 {
		p.behaviorData.DynamicResult.Seccomp = &varmor.Seccomp{}
	}
	p.behaviorData.Namespace = namespace
	p.behaviorData.NodeName = nodeName
	p.behaviorData.ProfileName = name

	err := p.parseOverlayInfo()
	if err != nil {
		p.log.Error(err, "parseOverlayInfo() failed")
		return nil
	}

	return &p
}

func (p *DataPreprocessor) containTargetPID(pid uint32) bool {
	_, exists := p.targetPIDs[pid]
	return exists
}

func (p *DataPreprocessor) addTargetPID(pid uint32) {
	p.targetPIDs[pid] = struct{}{}
}

func (p *DataPreprocessor) containTargetMnt(id uint32) bool {
	_, exists := p.targetMnts[id]
	return exists
}

func (p *DataPreprocessor) addTargetMnt(id uint32) {
	p.targetMnts[id] = struct{}{}
}

func (p *DataPreprocessor) gatherTargetPIDs() {
	// We don't need to gather the target PIDs, if the policy only use the AppArmor enforcer.
	// Because we can just use the profile name to identify the audit event of targets.
	if p.enforcer == varmortypes.AppArmor {
		return
	}

	file, err := os.Open(p.bpfRecordPath)
	if err != nil {
		p.log.Error(err, "os.Open() failed")
		return
	}
	defer file.Close()
	decoder := gob.NewDecoder(file)

	for {
		var event varmortracer.BpfProcessEvent
		err := decoder.Decode(&event)
		if err != nil {
			break
		}

		switch event.Type {
		case varmortypes.SchedProcessFork, varmortypes.SchedProcessExec:
			if p.containTargetMnt(event.ChildMntNsID) {
				if !p.containTargetPID(event.ChildTgid) {
					// Add child's tgid
					p.addTargetPID(event.ChildTgid)
					continue
				}
			} else {
				if p.containTargetMnt(event.ParentMntNsID) &&
					!p.containTargetPID(event.ChildTgid) {
					// Add child's tgid
					p.addTargetPID(event.ChildTgid)
					// Add child's mnt ns id if it's in a new mnt namespace
					p.addTargetMnt(event.ChildMntNsID)
					continue
				}
			}
		}
	}
}

func (p *DataPreprocessor) processAuditRecords() error {
	file, err := os.Open(p.auditRecordPath)
	if err != nil {
		p.log.Error(err, "os.Open() failed, nothing to preprocess", "profile name", p.profileName)
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				p.log.Error(err, "reader.ReadString('\n')")
				break
			}
		}

		if (p.enforcer&varmortypes.AppArmor != 0) &&
			(strings.Contains(line, "type=1400") || strings.Contains(line, "type=AVC")) {
			// process AppArmor event
			event, err := parseAppArmorEvent(line)
			if err != nil {
				p.log.Error(err, "p.parseAppArmorEvent() failed", "event", line)
				if p.debug {
					p.debugFileWriter.WriteString(fmt.Sprintf("\n[!] p.parseAppArmorEvent() failed: %s [%s]\n", err.Error(), line))
				}
				continue
			}

			if event.Profile == p.profileName || strings.HasPrefix(event.Profile, p.profileName+"//") {
				if p.debug {
					p.debugFileWriter.WriteString("\n[+] ----------------------\n")
					data, err := json.Marshal(event)
					if err != nil {
						p.log.Error(err, "json.Marshal() failed", "event", event)
						p.debugFileWriter.WriteString("\n[!] json.Marshal() failed.\n")
					} else {
						p.debugFileWriter.WriteString(string(data))
					}
				}

				err = p.parseAppArmorEventForTree(event)
				if err != nil {
					p.log.Error(err, "p.parseAppArmorEventForTree() failed", "event", event)
					if p.debug {
						p.debugFileWriter.WriteString(fmt.Sprintf("\n[!] p.parseAppArmorEventForTree() failed: %v\n", err))
					}
				}
			}
		}

		if (p.enforcer&varmortypes.Seccomp != 0) &&
			(strings.Contains(line, "type=1326") || strings.Contains(line, "type=SECCOMP")) {
			// process Seccomp event
			event, err := varmorauditor.ParseSeccompAuditEvent(line)
			if err != nil {
				p.log.Error(err, "varmorauditor.ParseSeccompAuditEvent() failed", "event", line)
				if p.debug {
					p.debugFileWriter.WriteString(fmt.Sprintf("\n[!] varmorauditor.ParseSeccompAuditEvent() failed: %v [%s]\n", err, line))
				}
				continue
			}

			// Try to parse the AppArmor profile name from the event
			// Note:
			// Some systems will output the AppArmor security context of the task in the Subj
			// field of the Seccomp audit event. So people might see the profile name in the
			// Seccomp event if they use both AppArmor and Seccomp enforcer.
			// We can utilize this feature to extract the profile name from the Seccomp event.
			profileName := varmorauditor.ParseProfileName(event.Subj)
			_, exists := p.targetPIDs[uint32(event.PID)]
			if profileName == p.profileName || exists {
				if p.debug {
					p.debugFileWriter.WriteString("\n[+] ----------------------\n")
					data, err := json.Marshal(event)
					if err != nil {
						p.log.Error(err, "json.Marshal() failed", "event", event)
						p.debugFileWriter.WriteString("\n[!] json.Marshal() failed.\n")
					} else {
						p.debugFileWriter.WriteString(string(data))
					}
				}

				err = p.parseSeccompEventForTree(event)
				if err != nil {
					p.log.Error(err, "p.parseSeccompEventForTree() failed", "event", event)
					if p.debug {
						p.debugFileWriter.WriteString(fmt.Sprintf("\n[!] p.parseSeccompEventForTree() failed: %v\n", err))
					}
				}
			}
		}
	}
	return nil
}

// Process the audit records with the pid list of target container
func (p *DataPreprocessor) Process() []byte {
	defaultData := fmt.Sprintf("{\"namespace\":\"%s\",\"armorProfile\":\"%s\",\"nodeName\":\"%s\",\"dynamicResult\":{},\"status\":\"succeeded\",\"message\":\"\"}",
		p.namespace, p.profileName, p.nodeName)

	// gather the pids in the target container
	p.gatherTargetPIDs()

	var err error
	if p.debug {
		p.debugFile, err = os.Create(p.debugFilePath)
		if err != nil {
			p.log.Error(err, "os.Create() failed")
			return nil
		}
		defer p.debugFile.Close()
		p.debugFileWriter = bufio.NewWriter(p.debugFile)
		defer p.debugFileWriter.Flush()
	}

	p.log.Info("starting data preprocess", "profile name", p.profileName)
	err = p.processAuditRecords()
	if err != nil {
		return []byte(defaultData)
	}

	if p.behaviorData.DynamicResult.AppArmor != nil {
		p.log.Info("apparmor data preprocess completed",
			"apparmor profile num", len(p.behaviorData.DynamicResult.AppArmor.Profiles))
	}

	if p.behaviorData.DynamicResult.Seccomp != nil {
		p.log.Info("seccomp data preprocess completed",
			"seccomp syscall num", len(p.behaviorData.DynamicResult.Seccomp.Syscalls))
	}

	p.behaviorData.Status = varmortypes.Succeeded
	p.behaviorData.Message = ""

	if p.debug {
		p.debugFileWriter.WriteString("\n\n[+] Behavior statistics of the target container:\n")
		data, err := json.Marshal(p.behaviorData.DynamicResult)
		if err != nil {
			p.log.Error(err, "json.Marshal() failed")
			p.debugFileWriter.WriteString(fmt.Sprintf("\n[!] json.Marshal() failed: %v.\n", err))
			return nil
		} else {
			p.debugFileWriter.WriteString(string(data))
		}
	}

	data, err := json.Marshal(p.behaviorData)
	if err != nil {
		p.log.Error(err, "json.Marshal() failed")
		return nil
	}
	return data
}
