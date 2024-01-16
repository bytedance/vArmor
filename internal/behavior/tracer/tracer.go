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

package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorapparmor "github.com/bytedance/vArmor/pkg/lsm/apparmor"
)

const (
	ratelimitSysctl = "/proc/sys/kernel/printk_ratelimit"
	regexAuditType  = "type=AVC|type=1400|type=SECCOMP|type=1326"
)

type Tracer struct {
	enabled        bool
	bpfObjs        bpfObjects
	execLink       link.Link
	forkLink       link.Link
	reader         *perf.Reader
	bpfEventChs    map[string]chan<- varmortypes.BpfTraceEvent
	savedRateLimit uint64
	auditConn      *net.UnixConn
	auditRegex     *regexp.Regexp
	auditEventChs  map[string]chan<- string
	log            logr.Logger
}

func NewTracer(log logr.Logger) (*Tracer, error) {
	tracer := Tracer{
		enabled:        false,
		bpfObjs:        bpfObjects{},
		bpfEventChs:    make(map[string]chan<- varmortypes.BpfTraceEvent),
		savedRateLimit: 0,
		auditEventChs:  make(map[string]chan<- string),
		log:            log,
	}

	err := tracer.init()
	if err != nil {
		return nil, err
	}
	return &tracer, nil
}

func (tracer *Tracer) init() error {
	// Allow the current process to lock memory for eBPF resources.
	tracer.log.Info("remove memory lock")
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("RemoveMemlock() failed: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	tracer.log.Info("load bpf program and maps into the kernel")
	if err := loadBpfObjects(&tracer.bpfObjs, nil); err != nil {
		return fmt.Errorf("loadBpfObjects() failed: %v", err)
	}

	// Compile the regex for matching AppArmor or Seccomp audit event.
	regex, err := regexp.Compile(regexAuditType)
	if err != nil {
		return fmt.Errorf("regexp.Compile() failed: %v", err)
	}
	tracer.auditRegex = regex

	return nil
}

func (tracer *Tracer) Close() {
	tracer.log.Info("unload the bpf resources of tracer")
	tracer.stopTracing()
	tracer.bpfObjs.Close()
}

func (tracer *Tracer) AddEventCh(name string, bpfCh chan varmortypes.BpfTraceEvent, auditCh chan string) {
	tracer.bpfEventChs[name] = bpfCh
	tracer.auditEventChs[name] = auditCh

	if len(tracer.bpfEventChs) == 1 && !tracer.enabled {
		err := tracer.startTracing()
		if err != nil {
			tracer.log.Error(err, "failed to enable tracing")
		}
	}
}

func (tracer *Tracer) DeleteEventCh(name string) {
	delete(tracer.bpfEventChs, name)
	delete(tracer.auditEventChs, name)

	if len(tracer.bpfEventChs) == 0 {
		tracer.stopTracing()
	}
}

func (tracer *Tracer) startTracing() error {
	err := tracer.setRateLimit()
	if err != nil {
		return fmt.Errorf("setRateLimit() failed: %v", err)
	}

	err = tracer.createOmuxsockServer()
	if err != nil {
		return fmt.Errorf("createOmuxsockServer() failed: %v", err)
	}

	err = tracer.attachBpfToTracepoint()
	if err != nil {
		return fmt.Errorf("attachBpfToTracepoint() failed: %v", err)
	}
	err = tracer.createBpfEventsReader()
	if err != nil {
		return fmt.Errorf("createBpfEventsReader() failed: %v", err)
	}

	// Handle bpf trace events.
	go tracer.handleBpfEvents()

	// Handle audit events.
	go tracer.handleAuditEvents()

	tracer.enabled = true
	tracer.log.Info("start tracing")

	return nil
}

func (tracer *Tracer) stopTracing() error {
	tracer.log.Info("stop tracing")

	err := tracer.closeOmuxsockServer()
	if err != nil {
		tracer.log.Error(err, "tracer.closeOmuxsockServer()")
	}

	tracer.closeBpfEventsReader()
	tracer.unattachBpfToTracepoint()

	tracer.enabled = false

	err = tracer.restoreRateLimit()
	if err != nil {
		tracer.log.Error(err, "tracer.restoreRateLimit()")
	}

	output, err := varmorapparmor.RemoveUnknown()
	if err != nil {
		tracer.log.Error(err, "varmorapparmor.RemoveUnknown()", "output", output)
	}

	return err
}

func sysctl_read(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.Trim(string(content), "\n"), nil
}

func sysctl_write(path string, value uint64) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	_, err = file.WriteString(fmt.Sprintf("%d", value))
	return err
}

// setRateLimit set the printk_ratelimit to 0 for recording the audit logs of AppArmor.
func (tracer *Tracer) setRateLimit() error {
	rateLimit, err := sysctl_read(ratelimitSysctl)
	if err != nil {
		return err
	}
	tracer.savedRateLimit, err = strconv.ParseUint(rateLimit, 10, 0)
	if err != nil {
		return err
	}
	if tracer.savedRateLimit != 0 {
		return sysctl_write(ratelimitSysctl, 0)
	}
	return nil
}

// restoreRateLimit recover the printk_ratelimit to previous value.
func (tracer *Tracer) restoreRateLimit() error {
	if tracer.savedRateLimit != 0 {
		return sysctl_write(ratelimitSysctl, tracer.savedRateLimit)
	}
	return nil
}

// createOmuxsockServer create a unixgram server and listen.
func (tracer *Tracer) createOmuxsockServer() error {
	if _, err := os.Stat(varmorconfig.OmuxSocketPath); err == nil {
		os.Remove(varmorconfig.OmuxSocketPath)
	}

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: varmorconfig.OmuxSocketPath,
		Net:  "unixgram"})
	if err != nil {
		return err
	}
	if err := os.Chmod(varmorconfig.OmuxSocketPath, 0662); err != nil {
		return err
	}
	tracer.auditConn = conn
	return tracer.auditConn.SetDeadline(time.Time{})
}

// closeOmuxsockServer close the unixgram server and remove the unix socket file.
func (tracer *Tracer) closeOmuxsockServer() error {
	if tracer.auditConn != nil {
		tracer.auditConn.Close()
		tracer.auditConn = nil
		if _, err := os.Stat(varmorconfig.OmuxSocketPath); err == nil {
			return os.Remove(varmorconfig.OmuxSocketPath)
		}
	}
	return nil
}

func (tracer *Tracer) handleAuditEvents() {
	var buf [4096]byte
	for {
		num, err := tracer.auditConn.Read(buf[:])
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				tracer.log.Error(err, "failed to read data from omuxsock")
			}
			return
		}

		if num > 0 {
			event := string(buf[:num])
			if tracer.auditRegex.FindString(event) != "" {
				for _, eventCh := range tracer.auditEventChs {
					eventCh <- event
				}
			}
		}
	}
}

// attachBpfToTracepoint link the bpf program to RawTracepoints.
func (tracer *Tracer) attachBpfToTracepoint() error {
	execLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: tracer.bpfObjs.TracepointSchedSchedProcessExec,
	})
	if err != nil {
		return err
	}
	tracer.execLink = execLink

	forkLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: tracer.bpfObjs.TracepointSchedSchedProcessFork,
	})
	if err != nil {
		return err
	}
	tracer.forkLink = forkLink

	return nil
}

func (tracer *Tracer) unattachBpfToTracepoint() {
	if tracer.execLink != nil {
		tracer.execLink.Close()
	}

	if tracer.forkLink != nil {
		tracer.forkLink.Close()
	}
}

// createBpfEventsReader open a perf event reader from kernel space on the BPF_MAP_TYPE_PERF_EVENT_ARRAY map.
func (tracer *Tracer) createBpfEventsReader() error {
	reader, err := perf.NewReader(tracer.bpfObjs.Events, 8192*128)
	if err != nil {
		return err
	}
	tracer.reader = reader
	return nil
}

func (tracer *Tracer) closeBpfEventsReader() {
	if tracer.reader != nil {
		tracer.reader.Close()
	}
}

func (tracer *Tracer) handleBpfEvents() {
	var event varmortypes.BpfTraceEvent
	for {
		record, err := tracer.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				tracer.log.V(3).Info("perf buffer reader is closed")
				return
			}
			tracer.log.Error(err, "reading from perf buffer failed")
			continue
		}

		if record.LostSamples != 0 {
			tracer.log.Error(fmt.Errorf("perf buffer is full, some events was dropped"), "dropped count", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			tracer.log.Error(err, "parsing perf event failed")
			continue
		}

		for _, eventCh := range tracer.bpfEventChs {
			eventCh <- event
		}
	}
}
