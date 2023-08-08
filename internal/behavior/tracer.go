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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorapparmor "github.com/bytedance/vArmor/pkg/lsm/apparmor"
)

const (
	ratelimitSysctl        = "/proc/sys/kernel/printk_ratelimit"
	regexAppArmorAuditType = "apparmor=|operation=|type=AVC"
)

type Tracer struct {
	objs           bpfObjects
	execLink       link.Link
	forkLink       link.Link
	reader         *perf.Reader
	bpfEventChs    map[string]chan<- bpfEvent
	auditEventChs  map[string]chan<- string
	enabled        bool
	savedRateLimit uint64
	auditConn      *net.UnixConn
	apparmorRegex  *regexp.Regexp
	log            logr.Logger
}

func NewBpfTracer(log logr.Logger) (*Tracer, error) {
	tracer := Tracer{
		objs:           bpfObjects{},
		bpfEventChs:    make(map[string]chan<- bpfEvent),
		auditEventChs:  make(map[string]chan<- string),
		enabled:        false,
		savedRateLimit: 0,
		log:            log,
	}

	err := tracer.initBPF()
	if err != nil {
		return nil, err
	}
	return &tracer, nil
}

func (tracer *Tracer) initBPF() error {
	// Allow the current process to lock memory for eBPF resources.
	tracer.log.Info("remove memory lock")
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("RemoveMemlock() failed: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	tracer.log.Info("load bpf program and maps into the kernel")
	if err := loadBpfObjects(&tracer.objs, nil); err != nil {
		return fmt.Errorf("loadBpfObjects() failed: %v", err)
	}

	// Compile the regex for matching AppArmor audit event.
	regex, err := regexp.Compile(regexAppArmorAuditType)
	if err != nil {
		return fmt.Errorf("regexp.Compile() failed: %v", err)
	}
	tracer.apparmorRegex = regex

	return nil
}

func (tracer *Tracer) RemoveBPF() {
	tracer.log.Info("unload the bpf resources of tracer")
	tracer.stopTracing()
	tracer.objs.Close()
}

func (tracer *Tracer) AddEventCh(uniqueID string, bpfCh chan bpfEvent, auditCh chan string) {
	tracer.bpfEventChs[uniqueID] = bpfCh
	tracer.auditEventChs[uniqueID] = auditCh

	if len(tracer.bpfEventChs) == 1 && !tracer.enabled {
		err := tracer.startTracing()
		if err != nil {
			tracer.log.Error(err, "failed to enable tracing")
		}
	}
}

func (tracer *Tracer) DeleteEventCh(uniqueID string) {
	delete(tracer.bpfEventChs, uniqueID)
	delete(tracer.auditEventChs, uniqueID)

	if len(tracer.bpfEventChs) == 0 {
		tracer.stopTracing()
	}
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

// attachBpfToTracepoint link the bpf program to RawTracepoints.
func (tracer *Tracer) attachBpfToTracepoint() error {
	execLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: tracer.objs.TracepointSchedSchedProcessExec,
	})
	if err != nil {
		return err
	}
	tracer.execLink = execLink

	forkLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: tracer.objs.TracepointSchedSchedProcessFork,
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
	reader, err := perf.NewReader(tracer.objs.Events, 8192*128)
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
	go tracer.handleTraceEvents()

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

func (tracer *Tracer) handleTraceEvents() {
	var event bpfEvent
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
			tracer.log.Info("perf buffer is full, some events was dropped", "dropped count", record.LostSamples)
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
			if tracer.apparmorRegex.FindString(event) != "" {
				for _, eventCh := range tracer.auditEventChs {
					eventCh <- event
				}
			}
		}
	}
}
