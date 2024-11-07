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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
)

type ProcessTracer struct {
	bpfObjs         bpfObjects
	execLink        link.Link
	forkLink        link.Link
	reader          *perf.Reader
	processEventChs map[string]chan<- BpfProcessEvent
	log             logr.Logger
}

func NewProcessTracer(log logr.Logger) (*ProcessTracer, error) {
	tracer := ProcessTracer{
		bpfObjs:         bpfObjects{},
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		log:             log,
	}

	err := tracer.init()
	if err != nil {
		return nil, err
	}
	return &tracer, nil
}

func (tracer *ProcessTracer) init() error {
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

	return nil
}

func (tracer *ProcessTracer) Close() {
	tracer.log.Info("unload the bpf resources of tracer")
	tracer.stopTracing()
	tracer.bpfObjs.Close()
}

func (tracer *ProcessTracer) AddProcessEventNotifyCh(subscriber string, processEventCh chan BpfProcessEvent) {
	tracer.processEventChs[subscriber] = processEventCh

	if len(tracer.processEventChs) == 1 {
		err := tracer.startTracing()
		if err != nil {
			tracer.log.Error(err, "failed to enable tracing")
		}
	}
}

func (tracer *ProcessTracer) DeleteProcessEventNotifyCh(subscriber string) {
	delete(tracer.processEventChs, subscriber)

	if len(tracer.processEventChs) == 0 {
		tracer.stopTracing()
	}
}

func (tracer *ProcessTracer) startTracing() error {
	err := tracer.attachBpfToTracepoint()
	if err != nil {
		return fmt.Errorf("attachBpfToTracepoint() failed: %v", err)
	}
	err = tracer.createBpfEventsReader()
	if err != nil {
		return fmt.Errorf("createBpfEventsReader() failed: %v", err)
	}

	// Handle bpf process events.
	go tracer.handleBpfEvents()

	tracer.log.Info("start tracing")

	return nil
}

func (tracer *ProcessTracer) stopTracing() error {
	tracer.log.Info("stop tracing")

	tracer.closeBpfEventsReader()
	tracer.unattachBpfToTracepoint()

	return nil
}

// attachBpfToTracepoint link the bpf program to RawTracepoints.
func (tracer *ProcessTracer) attachBpfToTracepoint() error {
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

func (tracer *ProcessTracer) unattachBpfToTracepoint() {
	if tracer.execLink != nil {
		tracer.execLink.Close()
	}

	if tracer.forkLink != nil {
		tracer.forkLink.Close()
	}
}

// createBpfEventsReader open a perf event reader from kernel space on the BPF_MAP_TYPE_PERF_EVENT_ARRAY map.
func (tracer *ProcessTracer) createBpfEventsReader() error {
	reader, err := perf.NewReader(tracer.bpfObjs.ProcessEvents, 8192*128)
	if err != nil {
		return err
	}
	tracer.reader = reader
	return nil
}

func (tracer *ProcessTracer) closeBpfEventsReader() {
	if tracer.reader != nil {
		tracer.reader.Close()
	}
}

func (tracer *ProcessTracer) handleBpfEvents() {
	var event BpfProcessEvent
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

		for _, eventCh := range tracer.processEventChs {
			eventCh <- event
		}
	}
}
