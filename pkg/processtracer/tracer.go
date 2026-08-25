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

// Package tracer implements process tracer module
package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

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
	chsMu           sync.RWMutex
	processEventChs map[string]chan<- BpfProcessEvent
	tracing         bool
	closed          bool
	resourcesClosed bool
	startTracingFn  func() error
	stopTracingFn   func() error
	closeBpfObjsFn  func() error
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
	tracer.chsMu.Lock()
	defer tracer.chsMu.Unlock()

	if tracer.resourcesClosed {
		return
	}
	tracer.closed = true
	clear(tracer.processEventChs)

	tracer.log.Info("unload the bpf resources of tracer")
	if tracer.tracing || tracer.reader != nil || tracer.execLink != nil || tracer.forkLink != nil {
		if err := tracer.disableTracing(); err != nil {
			tracer.log.Error(err, "failed to disable tracing")
			return
		}
		tracer.tracing = false
	}
	if err := tracer.closeBpfObjects(); err != nil {
		tracer.log.Error(err, "failed to unload the bpf resources of tracer")
		return
	}
	tracer.resourcesClosed = true
}

func (tracer *ProcessTracer) AddProcessEventNotifyCh(subscriber string, processEventCh *chan BpfProcessEvent) {
	tracer.chsMu.Lock()
	defer tracer.chsMu.Unlock()

	if tracer.closed || processEventCh == nil {
		return
	}
	tracer.processEventChs[subscriber] = *processEventCh

	if !tracer.tracing {
		err := tracer.enableTracing()
		if err != nil {
			tracer.log.Error(err, "failed to enable tracing")
			return
		}
		tracer.tracing = true
	}
}

func (tracer *ProcessTracer) DeleteProcessEventNotifyCh(subscriber string) {
	tracer.chsMu.Lock()
	defer tracer.chsMu.Unlock()

	delete(tracer.processEventChs, subscriber)

	if len(tracer.processEventChs) == 0 && tracer.tracing {
		err := tracer.disableTracing()
		// Stopping can partially release the reader or links. Mark tracing
		// inactive so the next subscriber retries startup and cleans up any
		// stale resources first.
		tracer.tracing = false
		if err != nil {
			tracer.log.Error(err, "failed to disable tracing")
		}
	}
}

func (tracer *ProcessTracer) enableTracing() error {
	if tracer.startTracingFn != nil {
		return tracer.startTracingFn()
	}
	return tracer.startTracing()
}

func (tracer *ProcessTracer) disableTracing() error {
	if tracer.stopTracingFn != nil {
		return tracer.stopTracingFn()
	}
	return tracer.stopTracing()
}

func (tracer *ProcessTracer) closeBpfObjects() error {
	if tracer.closeBpfObjsFn != nil {
		return tracer.closeBpfObjsFn()
	}
	return tracer.bpfObjs.Close()
}

func (tracer *ProcessTracer) snapshotProcessEventChs() []chan<- BpfProcessEvent {
	tracer.chsMu.RLock()
	defer tracer.chsMu.RUnlock()

	chs := make([]chan<- BpfProcessEvent, 0, len(tracer.processEventChs))
	for _, ch := range tracer.processEventChs {
		chs = append(chs, ch)
	}
	return chs
}

func (tracer *ProcessTracer) startTracing() error {
	if tracer.reader != nil || tracer.execLink != nil || tracer.forkLink != nil {
		if err := tracer.stopTracing(); err != nil {
			return fmt.Errorf("clean up stale tracing resources: %w", err)
		}
	}

	err := tracer.attachBpfToTracepoint()
	if err != nil {
		cleanupErr := tracer.unattachBpfToTracepoint()
		return errors.Join(fmt.Errorf("attachBpfToTracepoint() failed: %w", err), cleanupErr)
	}
	err = tracer.createBpfEventsReader()
	if err != nil {
		cleanupErr := tracer.unattachBpfToTracepoint()
		return errors.Join(fmt.Errorf("createBpfEventsReader() failed: %w", err), cleanupErr)
	}

	// Handle bpf process events.
	go tracer.handleBpfEvents(tracer.reader)

	tracer.log.Info("start tracing processes")

	return nil
}

func (tracer *ProcessTracer) stopTracing() error {
	err := errors.Join(
		tracer.closeBpfEventsReader(),
		tracer.unattachBpfToTracepoint(),
	)
	if err != nil {
		return err
	}

	tracer.log.Info("stop tracing processes")
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

func (tracer *ProcessTracer) unattachBpfToTracepoint() error {
	var errs []error
	if tracer.execLink != nil {
		if err := tracer.execLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close exec tracepoint link: %w", err))
		} else {
			tracer.execLink = nil
		}
	}

	if tracer.forkLink != nil {
		if err := tracer.forkLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close fork tracepoint link: %w", err))
		} else {
			tracer.forkLink = nil
		}
	}
	return errors.Join(errs...)
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

func (tracer *ProcessTracer) closeBpfEventsReader() error {
	if tracer.reader != nil {
		if err := tracer.reader.Close(); err != nil {
			return fmt.Errorf("close bpf events reader: %w", err)
		}
		tracer.reader = nil
	}
	return nil
}

func (tracer *ProcessTracer) handleBpfEvents(reader *perf.Reader) {
	var event BpfProcessEvent
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				tracer.log.V(2).Info("perf buffer reader is closed")
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

		for _, eventCh := range tracer.snapshotProcessEventChs() {
			eventCh <- event
		}
	}
}
