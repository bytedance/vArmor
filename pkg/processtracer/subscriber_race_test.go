// Copyright 2026 vArmor Authors
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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
)

func TestProcessEventChs_ConcurrentAccess(t *testing.T) {
	tracer := &ProcessTracer{
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		tracing:         true,
		stopTracingFn:   func() error { return nil },
		log:             logr.Discard(),
	}
	eventCh := make(chan BpfProcessEvent, 1)
	tracer.processEventChs["keepalive"] = eventCh

	const workers = 8
	const iterations = 500
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("subscriber-%d", id)
			for i := 0; i < iterations; i++ {
				tracer.AddProcessEventNotifyCh(name, &eventCh)
				tracer.DeleteProcessEventNotifyCh(name)
			}
		}(worker)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tracer.snapshotProcessEventChs()
			}
		}()
	}
	wg.Wait()

	if len(tracer.snapshotProcessEventChs()) != 1 {
		t.Fatal("keepalive subscriber was unexpectedly removed")
	}
}

func TestAddProcessEventNotifyCh_IdempotentStart(t *testing.T) {
	var starts atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		startTracingFn: func() error {
			starts.Add(1)
			return nil
		},
		log: logr.Discard(),
	}
	firstCh := make(chan BpfProcessEvent, 1)
	secondCh := make(chan BpfProcessEvent, 1)

	tracer.AddProcessEventNotifyCh("subscriber", &firstCh)
	tracer.AddProcessEventNotifyCh("subscriber", &secondCh)

	if got := starts.Load(); got != 1 {
		t.Fatalf("tracing started %d times, want 1", got)
	}
	if !tracer.tracing {
		t.Fatal("tracing was not marked active after a successful start")
	}
	chs := tracer.snapshotProcessEventChs()
	if len(chs) != 1 || chs[0] != secondCh {
		t.Fatal("re-registering a subscriber did not replace its notification channel")
	}
}

func TestAddProcessEventNotifyCh_StartFailureCanRetry(t *testing.T) {
	var starts atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		startTracingFn: func() error {
			if starts.Add(1) == 1 {
				return errors.New("injected start failure")
			}
			return nil
		},
		log: logr.Discard(),
	}
	eventCh := make(chan BpfProcessEvent, 1)

	tracer.AddProcessEventNotifyCh("subscriber", &eventCh)
	if tracer.tracing {
		t.Fatal("tracing was marked active after start failed")
	}

	tracer.AddProcessEventNotifyCh("subscriber", &eventCh)
	if !tracer.tracing {
		t.Fatal("tracing was not marked active after retry succeeded")
	}
	if got := starts.Load(); got != 2 {
		t.Fatalf("tracing start attempted %d times, want 2", got)
	}
}

func TestProcessEventNotifyCh_ReAddAfterDeleteRestartsTracing(t *testing.T) {
	var starts atomic.Int32
	var stops atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		startTracingFn: func() error {
			starts.Add(1)
			return nil
		},
		stopTracingFn: func() error {
			stops.Add(1)
			return nil
		},
		log: logr.Discard(),
	}
	eventCh := make(chan BpfProcessEvent, 1)

	tracer.AddProcessEventNotifyCh("subscriber", &eventCh)
	tracer.DeleteProcessEventNotifyCh("subscriber")
	tracer.AddProcessEventNotifyCh("subscriber", &eventCh)

	if got := starts.Load(); got != 2 {
		t.Fatalf("tracing started %d times, want 2", got)
	}
	if got := stops.Load(); got != 1 {
		t.Fatalf("tracing stopped %d times, want 1", got)
	}
	if !tracer.tracing {
		t.Fatal("tracing was not active after the subscriber was re-added")
	}
}

func TestProcessEventNotifyCh_ReAddAfterStopFailureRestartsTracing(t *testing.T) {
	var starts atomic.Int32
	var stops atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: map[string]chan<- BpfProcessEvent{
			"subscriber": make(chan BpfProcessEvent, 1),
		},
		tracing: true,
		startTracingFn: func() error {
			starts.Add(1)
			return nil
		},
		stopTracingFn: func() error {
			stops.Add(1)
			return errors.New("injected stop failure")
		},
		log: logr.Discard(),
	}

	tracer.DeleteProcessEventNotifyCh("subscriber")
	if tracer.tracing {
		t.Fatal("tracing remained active after stop failed")
	}
	if got := stops.Load(); got != 1 {
		t.Fatalf("tracing stopped %d times, want 1", got)
	}

	eventCh := make(chan BpfProcessEvent, 1)
	tracer.AddProcessEventNotifyCh("subscriber", &eventCh)
	if got := starts.Load(); got != 1 {
		t.Fatalf("tracing started %d times after re-add, want 1", got)
	}
	if !tracer.tracing {
		t.Fatal("tracing was not active after the subscriber was re-added")
	}
}

func TestProcessTracerClose_SynchronizesWithDelete(t *testing.T) {
	const iterations = 100
	for i := 0; i < iterations; i++ {
		var stops atomic.Int32
		tracer := &ProcessTracer{
			processEventChs: map[string]chan<- BpfProcessEvent{
				"subscriber": make(chan BpfProcessEvent, 1),
			},
			tracing: true,
			stopTracingFn: func() error {
				stops.Add(1)
				return nil
			},
			log: logr.Discard(),
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			tracer.DeleteProcessEventNotifyCh("subscriber")
		}()
		go func() {
			defer wg.Done()
			<-start
			tracer.Close()
		}()
		close(start)
		wg.Wait()

		tracer.Close()
		if got := stops.Load(); got != 1 {
			t.Fatalf("iteration %d: tracing stopped %d times, want 1", i, got)
		}
		if !tracer.closed {
			t.Fatalf("iteration %d: tracer was not marked closed", i)
		}
		if !tracer.resourcesClosed {
			t.Fatalf("iteration %d: tracer resources were not marked closed", i)
		}
		if len(tracer.snapshotProcessEventChs()) != 0 {
			t.Fatalf("iteration %d: subscribers remain after close", i)
		}
	}
}

func TestProcessTracerClose_SynchronizesWithAdd(t *testing.T) {
	const iterations = 100
	for i := 0; i < iterations; i++ {
		var starts atomic.Int32
		var stops atomic.Int32
		tracer := &ProcessTracer{
			processEventChs: make(map[string]chan<- BpfProcessEvent),
			startTracingFn: func() error {
				starts.Add(1)
				return nil
			},
			stopTracingFn: func() error {
				stops.Add(1)
				return nil
			},
			log: logr.Discard(),
		}
		eventCh := make(chan BpfProcessEvent, 1)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			tracer.AddProcessEventNotifyCh("subscriber", &eventCh)
		}()
		go func() {
			defer wg.Done()
			<-start
			tracer.Close()
		}()
		close(start)
		wg.Wait()

		startCount := starts.Load()
		if startCount > 1 {
			t.Fatalf("iteration %d: tracing started %d times, want at most 1", i, startCount)
		}
		if got := stops.Load(); got != startCount {
			t.Fatalf("iteration %d: tracing started %d times but stopped %d times", i, startCount, got)
		}
		if !tracer.closed {
			t.Fatalf("iteration %d: tracer was not marked closed", i)
		}
		if !tracer.resourcesClosed {
			t.Fatalf("iteration %d: tracer resources were not marked closed", i)
		}
		if len(tracer.snapshotProcessEventChs()) != 0 {
			t.Fatalf("iteration %d: subscribers remain after close", i)
		}
	}
}

func TestProcessTracerClose_PreventsRestart(t *testing.T) {
	var starts atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		startTracingFn: func() error {
			starts.Add(1)
			return nil
		},
		log: logr.Discard(),
	}

	tracer.Close()
	eventCh := make(chan BpfProcessEvent, 1)
	tracer.AddProcessEventNotifyCh("subscriber", &eventCh)

	if got := starts.Load(); got != 0 {
		t.Fatalf("tracing started %d times after Close, want 0", got)
	}
	if len(tracer.snapshotProcessEventChs()) != 0 {
		t.Fatal("subscriber was registered after Close")
	}
}

func TestProcessTracerClose_RetriesFailedStop(t *testing.T) {
	var stops atomic.Int32
	var closes atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: map[string]chan<- BpfProcessEvent{
			"subscriber": make(chan BpfProcessEvent, 1),
		},
		tracing: true,
		stopTracingFn: func() error {
			if stops.Add(1) == 1 {
				return errors.New("injected stop failure")
			}
			return nil
		},
		closeBpfObjsFn: func() error {
			closes.Add(1)
			return nil
		},
		log: logr.Discard(),
	}

	tracer.Close()
	if !tracer.closed {
		t.Fatal("tracer did not reject new subscribers after close began")
	}
	if tracer.resourcesClosed {
		t.Fatal("tracer resources were marked closed after stop failed")
	}
	if !tracer.tracing {
		t.Fatal("tracing was marked stopped after stop failed")
	}
	if got := closes.Load(); got != 0 {
		t.Fatalf("BPF objects closed %d times before tracing stopped, want 0", got)
	}

	eventCh := make(chan BpfProcessEvent, 1)
	tracer.AddProcessEventNotifyCh("new-subscriber", &eventCh)
	if len(tracer.snapshotProcessEventChs()) != 0 {
		t.Fatal("subscriber was registered while close was pending retry")
	}

	tracer.Close()
	if got := stops.Load(); got != 2 {
		t.Fatalf("stop attempted %d times, want 2", got)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("BPF objects closed %d times, want 1", got)
	}
	if tracer.tracing || !tracer.resourcesClosed {
		t.Fatal("tracer did not complete cleanup after retry succeeded")
	}

	tracer.Close()
	if got := stops.Load(); got != 2 {
		t.Fatalf("successful cleanup was retried; stop calls = %d, want 2", got)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("successful cleanup was retried; BPF close calls = %d, want 1", got)
	}
}

func TestProcessTracerClose_RetriesFailedBpfClose(t *testing.T) {
	var closes atomic.Int32
	tracer := &ProcessTracer{
		processEventChs: make(map[string]chan<- BpfProcessEvent),
		closeBpfObjsFn: func() error {
			if closes.Add(1) == 1 {
				return errors.New("injected BPF close failure")
			}
			return nil
		},
		log: logr.Discard(),
	}

	tracer.Close()
	if !tracer.closed || tracer.resourcesClosed {
		t.Fatal("failed BPF close did not leave cleanup retryable")
	}

	tracer.Close()
	if !tracer.resourcesClosed {
		t.Fatal("BPF cleanup retry did not complete")
	}
	if got := closes.Load(); got != 2 {
		t.Fatalf("BPF close attempted %d times, want 2", got)
	}

	tracer.Close()
	if got := closes.Load(); got != 2 {
		t.Fatalf("successful BPF close was retried; calls = %d, want 2", got)
	}
}
