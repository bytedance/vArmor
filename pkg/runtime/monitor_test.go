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

package runtime

import (
	"testing"
	"time"

	"gotest.tools/assert"
	"k8s.io/klog/v2/klogr"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

func Test_createRuntimeMonitor(t *testing.T) {
	createCh := make(chan varmortypes.ContainerInfo, 100)
	deleteCh := make(chan varmortypes.ContainerInfo, 100)
	syncCh := make(chan bool, 1)

	log.SetLogger(klogr.New())
	monitor, err := NewRuntimeMonitor(createCh, deleteCh, syncCh, log.Log.WithName("TEST"))
	if err != nil {
		return
	}
	defer monitor.Close()
}

func Test_watchContainerdEvents(t *testing.T) {
	createCh := make(chan varmortypes.ContainerInfo, 100)
	deleteCh := make(chan varmortypes.ContainerInfo, 100)
	syncCh := make(chan bool, 1)

	log.SetLogger(klogr.New())
	monitor, err := NewRuntimeMonitor(createCh, deleteCh, syncCh, log.Log.WithName("TEST_RUNTIME_MONITOR"))
	if err != nil {
		return
	}

	log.Log.Info("monitoring")
	go monitor.Run(nil)
	stopTicker := time.NewTicker(10 * time.Second)

LOOP:
	for {
		select {
		case info := <-createCh:
			log.Log.Info("recevie /task/create event", "info", info)
		case info := <-deleteCh:
			log.Log.Info("recevie /task/delete event", "info", info)
		case <-syncCh:
			log.Log.Info("recv syncCh")
		case <-stopTicker.C:
			assert.Equal(t, monitor.running, true)
			assert.Equal(t, monitor.status, nil)
			monitor.Close()
			break LOOP
		}
	}

	monitoring, _ := monitor.IsMonitoring()
	assert.Equal(t, monitoring, false)
}

func Test_CollectExistingTargetContainers(t *testing.T) {
	createCh := make(chan varmortypes.ContainerInfo, 100)
	deleteCh := make(chan varmortypes.ContainerInfo, 100)
	syncCh := make(chan bool, 1)

	log.SetLogger(klogr.New())
	monitor, err := NewRuntimeMonitor(createCh, deleteCh, syncCh, log.Log.WithName("TEST"))
	if err != nil {
		return
	}
	defer monitor.Close()

	go monitor.CollectExistingTargetContainers()

	stopTicker := time.NewTicker(5 * time.Second)

LOOP:
	for {
		select {
		case info := <-createCh:
			log.Log.Info("recevie /task/create event", "info", info)
		case info := <-deleteCh:
			log.Log.Info("recevie /task/delete event", "info", info)
		case <-stopTicker.C:
			assert.Equal(t, monitor.running, true)
			assert.Equal(t, monitor.status, nil)
			monitor.Close()
			break LOOP
		}
	}

	monitoring, _ := monitor.IsMonitoring()
	assert.Equal(t, monitoring, false)
}
