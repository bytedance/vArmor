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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/typeurl/v2"
	"github.com/go-logr/logr"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	varmortypes "github.com/bytedance/vArmor/pkg/types"
)

type RuntimeMonitor struct {
	containerdClient *containerd.Client
	runtimeClient    runtimeapi.RuntimeServiceClient
	runtimeConn      *grpc.ClientConn
	running          bool
	status           error
	taskCreateCh     chan<- varmortypes.ContainerInfo
	taskDeleteCh     chan<- varmortypes.ContainerInfo
	taskDeleteSyncCh chan<- bool
	modellerChs      map[string]chan<- uint32
	log              logr.Logger
}

func NewRuntimeMonitor(log logr.Logger) (*RuntimeMonitor, error) {
	var err error

	monitor := RuntimeMonitor{
		modellerChs: make(map[string]chan<- uint32),
		log:         log,
	}

	monitor.containerdClient, err = newContainerdClient(varmortypes.RuntimeEndpoint, varmortypes.RuntimeTimeout)
	if err != nil {
		return nil, err
	}

	monitor.runtimeClient, monitor.runtimeConn, err = newRuntimeServiceClient(varmortypes.RuntimeEndpoint, varmortypes.RuntimeTimeout)
	if err != nil {
		return nil, err
	}

	return &monitor, nil
}

func (monitor *RuntimeMonitor) Close() {
	monitor.log.Info("close the connection between the containerd and agent")
	monitor.running = false
	monitor.containerdClient.Close()
	monitor.runtimeConn.Close()
}

func (monitor *RuntimeMonitor) SetTaskNotifyChs(
	createCh chan varmortypes.ContainerInfo,
	deleteCh chan varmortypes.ContainerInfo,
	deleteSynCh chan bool) {
	monitor.taskCreateCh = createCh
	monitor.taskDeleteCh = deleteCh
	monitor.taskDeleteSyncCh = deleteSynCh
}

func (monitor *RuntimeMonitor) AddModellerChs(profileName string, ch chan uint32) {
	monitor.modellerChs[profileName] = ch
}

func (monitor *RuntimeMonitor) DeleteModellerChs(profileName string) {
	delete(monitor.modellerChs, profileName)
}

func (monitor *RuntimeMonitor) retrieveContainerInfo(containerInfo *varmortypes.ContainerInfo) error {
	ctx, cancel := appContext(context.Background(), varmortypes.K8sCriNamespace, varmortypes.RuntimeTimeout)
	defer cancel()

	container, err := monitor.containerdClient.LoadContainer(ctx, containerInfo.ContainerID)
	if err != nil {
		return err
	}

	info, err := container.Info(ctx)
	if err != nil {
		return err
	} else if info.Runtime.Name != "io.containerd.runc.v2" {
		return fmt.Errorf("unsupported runtime type: %s", info.Runtime.Name)
	}

	var spec runtimespec.Spec
	if info.Spec != nil {
		err = json.Unmarshal(info.Spec.GetValue(), &spec)
		if err != nil {
			return err
		}
	}

	if containerType, ok := spec.Annotations["io.kubernetes.cri.container-type"]; ok {
		if containerType == "sandbox" {
			return nil
		}
	} else {
		return fmt.Errorf("spec.Annotations['io.kubernetes.cri.container-type'] isn't exist")
	}

	if podID, ok := spec.Annotations["io.kubernetes.cri.sandbox-id"]; ok {
		containerInfo.PodID = podID
	} else {
		return fmt.Errorf("spec.Annotations['io.kubernetes.cri.sandbox-id'] isn't exist")
	}

	if containerName, ok := spec.Annotations["io.kubernetes.cri.container-name"]; ok {
		containerInfo.ContainerName = containerName
	} else {
		return fmt.Errorf("spec.Annotations['io.kubernetes.cri.container-name] isn't exist")
	}

	return nil
}

func (monitor *RuntimeMonitor) retrievePodInfo(containerInfo *varmortypes.ContainerInfo) error {
	ctx, cancel := getContextWithTimeout(context.Background(), varmortypes.RuntimeTimeout)
	defer cancel()

	request := &runtimeapi.PodSandboxStatusRequest{
		PodSandboxId: containerInfo.PodID,
	}
	response, err := monitor.runtimeClient.PodSandboxStatus(ctx, request)
	if err != nil {
		return err
	}

	containerInfo.PodName = response.Status.Metadata.Name
	containerInfo.PodNamespace = response.Status.Metadata.Namespace
	containerInfo.PodUID = response.Status.Metadata.Uid
	containerInfo.PodAnnotations = response.Status.Annotations

	return nil
}

// eventHandler monitor the create and delete events of containerd and send them to the enforcer to handle
func (monitor *RuntimeMonitor) eventHandler(stopCh <-chan struct{}) {
	logger := monitor.log.WithName("eventHandler()")
	logger.Info("start watching the containerd events")

	ctx, cancel := appContext(context.Background(), varmortypes.K8sCriNamespace, 0)
	defer cancel()

	eventsFilter := []string{`topic=="/tasks/create"`, `topic=="/tasks/delete"`}
	eventsService := monitor.containerdClient.EventService()
	eventsCh, errCh := eventsService.Subscribe(ctx, eventsFilter...)
	monitor.running = true

	for {
		select {
		case e := <-eventsCh:
			if e.Event == nil {
				continue
			}

			switch e.Topic {
			case "/tasks/create":
				var createEvent events.TaskCreate
				err := typeurl.UnmarshalTo(e.Event, &createEvent)
				if err != nil {
					logger.Error(err, "typeurl.UnmarshalTo() TaskCreate failed")
					continue
				}

				info := varmortypes.ContainerInfo{
					PID:         createEvent.Pid,
					ContainerID: createEvent.ContainerID,
				}

				err = monitor.retrieveContainerInfo(&info)
				if err != nil {
					logger.Error(err, "monitor.retrieveContainerInfo() failed", "container id", createEvent.ContainerID, "pid", createEvent.Pid)
					continue
				} else if info.PodID == "" {
					logger.V(3).Info("sandbox was created, just ignore it")
					continue
				}

				err = monitor.retrievePodInfo(&info)
				if err != nil {
					logger.Error(err, "monitor.retrievePodInfo() failed", "pod id", info.PodID)
					continue
				}

				logger.V(3).Info("/tasks/create event", "info", info)

				key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", info.ContainerName)
				if _, ok := info.PodAnnotations[key]; ok {
					if monitor.taskCreateCh != nil {
						monitor.taskCreateCh <- info
					}
				}

				key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", info.ContainerName)
				if value, ok := info.PodAnnotations[key]; ok {
					if strings.HasPrefix(value, "localhost/") {
						profileName := value[len("localhost/"):]
						if ch, ok := monitor.modellerChs[profileName]; ok {
							ch <- info.PID
						}
					}
				}

				key = fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", info.ContainerName)
				if value, ok := info.PodAnnotations[key]; ok {
					if strings.HasPrefix(value, "localhost/") {
						profileName := value[len("localhost/"):]
						if ch, ok := monitor.modellerChs[profileName]; ok {
							ch <- info.PID
						}
					}
				}

			case "/tasks/delete":
				var deleteEvent events.TaskDelete
				err := typeurl.UnmarshalTo(e.Event, &deleteEvent)
				if err != nil {
					fmt.Printf("typeurl.UnmarshalTo() ContainerDelete failed: %v\n", err)
					continue
				}

				info := varmortypes.ContainerInfo{
					PID:         deleteEvent.Pid,
					ContainerID: deleteEvent.ContainerID,
				}

				logger.V(3).Info("/tasks/delete event", "info", info)
				if monitor.taskDeleteCh != nil {
					monitor.taskDeleteCh <- info
				}
			}

		case err := <-errCh:
			logger.Error(err, "receive an error from the containerd, waiting for it to resume serving")
			monitor.running = false
			monitor.status = err

			serving, err := monitor.containerdClient.IsServing(ctx)
			if err != nil {
				logger.Error(err, "containerdClient.IsServing() failed")
				monitor.status = err
				return
			} else if serving {
				// kindly hold on until containerd is fully initialized
				time.Sleep(time.Second * 3)

				logger.Info("restart watching the containerd events")
				eventsService = monitor.containerdClient.EventService()
				eventsCh, errCh = eventsService.Subscribe(ctx, eventsFilter...)
				monitor.running = true
				monitor.status = nil

				if monitor.taskDeleteSyncCh != nil {
					logger.V(3).Info("notify the enforcer to handle the containers that exit or are created while the monitor is offline")
					monitor.taskDeleteSyncCh <- true
					monitor.CollectExistingTargetContainers()
				}
			} else {
				logger.Info("the containerd isn't serving")
				return
			}

		case <-stopCh:
			logger.Info("stop watching the containerd events")
			return
		}
	}
}

func (monitor *RuntimeMonitor) Run(stopCh <-chan struct{}) {
	monitor.eventHandler(stopCh)
}

func (monitor *RuntimeMonitor) IsMonitoring() (bool, error) {
	return monitor.running, monitor.status
}

// CollectExistingTargetContainers collects all existing containers that should be protected
// and sends them to the enforcer
func (monitor *RuntimeMonitor) CollectExistingTargetContainers() error {
	logger := monitor.log.WithName("CollectExistingTargetContainers()")
	logger.Info("start collecting the existing containers")

	ctx, cancel := appContext(context.Background(), varmortypes.K8sCriNamespace, varmortypes.RuntimeTimeout)
	defer cancel()

	service := monitor.containerdClient.TaskService()
	response, err := service.List(ctx, &tasks.ListTasksRequest{})
	if err != nil {
		return err
	}

	for _, task := range response.Tasks {
		if task.Status.String() != "RUNNING" {
			continue
		}

		info := varmortypes.ContainerInfo{
			PID:         task.Pid,
			ContainerID: task.ID,
		}
		err = monitor.retrieveContainerInfo(&info)
		if err != nil {
			logger.Error(err, "monitor.retrieveContainerInfo() failed", "container id", info.ContainerID, "pid", info.PID)
			continue
		} else if info.PodID == "" {
			logger.V(3).Info("sandbox was created, just ignore it", "container id", info.ContainerID, "pid", info.PID)
			continue
		}

		err = monitor.retrievePodInfo(&info)
		if err != nil {
			logger.Error(err, "monitor.retrievePodInfo() failed", "pod id", info.PodID)
			continue
		}

		key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", info.ContainerName)
		if _, ok := info.PodAnnotations[key]; ok {
			if monitor.taskCreateCh != nil {
				monitor.taskCreateCh <- info
			}
		}
	}

	return nil
}
