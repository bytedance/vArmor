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

// Package runtime implements a monitor to watch the task events
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
	varmorutils "github.com/bytedance/vArmor/pkg/utils"
)

type RuntimeMonitor struct {
	containerdClient  *containerd.Client
	runtimeClient     runtimeapi.RuntimeServiceClient
	runtimeConn       *grpc.ClientConn
	running           bool
	status            error
	taskStartChs      map[string]chan<- varmortypes.ContainerInfo
	taskDeleteChs     map[string]chan<- varmortypes.ContainerInfo
	taskDeleteSyncChs map[string]chan<- bool
	log               logr.Logger
}

func NewRuntimeMonitor(log logr.Logger) (*RuntimeMonitor, error) {
	var err error

	monitor := RuntimeMonitor{
		taskStartChs:      make(map[string]chan<- varmortypes.ContainerInfo),
		taskDeleteChs:     make(map[string]chan<- varmortypes.ContainerInfo),
		taskDeleteSyncChs: make(map[string]chan<- bool),
		log:               log,
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

func (monitor *RuntimeMonitor) AddTaskNotifyChs(
	subscriber string,
	startCh *chan varmortypes.ContainerInfo,
	deleteCh *chan varmortypes.ContainerInfo,
	deleteSynCh *chan bool) {

	if startCh != nil {
		monitor.taskStartChs[subscriber] = *startCh
	}
	if deleteCh != nil {
		monitor.taskDeleteChs[subscriber] = *deleteCh
	}
	if deleteSynCh != nil {
		monitor.taskDeleteSyncChs[subscriber] = *deleteSynCh
	}
}

func (monitor *RuntimeMonitor) DeleteTaskNotifyChs(subscriber string) {
	delete(monitor.taskStartChs, subscriber)
	delete(monitor.taskDeleteChs, subscriber)
	delete(monitor.taskDeleteSyncChs, subscriber)
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

	containerInfo.Image = info.Image

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

	if response.Status != nil {
		containerInfo.PodAnnotations = response.Status.Annotations

		if response.Status.Metadata != nil {
			containerInfo.PodName = response.Status.Metadata.Name
			containerInfo.PodNamespace = response.Status.Metadata.Namespace
			containerInfo.PodUID = response.Status.Metadata.Uid
		}

		if response.Status.Network != nil {
			if response.Status.Linux != nil &&
				response.Status.Linux.Namespaces != nil &&
				response.Status.Linux.Namespaces.Options != nil &&
				response.Status.Linux.Namespaces.Options.Network == runtimeapi.NamespaceMode_NODE {
				return nil
			}
			containerInfo.PodIPs = append(containerInfo.PodIPs, response.Status.Network.Ip)
			for _, ip := range response.Status.Network.AdditionalIps {
				containerInfo.PodIPs = append(containerInfo.PodIPs, ip.Ip)
			}
		}
	}

	return nil
}

func extractVarmorProfileName(info varmortypes.ContainerInfo) string {
	keys := []string{
		fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", info.ContainerName),
		fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", info.ContainerName),
		fmt.Sprintf("container.apparmor.security.beta.varmor.org/%s", info.ContainerName),
		fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", info.ContainerName),
	}

	for _, key := range keys {
		if value, ok := info.PodAnnotations[key]; ok {
			if strings.HasPrefix(value, "localhost/") {
				return strings.TrimPrefix(value, "localhost/")
			}
		}
	}
	return ""
}

// eventHandler monitor the start and delete events of containerd and send them to subscribers to handle
func (monitor *RuntimeMonitor) eventHandler(stopCh <-chan struct{}) {
	logger := monitor.log.WithName("eventHandler()")
	logger.Info("start watching the containerd events")

	ctx, cancel := appContext(context.Background(), varmortypes.K8sCriNamespace, 0)
	defer cancel()

	eventsFilter := []string{`topic=="/tasks/start"`, `topic=="/tasks/delete"`}
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
			case "/tasks/start":
				var startEvent events.TaskStart
				err := typeurl.UnmarshalTo(e.Event, &startEvent)
				if err != nil {
					logger.Error(err, "typeurl.UnmarshalTo() TaskStart failed")
					continue
				}

				info := varmortypes.ContainerInfo{
					PID:         startEvent.Pid,
					ContainerID: startEvent.ContainerID,
				}

				err = monitor.retrieveContainerInfo(&info)
				if err != nil {
					logger.Error(err, "monitor.retrieveContainerInfo() failed", "container id", info.ContainerID, "pid", info.PID)
					continue
				} else if info.PodID == "" {
					logger.V(2).Info("sandbox was started, just ignore it")
					continue
				}

				info.MntNsID, err = varmorutils.ReadMntNsID(info.PID)
				if err != nil {
					logger.Error(err, "varmorutils.ReadMntNsID() failed", "container id", info.ContainerID, "pid", info.PID)
					continue
				}

				err = monitor.retrievePodInfo(&info)
				if err != nil {
					logger.Error(err, "monitor.retrievePodInfo() failed", "pod id", info.PodID)
					continue
				}

				info.ProfileName = extractVarmorProfileName(info)
				if info.ProfileName != "" {
					logger.V(2).Info("notify subscribers of the '/tasks/start'", "info", info)
					for _, ch := range monitor.taskStartChs {
						ch <- info
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

				logger.V(2).Info("notify subscribers of the '/tasks/delete' event", "info", info)
				for _, ch := range monitor.taskDeleteChs {
					ch <- info
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

				logger.V(2).Info("notify subscribers to handle the containers that exit or are created while the monitor is offline")
				for _, ch := range monitor.taskDeleteSyncChs {
					ch <- true
				}
				monitor.CollectExistingTargetContainers()

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
// and sends them to subscribers
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
			logger.V(2).Info("sandbox was created, just ignore it", "container id", info.ContainerID, "pid", info.PID)
			continue
		}

		info.MntNsID, err = varmorutils.ReadMntNsID(info.PID)
		if err != nil {
			logger.Error(err, "varmorutils.ReadMntNsID() failed", "container id", info.ContainerID, "pid", info.PID)
			continue
		}

		err = monitor.retrievePodInfo(&info)
		if err != nil {
			logger.Error(err, "monitor.retrievePodInfo() failed", "pod id", info.PodID)
			continue
		}

		info.ProfileName = extractVarmorProfileName(info)
		if info.ProfileName != "" {
			for _, ch := range monitor.taskStartChs {
				ch <- info
			}
		}
	}

	return nil
}
