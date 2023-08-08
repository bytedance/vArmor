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

package statusmanagerv1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	apparmorprofile "github.com/bytedance/vArmor/internal/profile/apparmor"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

// Data is an HTTP interface used for receiving the BehaviorData come from agents
func (m *StatusManager) Data(c *gin.Context) {
	logger := m.log.WithName("Data()")

	reqBody, err := getHttpBody(c)
	if err != nil {
		logger.Error(err, "getHttpBody()")
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	var data varmortypes.BehaviorData
	err = json.Unmarshal(reqBody, &data)
	if err != nil {
		logger.Error(err, "json.Unmarshal()")
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	logger.V(3).Info("enqueue dynamicResult from agent")
	m.dataQueue.Add(string(reqBody))
}

func (m *StatusManager) retrieveArmorProfileModel(namespace, name string) (*varmor.ArmorProfileModel, error) {
	apm, err := m.varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			newApm := varmor.ArmorProfileModel{}
			newApm.Name = name
			newApm.Namespace = namespace
			apm, err := m.varmorInterface.ArmorProfileModels(namespace).Create(context.Background(), &newApm, metav1.CreateOptions{})
			return apm, err
		}
		return nil, err
	}
	return apm, nil
}

func (m *StatusManager) mergeDynamicResult(apm *varmor.ArmorProfileModel, data *varmortypes.BehaviorData) {
	if apm.Spec.DynamicResult.Profiles == nil && len(data.DynamicResult.Profiles) != 0 {
		apm.Spec.DynamicResult.Profiles = make([]string, 0)
		apm.Spec.DynamicResult.Profiles = append(apm.Spec.DynamicResult.Profiles, data.DynamicResult.Profiles...)
	} else {
		for _, newProfile := range data.DynamicResult.Profiles {
			find := false
			for _, profile := range apm.Spec.DynamicResult.Profiles {
				if newProfile == profile {
					find = true
					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Profiles = append(apm.Spec.DynamicResult.Profiles, newProfile)
			}
		}
	}

	if apm.Spec.DynamicResult.Executions == nil && len(data.DynamicResult.Executions) != 0 {
		apm.Spec.DynamicResult.Executions = make([]string, 0)
		apm.Spec.DynamicResult.Executions = append(apm.Spec.DynamicResult.Executions, data.DynamicResult.Executions...)
	} else {
		for _, newExe := range data.DynamicResult.Executions {
			find := false
			for _, execution := range apm.Spec.DynamicResult.Executions {
				if newExe == execution {
					find = true
					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Executions = append(apm.Spec.DynamicResult.Executions, newExe)
			}
		}
	}

	if apm.Spec.DynamicResult.Files == nil && len(data.DynamicResult.Files) != 0 {
		apm.Spec.DynamicResult.Files = make([]varmor.File, 0)
		apm.Spec.DynamicResult.Files = append(apm.Spec.DynamicResult.Files, data.DynamicResult.Files...)
	} else {
		for _, newFile := range data.DynamicResult.Files {
			findFile := false
			for index, file := range apm.Spec.DynamicResult.Files {
				if newFile.Path == file.Path && newFile.Owner == file.Owner {
					findFile = true

					for _, newPerm := range newFile.Permissions {
						findPerm := false
						for _, perm := range file.Permissions {
							if newPerm == perm {
								findPerm = true
								break
							}
						}
						if !findPerm {
							apm.Spec.DynamicResult.Files[index].Permissions = append(apm.Spec.DynamicResult.Files[index].Permissions, newPerm)
						}
					}

					if file.OldPath == "" && newFile.OldPath != "" {
						apm.Spec.DynamicResult.Files[index].OldPath = newFile.OldPath
					}
					break
				}
			}
			if !findFile {
				apm.Spec.DynamicResult.Files = append(apm.Spec.DynamicResult.Files, newFile)
			}
		}
	}

	if apm.Spec.DynamicResult.Capabilities == nil && len(data.DynamicResult.Capabilities) != 0 {
		apm.Spec.DynamicResult.Capabilities = make([]string, 0)
		apm.Spec.DynamicResult.Capabilities = append(apm.Spec.DynamicResult.Capabilities, data.DynamicResult.Capabilities...)
	} else {
		for _, newCap := range data.DynamicResult.Capabilities {
			find := false
			for _, cap := range apm.Spec.DynamicResult.Capabilities {
				if newCap == cap {
					find = true
					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Capabilities = append(apm.Spec.DynamicResult.Capabilities, newCap)
			}
		}
	}

	if apm.Spec.DynamicResult.Networks == nil && len(data.DynamicResult.Networks) != 0 {
		apm.Spec.DynamicResult.Networks = make([]varmor.Network, 0)
		apm.Spec.DynamicResult.Networks = append(apm.Spec.DynamicResult.Networks, data.DynamicResult.Networks...)
	} else {
		for _, newNet := range data.DynamicResult.Networks {
			find := false
			for _, net := range apm.Spec.DynamicResult.Networks {
				if reflect.DeepEqual(newNet, net) {
					find = true
					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Networks = append(apm.Spec.DynamicResult.Networks, newNet)
			}
		}
	}

	if apm.Spec.DynamicResult.Ptraces == nil && len(data.DynamicResult.Ptraces) != 0 {
		apm.Spec.DynamicResult.Ptraces = make([]varmor.Ptrace, 0)
		apm.Spec.DynamicResult.Ptraces = append(apm.Spec.DynamicResult.Ptraces, data.DynamicResult.Ptraces...)
	} else {
		for _, newPtrace := range data.DynamicResult.Ptraces {
			find := false
			for index, ptrace := range apm.Spec.DynamicResult.Ptraces {
				if newPtrace.Peer == ptrace.Peer {
					find = true

					for _, newPerm := range newPtrace.Permissions {
						findPerm := false
						for _, perm := range ptrace.Permissions {
							if newPerm == perm {
								findPerm = true
								break
							}
						}
						if !findPerm {
							apm.Spec.DynamicResult.Ptraces[index].Permissions = append(apm.Spec.DynamicResult.Ptraces[index].Permissions, newPerm)
						}
					}

					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Ptraces = append(apm.Spec.DynamicResult.Ptraces, newPtrace)
			}
		}
	}

	if apm.Spec.DynamicResult.Signals == nil && len(data.DynamicResult.Signals) != 0 {
		apm.Spec.DynamicResult.Signals = make([]varmor.Signal, 0)
		apm.Spec.DynamicResult.Signals = append(apm.Spec.DynamicResult.Signals, data.DynamicResult.Signals...)
	} else {
		for _, newSignal := range data.DynamicResult.Signals {
			find := false
			for index, signal := range apm.Spec.DynamicResult.Signals {
				if newSignal.Peer == signal.Peer {
					find = true

					for _, newPerm := range newSignal.Permissions {
						findPerm := false
						for _, perm := range signal.Permissions {
							if newPerm == perm {
								findPerm = true
								break
							}
						}
						if !findPerm {
							apm.Spec.DynamicResult.Signals[index].Permissions = append(apm.Spec.DynamicResult.Signals[index].Permissions, newPerm)
						}
					}

					for _, newSig := range newSignal.Signals {
						findSig := false
						for _, sig := range signal.Signals {
							if newSig == sig {
								findSig = true
								break
							}
						}
						if !findSig {
							apm.Spec.DynamicResult.Signals[index].Signals = append(apm.Spec.DynamicResult.Signals[index].Signals, newSig)
						}
					}

					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Signals = append(apm.Spec.DynamicResult.Signals, newSignal)
			}
		}
	}

	if apm.Spec.DynamicResult.Unhandled == nil && len(data.DynamicResult.Unhandled) != 0 {
		apm.Spec.DynamicResult.Unhandled = make([]string, 0)
		apm.Spec.DynamicResult.Unhandled = append(apm.Spec.DynamicResult.Unhandled, data.DynamicResult.Unhandled...)
	} else {
		for _, newUnhandled := range data.DynamicResult.Unhandled {
			find := false
			for _, unhandled := range apm.Spec.DynamicResult.Unhandled {
				if newUnhandled == unhandled {
					find = true
					break
				}
			}
			if !find {
				apm.Spec.DynamicResult.Unhandled = append(apm.Spec.DynamicResult.Unhandled, newUnhandled)
			}
		}
	}
}

func (m *StatusManager) updateArmorProfileModel(apm *varmor.ArmorProfileModel) (*varmor.ArmorProfileModel, error) {
	return m.varmorInterface.ArmorProfileModels(apm.Namespace).Update(context.Background(), apm, metav1.UpdateOptions{})
}

// Unlike updatePolicyStatus(), behavioral modeling is an asynchronous operation so that state transitions do not need to be considered
func (m *StatusManager) updateModelingStatus(statusKey string, behaviorData *varmortypes.BehaviorData) error {

	if behaviorData.Status != varmortypes.Failed && behaviorData.Status != varmortypes.Succeeded {
		return fmt.Errorf("behaviorData.Status is illegal")
	}

	var modelingStatus varmortypes.ModelingStatus

	if _, ok := m.ModelingStatuses[statusKey]; !ok {
		modelingStatus.CompletedNumber = 0
		modelingStatus.FailedNumber = 0
		modelingStatus.NodeMessages = make(map[string]string, m.desiredNumber)
		m.ModelingStatuses[statusKey] = modelingStatus
	}

	modelingStatus = m.ModelingStatuses[statusKey]
	switch behaviorData.Status {
	case varmortypes.Failed:
		modelingStatus.FailedNumber += 1
		modelingStatus.NodeMessages[behaviorData.NodeName] = behaviorData.Message
	case varmortypes.Succeeded:
		modelingStatus.CompletedNumber += 1
		modelingStatus.NodeMessages[behaviorData.NodeName] = string(varmortypes.ArmorProfileModelReady)
	}

	m.ModelingStatuses[statusKey] = modelingStatus

	return nil
}

func (m *StatusManager) updateArmorProfileModelStatus(apm *varmor.ArmorProfileModel, modelingStatus *varmortypes.ModelingStatus, complete bool) error {
	var conditions []varmor.ArmorProfileModelCondition
	for nodeName, message := range modelingStatus.NodeMessages {
		if message != string(varmortypes.ArmorProfileModelReady) {
			c := newArmorProfileModelCondition(nodeName, varmortypes.ArmorProfileModelReady, v1.ConditionFalse, "", message)
			conditions = append(conditions, *c)
		}
	}

	if reflect.DeepEqual(apm.Status.Conditions, conditions) &&
		apm.Status.CompletedNumber == modelingStatus.CompletedNumber {
		return nil
	}

	apm.Status.DesiredNumber = m.desiredNumber
	apm.Status.CompletedNumber = modelingStatus.CompletedNumber
	if complete {
		apm.Status.Ready = true
	}
	if len(conditions) > 0 {
		apm.Status.Conditions = conditions
	} else {
		apm.Status.Conditions = nil
	}

	_, err := m.varmorInterface.ArmorProfileModels(apm.Namespace).UpdateStatus(context.Background(), apm, metav1.UpdateOptions{})

	return err
}

func (m *StatusManager) syncData(data string) error {
	logger := m.log.WithName("syncData()")

	startTime := time.Now()
	logger.V(3).Info("started syncing data", "startTime", startTime)
	defer func() {
		logger.V(3).Info("finished syncing data", "processingTime", time.Since(startTime).String())
	}()

	// Unmarshal the behavior data comes from agent
	var behaviorData varmortypes.BehaviorData
	err := json.Unmarshal([]byte(data), &behaviorData)
	if err != nil {
		logger.Error(err, "json.Unmarshal() behaviorData failed")
		return nil
	}
	logger.Info("1. receive behavior data from agent", "profile", behaviorData.ProfileName, "node", behaviorData.NodeName)

	// Merge the behavior data to the ArmorProfileModel objet
	apm, err := m.retrieveArmorProfileModel(behaviorData.Namespace, behaviorData.ProfileName)
	if err != nil {
		logger.Error(err, "m.retrieveArmorProfileModel()")
		return err
	}
	oldDynamicResult := apm.Spec.DynamicResult.DeepCopy()
	m.mergeDynamicResult(apm, &behaviorData)
	needUpdateAPM := !reflect.DeepEqual(oldDynamicResult, &apm.Spec.DynamicResult)
	if !needUpdateAPM {
		logger.Info("2. no new behavior data to update to ArmorProfileModel", "profile", behaviorData.ProfileName, "node", behaviorData.NodeName)
	} else {
		// Update ArmorProfileModel object
		logger.Info("2. update new behavior data to ArmorProfileModel", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
		apm, err = m.updateArmorProfileModel(apm)
		if err != nil {
			logger.Error(err, "updateArmorProfileModel()")
			return err
		}
	}

	// Update the modeling status cache
	statusKey, err := generateModelingStatusKey(&behaviorData)
	if err != nil {
		logger.Error(err, "generatemodelingStatusKey()")
		return nil
	}
	err = m.updateModelingStatus(statusKey, &behaviorData)
	if err != nil {
		logger.Error(err, "updateModelingStatus()")
		return nil
	}
	logger.Info("3. modeling status cache updated", "key", statusKey, "value", m.ModelingStatuses[statusKey], "desired number", m.desiredNumber)

	modelingStatus := m.ModelingStatuses[statusKey]
	complete := false

	if modelingStatus.CompletedNumber >= m.desiredNumber {
		complete = true

		logger.Info("3.1 all modeller completed")

		if needUpdateAPM {
			// Build the final AppArmor Profile
			logger.Info("3.1.1 start building AppArmor profile", "profile", behaviorData.ProfileName)
			builder := apparmorprofile.NewProfileBuilder(&apm.Spec.DynamicResult, m.debug)
			profile, err := builder.Build()
			if err != nil {
				logger.Error(err, "varmorprofile.NewProfileBuilder()")
				return err
			} else {
				// Update ArmorProfileModel
				logger.Info("3.1.2 update AppArmor profile to ArmorProfileModel", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
				apm.Spec.Profile.Content = profile
				apm.Spec.Profile.Name = behaviorData.ProfileName
				apm.Spec.Profile.Mode = "enforce"
				apm, err = m.updateArmorProfileModel(apm)
				if err != nil {
					logger.Error(err, "m.updateArmorProfileModel()")
					return err
				}
			}
		}
		logger.Info("3.2 send signal to UpdateModeCh", "status key", statusKey)
		m.UpdateModeCh <- statusKey
	}

	// Update ArmorProfileModel/status
	logger.Info("4. update ArmorProfileModel/status", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
	err = m.updateArmorProfileModelStatus(apm, &modelingStatus, complete)
	if err != nil {
		logger.Error(err, "updateArmorProfileModelStatus()")
	}

	return nil
}

func (m *StatusManager) handleDataErr(err error, data interface{}) {
	logger := m.log
	if err == nil {
		m.dataQueue.Forget(data)
		return
	}

	if m.dataQueue.NumRequeues(data) < maxRetries {
		logger.Error(err, "failed to sync data", "data", data)
		m.dataQueue.AddRateLimited(data)
		return
	}

	utilruntime.HandleError(err)
	logger.V(3).Info("dropping data out of dataQueue", "key", data)
	m.dataQueue.Forget(data)
}

func (m *StatusManager) processNextDataWorkItem() bool {
	data, quit := m.dataQueue.Get()
	if quit {
		return false
	}
	defer m.dataQueue.Done(data)

	err := m.syncData(data.(string))
	m.handleDataErr(err, data)

	return true
}

func (m *StatusManager) dataWorker() {
	for m.processNextDataWorkItem() {
	}
}
