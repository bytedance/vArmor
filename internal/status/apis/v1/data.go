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
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorapm "github.com/bytedance/vArmor/internal/apm"
	apparmorprofile "github.com/bytedance/vArmor/internal/profile/apparmor"
	seccompprofile "github.com/bytedance/vArmor/internal/profile/seccomp"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

// Data is the API interface that receives the behavior data from agents.
// The behavioral data is cached to a queue and then processed asynchronously.
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

	logger.V(2).Info("enqueue dynamicResult from agent")
	m.dataQueue.Add(string(reqBody))
}

// updateModelingStatus update StatusManager.modelingStatuses[statusKey] with behaviorData which comes from agent.
// Unlike updatePolicyStatus(), behavioral modeling is an asynchronous operation
// so that state transitions do not need to be considered.
func (m *StatusManager) updateModelingStatus(statusKey string, behaviorData *varmortypes.BehaviorData) error {
	m.modelingStatusesLock.Lock()
	defer m.modelingStatusesLock.Unlock()

	if behaviorData.Status != varmortypes.Failed && behaviorData.Status != varmortypes.Succeeded {
		return fmt.Errorf("behaviorData.Status is illegal")
	}

	var modelingStatus varmortypes.ModelingStatus

	if _, ok := m.modelingStatuses[statusKey]; !ok {
		modelingStatus.CompletedNumber = 0
		modelingStatus.FailedNumber = 0
		modelingStatus.NodeMessages = make(map[string]string, m.desiredNumber)
		m.modelingStatuses[statusKey] = modelingStatus
	}

	modelingStatus = m.modelingStatuses[statusKey]
	switch behaviorData.Status {
	case varmortypes.Failed:
		modelingStatus.FailedNumber += 1
		modelingStatus.NodeMessages[behaviorData.NodeName] = behaviorData.Message
	case varmortypes.Succeeded:
		modelingStatus.CompletedNumber += 1
		modelingStatus.NodeMessages[behaviorData.NodeName] = string(varmortypes.ArmorProfileModelReady)
	}

	m.modelingStatuses[statusKey] = modelingStatus

	return nil
}

// syncData processes the behavior data asynchronously.
func (m *StatusManager) syncData(data string) error {
	logger := m.log.WithName("syncData()")

	startTime := time.Now()
	logger.V(2).Info("started syncing data", "startTime", startTime)
	defer func() {
		logger.V(2).Info("finished syncing data", "processingTime", time.Since(startTime).String())
	}()

	// Unmarshal the behavior data comes from agent
	var behaviorData varmortypes.BehaviorData
	err := json.Unmarshal([]byte(data), &behaviorData)
	if err != nil {
		logger.Error(err, "json.Unmarshal() behaviorData failed")
		return nil
	}
	logger.Info("1. receive behavior data from agent", "profile", behaviorData.ProfileName, "node", behaviorData.NodeName)

	// Merge the behavior data into the ArmorProfileModel objet
	apm, err := varmorapm.RetrieveArmorProfileModel(m.varmorInterface, behaviorData.Namespace, behaviorData.ProfileName, true, logger)
	if err != nil {
		logger.Error(err, "varmorapm.RetrieveArmorProfileModel()")
		return err
	}
	oldDynamicResult := apm.Data.DynamicResult.DeepCopy()
	if behaviorData.DynamicResult.AppArmor != nil {
		mergeAppArmorResult(apm, &behaviorData)
	}
	if behaviorData.DynamicResult.Seccomp != nil {
		mergeSeccompResult(apm, &behaviorData)
	}
	if reflect.DeepEqual(oldDynamicResult, &apm.Data.DynamicResult) {
		logger.Info("2. no new behavior data to update to ArmorProfileModel", "profile", behaviorData.ProfileName, "node", behaviorData.NodeName)
	} else {
		// Update ArmorProfileModel object
		logger.Info("2. update new behavior data to ArmorProfileModel", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
		apm, err = varmorapm.PersistArmorProfileModel(m.varmorInterface, apm, logger)
		if err != nil {
			logger.Error(err, "varmorapm.PersistArmorProfileModel()")
		}
	}

	// Update the modeling status cache
	statusKey, err := generateModelingStatusKey(&behaviorData)
	if err != nil {
		logger.Error(err, "generatemodelingStatusKey()", "behavior data", behaviorData)
		return nil
	}
	err = m.updateModelingStatus(statusKey, &behaviorData)
	if err != nil {
		logger.Error(err, "updateModelingStatus()")
		return nil
	}
	modelingStatus := m.modelingStatuses[statusKey]
	logger.Info("3. modeling status cache updated", "key", statusKey, "value", modelingStatus, "desired number", m.desiredNumber)

	complete := false

	// Build profiles and update ArmorProfile for the BehaviorModeling mode.
	if modelingStatus.CompletedNumber >= m.desiredNumber {
		complete = true

		logger.Info("3.1. all modeller completed")

		// Build the final AppArmor Profile
		if apm.Data.DynamicResult.AppArmor != nil {
			logger.Info("3.1.1. build AppArmor profile with behavior model")
			apparmorProfile, err := apparmorprofile.GenerateProfileWithBehaviorModel(apm.Data.DynamicResult.AppArmor, m.debug)
			if err != nil {
				logger.Info("apparmorprofile.GenerateProfileWithBehaviorModel() failed", "info", err)
			}
			apm.Data.Profile.Content = apparmorProfile
		}

		if apm.Data.DynamicResult.Seccomp != nil {
			// Build the final Seccomp Profile
			logger.Info("3.1.2. build Seccomp profile with behavior model")
			seccompProfile, err := seccompprofile.GenerateProfileWithBehaviorModel(apm.Data.DynamicResult.Seccomp)
			if err != nil {
				logger.Info("seccompprofile.GenerateProfileWithBehaviorModel() failed", "info", err)
			}
			apm.Data.Profile.SeccompContent = seccompProfile
		}

		// Update ArmorProfileModel object
		logger.Info("3.2. update profile to ArmorProfileModel", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
		apm.Data.Profile.Name = behaviorData.ProfileName
		apm, err = varmorapm.PersistArmorProfileModel(m.varmorInterface, apm, logger)
		if err != nil {
			logger.Error(err, "varmorapm.PersistArmorProfileModel()")
		}

		logger.Info("3.3. send signal to UpdateModeCh", "status key", statusKey)
		m.UpdateModeCh <- statusKey
	}

	// Update ArmorProfileModel/status
	logger.Info("4. update ArmorProfileModel/status", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
	// Set the data to empty before updating the status in case the data exceeds the limit.
	apm.Data = varmor.ArmorProfileModelData{}
	err = UpdateArmorProfileModelStatus(m.varmorInterface, apm, &modelingStatus, m.desiredNumber, complete)
	if err != nil {
		logger.Error(err, "UpdateArmorProfileModelStatus()")
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
	logger.V(2).Info("dropping data out of dataQueue", "key", data)
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
