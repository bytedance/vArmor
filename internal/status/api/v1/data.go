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
	"os"
	"path"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	apparmorprofile "github.com/bytedance/vArmor/internal/profile/apparmor"
	seccompprofile "github.com/bytedance/vArmor/internal/profile/seccomp"
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

// ExportArmorProfileModel export the armorprofilemodel object with all behavior data
func (m *StatusManager) ExportArmorProfileModel(c *gin.Context) {
	m.log.Info("Export ArmorProfileModel object", "namespace", c.Param("namespace"), "name", c.Param("name"))
	apm, err := m.retrieveArmorProfileModel(c.Param("namespace"), c.Param("name"), false)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, apm)
}

func (m *StatusManager) retrieveArmorProfileModel(namespace, name string, createNew bool) (*varmor.ArmorProfileModel, error) {
	apm, err := m.varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) && createNew {
			// Create a new ArmorProfileModel object
			a := varmor.ArmorProfileModel{}
			a.Name = name
			a.Namespace = namespace
			a.Data.StorageType = varmortypes.StorageTypeCRDInternal
			return m.varmorInterface.ArmorProfileModels(namespace).Create(context.Background(), &a, metav1.CreateOptions{})
		}
		return nil, err
	}

	// Load behavior data of the ArmorProfileModel object from the local file
	if apm.Data.StorageType != varmortypes.StorageTypeCRDInternal {
		fileName := path.Join(varmorconfig.BehaviorDataDirectory, name)
		data, err := os.ReadFile(fileName)
		if err != nil {
			m.log.Error(err, "Read "+fileName+" failed")
			return apm, nil
		}

		a := varmor.ArmorProfileModel{}
		err = json.Unmarshal(data, &a)
		if err != nil {
			m.log.Error(err, "Unmarshal "+fileName+" failed")
			return apm, nil
		}
		apm.Data.DynamicResult = a.Data.DynamicResult
		apm.Data.StaticResult = a.Data.StaticResult
	}

	return apm, nil
}

func mergeAppArmorResult(apm *varmor.ArmorProfileModel, data *varmortypes.BehaviorData) {
	if apm.Data.DynamicResult.AppArmor == nil {
		apm.Data.DynamicResult.AppArmor = &varmor.AppArmor{}
	}

	for _, newProfile := range data.DynamicResult.AppArmor.Profiles {
		find := false
		for _, profile := range apm.Data.DynamicResult.AppArmor.Profiles {
			if newProfile == profile {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Profiles = append(apm.Data.DynamicResult.AppArmor.Profiles, newProfile)
		}
	}

	for _, newExe := range data.DynamicResult.AppArmor.Executions {
		find := false
		for _, execution := range apm.Data.DynamicResult.AppArmor.Executions {
			if newExe == execution {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Executions = append(apm.Data.DynamicResult.AppArmor.Executions, newExe)
		}
	}

	for _, newFile := range data.DynamicResult.AppArmor.Files {
		findFile := false
		for index, file := range apm.Data.DynamicResult.AppArmor.Files {
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
						apm.Data.DynamicResult.AppArmor.Files[index].Permissions = append(apm.Data.DynamicResult.AppArmor.Files[index].Permissions, newPerm)
					}
				}

				if file.OldPath == "" && newFile.OldPath != "" {
					apm.Data.DynamicResult.AppArmor.Files[index].OldPath = newFile.OldPath
				}
				break
			}
		}
		if !findFile {
			apm.Data.DynamicResult.AppArmor.Files = append(apm.Data.DynamicResult.AppArmor.Files, newFile)
		}
	}

	for _, newCap := range data.DynamicResult.AppArmor.Capabilities {
		find := false
		for _, cap := range apm.Data.DynamicResult.AppArmor.Capabilities {
			if newCap == cap {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Capabilities = append(apm.Data.DynamicResult.AppArmor.Capabilities, newCap)
		}
	}

	for _, newNet := range data.DynamicResult.AppArmor.Networks {
		find := false
		for _, net := range apm.Data.DynamicResult.AppArmor.Networks {
			if reflect.DeepEqual(newNet, net) {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Networks = append(apm.Data.DynamicResult.AppArmor.Networks, newNet)
		}
	}

	for _, newPtrace := range data.DynamicResult.AppArmor.Ptraces {
		find := false
		for index, ptrace := range apm.Data.DynamicResult.AppArmor.Ptraces {
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
						apm.Data.DynamicResult.AppArmor.Ptraces[index].Permissions = append(apm.Data.DynamicResult.AppArmor.Ptraces[index].Permissions, newPerm)
					}
				}

				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Ptraces = append(apm.Data.DynamicResult.AppArmor.Ptraces, newPtrace)
		}
	}

	for _, newSignal := range data.DynamicResult.AppArmor.Signals {
		find := false
		for index, signal := range apm.Data.DynamicResult.AppArmor.Signals {
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
						apm.Data.DynamicResult.AppArmor.Signals[index].Permissions = append(apm.Data.DynamicResult.AppArmor.Signals[index].Permissions, newPerm)
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
						apm.Data.DynamicResult.AppArmor.Signals[index].Signals = append(apm.Data.DynamicResult.AppArmor.Signals[index].Signals, newSig)
					}
				}

				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Signals = append(apm.Data.DynamicResult.AppArmor.Signals, newSignal)
		}
	}

	for _, newUnhandled := range data.DynamicResult.AppArmor.Unhandled {
		find := false
		for _, unhandled := range apm.Data.DynamicResult.AppArmor.Unhandled {
			if newUnhandled == unhandled {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Unhandled = append(apm.Data.DynamicResult.AppArmor.Unhandled, newUnhandled)
		}
	}
}

func mergeSeccompResult(apm *varmor.ArmorProfileModel, data *varmortypes.BehaviorData) {
	if apm.Data.DynamicResult.Seccomp == nil {
		apm.Data.DynamicResult.Seccomp = &varmor.Seccomp{}
	}

	for _, newSyscall := range data.DynamicResult.Seccomp.Syscalls {
		find := false
		for _, syscall := range apm.Data.DynamicResult.Seccomp.Syscalls {
			if newSyscall == syscall {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.Seccomp.Syscalls = append(apm.Data.DynamicResult.Seccomp.Syscalls, newSyscall)
		}
	}
}

func (m *StatusManager) updateArmorProfileModel(apm *varmor.ArmorProfileModel) (*varmor.ArmorProfileModel, error) {
	var regain bool
	var err error

	update := func() (e error) {
		if regain {
			a, e := m.varmorInterface.ArmorProfileModels(apm.Namespace).Get(context.Background(), apm.Name, metav1.GetOptions{})
			if e != nil {
				if k8errors.IsNotFound(e) {
					err = e
					return nil
				}
				return e
			}
			apm.ResourceVersion = a.ResourceVersion
		}

		a, e := m.varmorInterface.ArmorProfileModels(apm.Namespace).Update(context.Background(), apm, metav1.UpdateOptions{})
		if e == nil {
			apm = a
		} else {
			if k8errors.IsRequestEntityTooLargeError(e) {
				err = e
				return nil
			}
		}
		return e
	}
	e := retry.RetryOnConflict(retry.DefaultRetry, update)
	if e == nil {
		return apm, err
	} else {
		return apm, e
	}
}

func (m *StatusManager) persistArmorProfileModel(apm *varmor.ArmorProfileModel) (*varmor.ArmorProfileModel, error) {
	if apm.Data.StorageType == varmortypes.StorageTypeCRDInternal {
		apm, err := m.updateArmorProfileModel(apm)
		if err == nil {
			return apm, nil
		}

		if !k8errors.IsRequestEntityTooLargeError(err) {
			return apm, err
		}
	}

	// The limit of object is 3145728. Persist the object into the backend storage
	fileName := path.Join(varmorconfig.BehaviorDataDirectory, apm.Name)
	m.log.Info("Persist the data into a local file because the data is too large to store into an ArmorProfileModel object",
		"namespace", apm.Namespace, "name", apm.Name, "path", fileName)
	jsonData, err := json.MarshalIndent(apm, "", "  ")
	if err == nil {
		err = os.WriteFile(fileName, jsonData, 0600)
		if err != nil {
			m.log.Error(err, "unable persist the behavior data into the local file")
		}
	} else {
		m.log.Error(err, "unable marshal the ArmorProfileModel object")
	}

	// Cache behavior data
	dynamic := apm.Data.DynamicResult
	static := apm.Data.StaticResult

	// Update the ArmorProfileModel object without behavior data and profiles
	apm.Data.DynamicResult = varmor.DynamicResult{}
	apm.Data.StaticResult = varmor.StaticResult{}
	apm.Data.Profile.Content = ""
	apm.Data.Profile.BpfContent = nil
	apm.Data.Profile.SeccompContent = ""
	apm.Data.StorageType = varmortypes.StorageTypeLocalDisk
	a, err := m.updateArmorProfileModel(apm)

	// Recover behavior data
	a.Data.DynamicResult = dynamic
	a.Data.StaticResult = static
	return a, err
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

	// Merge the behavior data into the ArmorProfileModel objet
	apm, err := m.retrieveArmorProfileModel(behaviorData.Namespace, behaviorData.ProfileName, true)
	if err != nil {
		logger.Error(err, "m.retrieveArmorProfileModel()")
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
		apm, err = m.persistArmorProfileModel(apm)
		if err != nil {
			logger.Error(err, "m.persistArmorProfileModel()")
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
	logger.Info("3. modeling status cache updated", "key", statusKey, "value", m.ModelingStatuses[statusKey], "desired number", m.desiredNumber)

	modelingStatus := m.ModelingStatuses[statusKey]
	complete := false

	// Build profiles and Update ArmorProfile for the BehaviorModeling mode.
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
		apm, err = m.persistArmorProfileModel(apm)
		if err != nil {
			logger.Error(err, "m.persistArmorProfileModel()")
		}

		logger.Info("3.3. send signal to UpdateModeCh", "status key", statusKey)
		m.UpdateModeCh <- statusKey
	}

	// Update ArmorProfileModel/status
	logger.Info("4. update ArmorProfileModel/status", "namespace", behaviorData.Namespace, "name", behaviorData.ProfileName)
	// Set the data to empty before updating the status in case the data exceeds the limit.
	apm.Data = varmor.ArmorProfileModelData{}
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
