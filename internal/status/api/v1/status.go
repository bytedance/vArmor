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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	varmortypes "github.com/bytedance/vArmor/internal/types"
)

const (
	// maxRetries used for setting the retry times of sync failed.
	maxRetries = 5
)

// Status is an HTTP interface used for receiving the status come from agents.
func (m *StatusManager) Status(c *gin.Context) {
	logger := m.log.WithName("Status()")

	reqBody, err := getHttpBody(c)
	if err != nil {
		logger.Error(err, "getHttpBody()")
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	var profileStatus varmortypes.ProfileStatus
	err = json.Unmarshal(reqBody, &profileStatus)
	if err != nil {
		logger.Error(err, "json.Unmarshal()")
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	if profileStatus.Namespace == "" || profileStatus.ProfileName == "" ||
		profileStatus.NodeName == "" || profileStatus.Status == "" {
		err = fmt.Errorf("request is illegal")
		logger.Error(err, "bad request body")
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	logger.V(3).Info("enqueue ProfileStatus from agent")
	m.statusQueue.Add(profileStatus)
	if m.metricsModule.Enabled == true {
		go m.HandleProfileStatusUpdate(profileStatus)
	}
}
func (m *StatusManager) HandleProfileStatusUpdate(status varmortypes.ProfileStatus) {
	ctx := context.Background()
	// label info
	labels := []attribute.KeyValue{
		attribute.String("namespace", status.Namespace),
		attribute.String("profile_name", status.ProfileName),
		attribute.String("node_name", status.NodeName),
	}

	if status.Status == "Success" {
		m.profileSuccess.Add(ctx, 1, metric.WithAttributes(labels...))
	} else {
		m.profileFailure.Add(ctx, 1, metric.WithAttributes(labels...))
	}

	m.profileChangeCount.Add(ctx, 1, metric.WithAttributes(labels...))

	if status.Status == "Success" {
		m.profileStatusPerNode.Record(ctx, 1, metric.WithAttributes(labels...)) // 1 mean success
	} else {
		m.profileStatusPerNode.Record(ctx, 0, metric.WithAttributes(labels...)) // 0 mean failure
	}

}

// updatePolicyStatus update StatusManager.PolicyStatuses[statusKey] with profileStatus which comes from agent.
func (m *StatusManager) updatePolicyStatus(statusKey string, profileStatus *varmortypes.ProfileStatus) error {

	if profileStatus.Status != varmortypes.Failed && profileStatus.Status != varmortypes.Succeeded {
		return fmt.Errorf("profileStatus.Status is illegal")
	}

	var policyStatus varmortypes.PolicyStatus

	if _, ok := m.PolicyStatuses[statusKey]; !ok {
		policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)
		m.PolicyStatuses[statusKey] = policyStatus
	}

	policyStatus = m.PolicyStatuses[statusKey]
	switch profileStatus.Status {
	case varmortypes.Failed:
		if nodeMessage, ok := policyStatus.NodeMessages[profileStatus.NodeName]; ok {

			if nodeMessage == string(varmortypes.ArmorProfileReady) {
				// Succeeded status -> Failed status
				policyStatus.SuccessedNumber -= 1
				policyStatus.FailedNumber += 1
				policyStatus.NodeMessages[profileStatus.NodeName] = profileStatus.Message
			} else {
				// Failed status -> Failed status
				policyStatus.NodeMessages[profileStatus.NodeName] = profileStatus.Message
			}

		} else {
			// new Failed status
			policyStatus.FailedNumber += 1
			policyStatus.NodeMessages[profileStatus.NodeName] = profileStatus.Message
		}

	case varmortypes.Succeeded:
		if nodeMessage, ok := policyStatus.NodeMessages[profileStatus.NodeName]; ok {

			if nodeMessage != string(varmortypes.ArmorProfileReady) {
				// Failed status -> Succeeded status
				policyStatus.FailedNumber -= 1
				policyStatus.SuccessedNumber += 1
				policyStatus.NodeMessages[profileStatus.NodeName] = string(varmortypes.ArmorProfileReady)
			}

		} else {
			// new Succeeded status
			policyStatus.SuccessedNumber += 1
			policyStatus.NodeMessages[profileStatus.NodeName] = string(varmortypes.ArmorProfileReady)
		}
	}

	m.PolicyStatuses[statusKey] = policyStatus

	return nil
}

func (m *StatusManager) syncStatus(profileStatus varmortypes.ProfileStatus) error {
	logger := m.log.WithName("syncStatus()")

	startTime := time.Now()
	logger.V(3).Info("started syncing status", "startTime", startTime)
	defer func() {
		logger.V(3).Info("finished syncing status", "processingTime", time.Since(startTime).String())
	}()

	logger.Info("1. receive profile status from agent", "profile", profileStatus.ProfileName, "node", profileStatus.NodeName, "status", profileStatus.Status)

	// Update the policy status cache.
	statusKey, err := generatePolicyStatusKey(&profileStatus)
	if err != nil {
		logger.Error(err, "generatePolicyStatusKey()")
		return nil
	}
	err = m.updatePolicyStatus(statusKey, &profileStatus)
	if err != nil {
		logger.Error(err, "updatePolicyStatus()")
		return nil
	}

	status := fmt.Sprintf("successed/failed/desired (%d/%d/%d)", m.PolicyStatuses[statusKey].SuccessedNumber, m.PolicyStatuses[statusKey].FailedNumber, m.desiredNumber)
	logger.Info("2. policy status cache updated", "key", statusKey, "status", status)

	logger.Info("3. send signal to UpdateStatusCh", "status key", statusKey)
	m.UpdateStatusCh <- statusKey

	return nil
}

func (m *StatusManager) handleStatusErr(err error, status interface{}) {
	logger := m.log
	if err == nil {
		m.statusQueue.Forget(status)
		return
	}

	if m.statusQueue.NumRequeues(status) < maxRetries {
		logger.Error(err, "failed to sync status", "status", status)
		m.statusQueue.AddRateLimited(status)
		return
	}

	utilruntime.HandleError(err)
	logger.V(3).Info("dropping status out of statusQueue", "key", status)
	m.statusQueue.Forget(status)
}

func (m *StatusManager) processNextStatusWorkItem() bool {
	status, quit := m.statusQueue.Get()
	if quit {
		return false
	}
	defer m.statusQueue.Done(status)

	err := m.syncStatus(status.(varmortypes.ProfileStatus))
	m.handleStatusErr(err, status)

	return true
}

func (m *StatusManager) statusWorker() {
	for m.processNextStatusWorkItem() {
	}
}
