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
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

const (
	// maxRetries used for setting the retry times of sync failed.
	maxRetries = 5
)

// Status is the API interface which receives the status come from agents.
// The status is cached to a queue and then processed asynchronously.
func (m *StatusManager) Status(c *gin.Context) {
	logger := m.log.WithName("Status()")

	var profileStatus varmortypes.ProfileStatus
	if err := c.ShouldBindJSON(&profileStatus); err != nil {
		logger.Error(err, "c.ShouldBindJSON() failed")
		c.JSON(http.StatusBadRequest, err)
		return
	}

	if profileStatus.Namespace == "" || profileStatus.ProfileName == "" ||
		profileStatus.NodeName == "" || profileStatus.Status == "" {
		err := fmt.Errorf("request is illegal")
		logger.Error(err, "bad request body")
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	logger.V(2).Info("enqueue ProfileStatus from agent")
	m.statusQueue.Add(profileStatus)

	if m.metricsModule.Enabled {
		m.handleProfileStatusUpdate(profileStatus)
	}

	c.Status(http.StatusOK)
}

func (m *StatusManager) handleProfileStatusUpdate(status varmortypes.ProfileStatus) {
	ctx := context.Background()
	// label info
	labels := []attribute.KeyValue{
		attribute.String("node_name", status.NodeName),
	}
	attrSet := attribute.NewSet(labels...)

	if status.Status == varmortypes.Succeeded {
		m.profileSuccess.Add(ctx, 1, metric.WithAttributeSet(attrSet))
	} else {
		m.profileFailure.Add(ctx, 1, metric.WithAttributeSet(attrSet))
	}

	m.profileChangeCount.Add(ctx, 1, metric.WithAttributeSet(attrSet))
}

// disable syncStatusMetricsLoop until otel support clear metrics
//func (m *StatusManager) syncStatusMetricsLoop() {
//	ctx := context.Background()
//	for {
//		time.Sleep(time.Duration(m.metricsModule.Refresh) * time.Second)
//		logger := m.log.WithName("syncStatusMetricsLoop()")
//		logger.Info("start syncing status metrics")
//		m.profileStatusPerNode = m.metricsModule.RegisterFloat64Gauge("varmor_profile_status_per_node", "Profile status per node (1=success, 0=failure)")
//		for key, status := range m.policyStatuses {
//			namespace, name, err := policyStatusKeyGetInfo(key)
//			if err != nil {
//				logger.Error(err, "policyStatusKeyGetInfo()")
//				continue
//			}
//			for nodeName, nodeMessage := range status.NodeMessages {
//				labels := []attribute.KeyValue{
//					attribute.String("namespace", namespace),
//					attribute.String("profile_name", name),
//					attribute.String("node_name", nodeName),
//					attribute.Int64("timestamp", time.Now().Unix()),
//				}
//				attrSet := attribute.NewSet(labels...)
//				if nodeMessage == string(varmortypes.ArmorProfileReady) {
//					m.profileStatusPerNode.Record(ctx, 1, metric.WithAttributeSet(attrSet)) // 1 mean success
//				} else {
//					m.profileStatusPerNode.Record(ctx, 0, metric.WithAttributeSet(attrSet)) // 0 mean failure
//				}
//			}
//		}
//	}
//}

// updatePolicyStatus update StatusManager.policyStatuses[statusKey] with profileStatus which comes from agent.
func (m *StatusManager) updatePolicyStatus(statusKey string, profileStatus *varmortypes.ProfileStatus) error {
	m.policyStatusesLock.Lock()
	defer m.policyStatusesLock.Unlock()

	if profileStatus.Status != varmortypes.Failed && profileStatus.Status != varmortypes.Succeeded {
		return fmt.Errorf("profileStatus.Status is illegal")
	}

	var policyStatus varmortypes.PolicyStatus

	if _, ok := m.policyStatuses[statusKey]; !ok {
		policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)
		m.policyStatuses[statusKey] = policyStatus
	}

	policyStatus = m.policyStatuses[statusKey]
	switch profileStatus.Status {
	case varmortypes.Failed:
		if nodeMessage, ok := policyStatus.NodeMessages[profileStatus.NodeName]; ok {

			if nodeMessage == string(varmor.ArmorProfileReady) {
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

			if nodeMessage != string(varmor.ArmorProfileReady) {
				// Failed status -> Succeeded status
				policyStatus.FailedNumber -= 1
				policyStatus.SuccessedNumber += 1
				policyStatus.NodeMessages[profileStatus.NodeName] = string(varmor.ArmorProfileReady)
			}

		} else {
			// new Succeeded status
			policyStatus.SuccessedNumber += 1
			policyStatus.NodeMessages[profileStatus.NodeName] = string(varmor.ArmorProfileReady)
		}
	}

	m.policyStatuses[statusKey] = policyStatus

	return nil
}

// syncData processes the status of profiles asynchronously.
func (m *StatusManager) syncStatus(profileStatus varmortypes.ProfileStatus) error {
	logger := m.log.WithName("syncStatus()")

	startTime := time.Now()
	logger.V(2).Info("started syncing status", "startTime", startTime)
	defer func() {
		logger.V(2).Info("finished syncing status", "processingTime", time.Since(startTime).String())
	}()

	logger.Info("1. receive profile status from agent", "profile", profileStatus.ProfileName,
		"node", profileStatus.NodeName, "status", profileStatus.Status, "message", profileStatus.Message)

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

	m.policyStatusesLock.RLock()
	successedNumber := m.policyStatuses[statusKey].SuccessedNumber
	failedNumber := m.policyStatuses[statusKey].FailedNumber
	m.policyStatusesLock.RUnlock()
	status := fmt.Sprintf("successed/failed/desired (%d/%d/%d)", successedNumber, failedNumber, m.desiredNumber)
	logger.Info("2. policy status cache updated", "key", statusKey, "status", status)

	// Schedule batch update instead of immediate update
	// The batchWorker will send the signal to UpdateStatusCh after the time window
	m.pendingUpdatesLock.Lock()
	m.pendingUpdates[statusKey] = time.Now()
	m.pendingUpdatesLock.Unlock()
	logger.Info("3. scheduled batch update", "status key", statusKey)

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
	logger.V(2).Info("dropping status out of statusQueue", "key", status)
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
