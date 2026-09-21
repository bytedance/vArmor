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

package statusmanagerv1

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorfake "github.com/bytedance/vArmor/pkg/client/clientset/versioned/fake"
)

func newPeriodicStatusTestManager(capacity, policies int) *StatusManager {
	client := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node"}})
	m := &StatusManager{
		coreInterface:  client.CoreV1(),
		policyStatuses: make(map[string]varmortypes.PolicyStatus),
		pendingUpdates: make(map[string]time.Time),
		UpdateStatusCh: make(chan string, capacity),
		log:            logr.Discard(),
	}
	for i := 0; i < policies; i++ {
		m.policyStatuses[fmt.Sprintf("default/policy-%d", i)] = varmortypes.PolicyStatus{
			NodeMessages: map[string]string{"node": string(varmor.ArmorProfileReady)},
		}
	}
	return m
}

// No consumer runs during a periodic refresh: reconcileStatus itself calls it.
func refreshStatusWithoutConsumer(t *testing.T, m *StatusManager) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		m.updateAllCRStatus(logr.Discard())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// Release a regressed blocking implementation before failing the test.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-done:
				t.Fatal("periodic refresh blocked without a channel consumer")
			case <-m.UpdateStatusCh:
			case <-timer.C:
				t.Fatal("periodic refresh did not finish during cleanup")
			}
		}
	}
}

func TestUpdateAllCRStatus_BatchesWithoutBlocking(t *testing.T) {
	for _, tc := range []struct {
		name               string
		capacity, policies int
		full               bool
	}{
		{"exceeds_100", 100, 101, false},
		{"exceeds_400", 400, 401, false},
		{"already_full", 1, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newPeriodicStatusTestManager(tc.capacity, tc.policies)
			if tc.full {
				m.UpdateStatusCh <- "existing"
			}
			originalDepth := len(m.UpdateStatusCh)
			m.pendingUpdates["default/another-policy"] = time.Now()
			refreshStatusWithoutConsumer(t, m)
			refreshStatusWithoutConsumer(t, m)
			assert.Len(t, m.pendingUpdates, tc.policies+1, "repeated refreshes must coalesce by key")
			for key := range m.policyStatuses {
				assert.Contains(t, m.pendingUpdates, key)
			}
			assert.Contains(t, m.pendingUpdates, "default/another-policy")
			assert.Len(t, m.UpdateStatusCh, originalDepth, "only batchWorker should deliver periodic notifications")
			for _, status := range m.policyStatuses {
				assert.EqualValues(t, 1, status.SuccessedNumber)
			}
		})
	}
}

// Drive one complete batch without sleeps or a live reconcileStatus consumer.
func runStatusBatch(t *testing.T, m *StatusManager) {
	t.Helper()
	ticks := make(chan time.Time)
	m.batchWorkerTicker = &time.Ticker{C: ticks}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.batchWorker(stop); close(done) }()
	select {
	case ticks <- time.Now():
	case <-time.After(2 * time.Second):
		close(stop)
		t.Fatal("batch worker did not receive tick")
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("batch worker blocked on a full channel")
	}
}

func TestUpdateAllCRStatus_RetriesFullChannel(t *testing.T) {
	m := newPeriodicStatusTestManager(1, 3)
	m.UpdateStatusCh <- "existing"
	refreshStatusWithoutConsumer(t, m)
	runStatusBatch(t, m)
	assert.Len(t, m.pendingUpdates, 3, "full channel must retain pending updates")
	assert.Equal(t, "existing", <-m.UpdateStatusCh)
	seen := make(map[string]bool)
	for i := 0; i < 3; i++ {
		runStatusBatch(t, m)
		select {
		case key := <-m.UpdateStatusCh:
			assert.Contains(t, m.policyStatuses, key)
			assert.False(t, seen[key], "unexpected duplicate: %s", key)
			seen[key] = true
		default:
			t.Fatal("batch worker lost a pending notification")
		}
	}
	assert.Len(t, seen, 3)
	assert.Empty(t, m.pendingUpdates)
}

func TestUpdateAllCRStatus_StillForcesProfileReconciliation(t *testing.T) {
	m := newPeriodicStatusTestManager(1, 1)
	m.UpdateStatusCh <- "existing"
	m.policyStatuses["default/policy-0"] = varmortypes.PolicyStatus{
		NodeMessages: map[string]string{"offline-node": string(varmor.ArmorProfileReady)},
	}
	name := varmorprofile.GenerateArmorProfileName("default", "policy-0", false)
	client := varmorfake.NewSimpleClientset(&varmor.ArmorProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
	})
	m.varmorInterface = client.CrdV1beta1()
	refreshStatusWithoutConsumer(t, m)
	ap, err := client.CrdV1beta1().ArmorProfiles("default").Get(context.Background(), name, metav1.GetOptions{})
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "1", ap.Annotations[varmortypes.ReconcileAnnotation])
	assert.Empty(t, m.policyStatuses["default/policy-0"].NodeMessages)
	assert.Contains(t, m.pendingUpdates, "default/policy-0")
	assert.Equal(t, "existing", <-m.UpdateStatusCh)
}

func TestUpdateAllCRStatus_CoalescesWithAgentReports(t *testing.T) {
	for _, scanFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("scan_first_%t", scanFirst), func(t *testing.T) {
			m := newPeriodicStatusTestManager(400, 0)
			report := varmortypes.ProfileStatus{
				Namespace:   "default",
				ProfileName: varmorprofile.GenerateArmorProfileName("default", "policy-0", false),
				NodeName:    "node",
				Status:      varmortypes.Succeeded,
			}
			if !assert.NoError(t, m.syncStatus(report)) {
				return
			}
			if scanFirst {
				refreshStatusWithoutConsumer(t, m)
			}
			report.Status = varmortypes.Failed
			report.Message = "profile load failed"
			if !assert.NoError(t, m.syncStatus(report)) {
				return
			}
			if !scanFirst {
				refreshStatusWithoutConsumer(t, m)
			}

			assert.Len(t, m.pendingUpdates, 1, "both sources request the same latest status")
			runStatusBatch(t, m)
			assert.Len(t, m.UpdateStatusCh, 1)
			assert.Empty(t, m.pendingUpdates)
			status := m.policyStatuses["default/policy-0"]
			assert.EqualValues(t, 0, status.SuccessedNumber)
			assert.EqualValues(t, 1, status.FailedNumber)
			assert.Equal(t, report.Message, status.NodeMessages["node"])

			// An already queued notification must not prevent a later report
			// from scheduling another refresh of the latest cache contents.
			report.Status = varmortypes.Succeeded
			if !assert.NoError(t, m.syncStatus(report)) {
				return
			}
			assert.Contains(t, m.pendingUpdates, "default/policy-0")
			status = m.policyStatuses["default/policy-0"]
			assert.EqualValues(t, 1, status.SuccessedNumber)
			assert.EqualValues(t, 0, status.FailedNumber)
		})
	}
}
