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

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorauditor "github.com/bytedance/vArmor/internal/auditor"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorclient "github.com/bytedance/vArmor/pkg/client/clientset/versioned/fake"
)

type failingBpfEnforcer struct {
	err     error
	calls   int
	applied bool
}

func (e *failingBpfEnforcer) SaveAndApplyBpfProfile(string, varmor.ProfileMode, varmor.BpfContent) error {
	e.calls++
	e.applied = e.err == nil
	return e.err
}
func (*failingBpfEnforcer) DeleteBpfProfile(string) error { return nil }
func (*failingBpfEnforcer) IsBpfProfileExist(string) bool { return true }
func (*failingBpfEnforcer) Run(<-chan struct{})           {}
func (*failingBpfEnforcer) Close()                        {}

func TestBpfApplicationStatus_Reconciliation(t *testing.T) {
	for _, reportFails := range []bool{false, true} {
		t.Run(strconv.FormatBool(reportFails), func(t *testing.T) {
			var failReport atomic.Bool
			failReport.Store(reportFails)
			var mu sync.Mutex
			var statuses []varmortypes.Status
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var status varmortypes.ProfileStatus
				if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				statuses = append(statuses, status.Status)
				mu.Unlock()
				if failReport.Load() {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			ap := &varmor.ArmorProfile{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}, Spec: varmor.ArmorProfileSpec{Profile: varmor.Profile{Name: "p", Enforcer: "BPF", Mode: varmor.ProfileModeEnforce, Bpf: &varmor.BpfContent{}}}}
			client := varmorclient.NewSimpleClientset(ap)
			enforcer := &failingBpfEnforcer{err: errors.New("kernel application failed")}
			agent := &Agent{
				varmorInterface: client.CrdV1beta1(), bpfEnforcer: enforcer, bpfLsmSupported: true,
				auditor: &varmorauditor.Auditor{}, log: logr.Discard(), nodeName: "node",
				svcAddresses: map[string]string{varmorconfig.StatusServiceName: strings.TrimPrefix(server.URL, "https://")},
				queue:        workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Millisecond, time.Millisecond)),
			}
			defer agent.queue.ShutDown()
			agent.queue.Add("default/p")
			require.True(t, agent.processNextWorkItem())
			require.Equal(t, 1, enforcer.calls)
			assert.False(t, enforcer.applied)
			if reportFails {
				assert.Equal(t, 1, agent.queue.NumRequeues("default/p"))
			} else {
				assert.Zero(t, agent.queue.Len())
				assert.Zero(t, agent.queue.NumRequeues("default/p"))
			}
			failReport.Store(false)
			manualReconcile := func(counter string) {
				old := ap.DeepCopy()
				ap = ap.DeepCopy()
				ap.Annotations = map[string]string{varmortypes.ReconcileAnnotation: counter}
				_, err := client.CrdV1beta1().ArmorProfiles(ap.Namespace).Update(context.Background(), ap, metav1.UpdateOptions{})
				require.NoError(t, err)
				agent.updateArmorProfile(old, ap)
			}
			if !reportFails {
				manualReconcile("1")
			}
			// Either a manual reconcile or the queued reporting retry must still
			// report Failed while the BPF application continues to fail.
			require.True(t, agent.processNextWorkItem())
			require.Equal(t, 2, enforcer.calls)
			mu.Lock()
			for _, status := range statuses {
				assert.Equal(t, varmortypes.Failed, status)
			}
			mu.Unlock()
			assert.False(t, enforcer.applied)
			assert.Zero(t, agent.queue.NumRequeues("default/p"))
			enforcer.err = nil
			manualReconcile("2")
			require.True(t, agent.processNextWorkItem())
			require.Equal(t, 3, enforcer.calls)
			assert.True(t, enforcer.applied)
			mu.Lock()
			assert.Equal(t, varmortypes.Succeeded, statuses[len(statuses)-1])
			mu.Unlock()
		})
	}
}
