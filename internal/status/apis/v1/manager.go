// Copyright 2022-2023 vArmor Authors
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
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/metric"
	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	varmormetrics "github.com/bytedance/vArmor/pkg/metrics"
)

type StatusManager struct {
	coreInterface       corev1.CoreV1Interface
	appsInterface       appsv1.AppsV1Interface
	varmorInterface     varmorinterface.CrdV1beta1Interface
	UpdateDesiredNumber bool
	desiredNumber       int
	// Use "namespace/VarmorPolicyName" or "VarmorClusterPolicyName" as key.
	// One VarmorPolicy/ClusterPolicyName object corresponds to one PolicyStatus
	policyStatuses     map[string]varmortypes.PolicyStatus
	policyStatusesLock sync.RWMutex
	// Use "namespace/VarmorPolicyName" as key. One VarmorPolicy object corresponds to one ModelingStatus
	// TODO: Rebuild modelingStatuses from ArmorProfile object when leader change occurs.
	modelingStatuses     map[string]varmortypes.ModelingStatus
	modelingStatusesLock sync.RWMutex
	ResetCh              chan string
	DeleteCh             chan string
	UpdateStatusCh       chan string
	UpdateModeCh         chan string
	statusQueue          workqueue.RateLimitingInterface
	dataQueue            workqueue.RateLimitingInterface
	statusUpdateCycle    time.Duration
	debug                bool
	inContainer          bool
	log                  logr.Logger
	metricsModule        *varmormetrics.MetricsModule
	profileSuccess       metric.Float64Counter
	profileFailure       metric.Float64Counter
	profileChangeCount   metric.Float64Counter
	//profileStatusPerNode metric.Float64Gauge
}

// NewStatusManager creates a StatusManager instance to manage the status of all CRD objects.
func NewStatusManager(coreInterface corev1.CoreV1Interface,
	appsInterface appsv1.AppsV1Interface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	statusUpdateCycle time.Duration,
	debug bool,
	inContainer bool,
	metricsModule *varmormetrics.MetricsModule,
	log logr.Logger) *StatusManager {

	m := StatusManager{
		coreInterface:     coreInterface,
		appsInterface:     appsInterface,
		varmorInterface:   varmorInterface,
		desiredNumber:     0,
		policyStatuses:    make(map[string]varmortypes.PolicyStatus),
		modelingStatuses:  make(map[string]varmortypes.ModelingStatus),
		ResetCh:           make(chan string, 50),
		DeleteCh:          make(chan string, 50),
		UpdateStatusCh:    make(chan string, 100),
		UpdateModeCh:      make(chan string, 50),
		statusQueue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "status"),
		dataQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "data"),
		statusUpdateCycle: statusUpdateCycle,
		metricsModule:     metricsModule,
		debug:             debug,
		inContainer:       inContainer,
		log:               log,
	}

	if metricsModule.Enabled {
		m.profileSuccess = metricsModule.RegisterFloat64Counter("varmor_profile_processing_success", "Number of successful profile processing")
		m.profileFailure = metricsModule.RegisterFloat64Counter("varmor_profile_processing_failure", "Number of failed profile processing")
		m.profileChangeCount = metricsModule.RegisterFloat64Counter("varmor_profile_change_count", "Number of profile change")
		//m.profileStatusPerNode = metricsModule.RegisterFloat64Gauge("varmor_profile_status_per_node", "Profile status per node (1=success, 0=failure)")
	}

	if _, err := os.Stat(varmorconfig.ArmorProfileModelDataDirectory); os.IsNotExist(err) {
		os.MkdirAll(varmorconfig.ArmorProfileModelDataDirectory, os.ModePerm)
	}

	return &m
}

// retrieveDesiredNumber retrieve the desired number of agents.
func (m *StatusManager) retrieveDesiredNumber() error {
	if !m.inContainer {
		nodes, err := m.coreInterface.Nodes().List(context.Background(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		m.desiredNumber = len(nodes.Items)
		return nil
	}

	retrieveAgentDsStatus := func() error {
		ds, err := m.appsInterface.DaemonSets(varmorconfig.Namespace).Get(context.Background(), varmorconfig.AgentName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		m.UpdateDesiredNumber = false
		m.desiredNumber = int(ds.Status.DesiredNumberScheduled)
		return nil
	}
	retriable := func(err error) bool {
		return err != nil
	}
	err := retry.OnError(retry.DefaultRetry, retriable, retrieveAgentDsStatus)
	return err
}

// retrieveNodeNameList retrieves the list of nodes where the agent is running.
func (m *StatusManager) retrieveNodeNameList() ([]string, error) {
	var nodes []string

	if !m.inContainer {
		nodeList, err := m.coreInterface.Nodes().List(context.Background(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return nil, err
		}
		for _, node := range nodeList.Items {
			nodes = append(nodes, node.Name)
		}
	} else {
		listOpt := metav1.ListOptions{
			LabelSelector:   varmortypes.AgentLabelSelector,
			ResourceVersion: "0",
		}
		podList, err := m.coreInterface.Pods(varmorconfig.Namespace).List(context.Background(), listOpt)
		if err != nil {
			return nil, err
		}
		for _, pod := range podList.Items {
			if pod.Status.Phase == v1.PodRunning {
				nodes = append(nodes, pod.Spec.NodeName)
			}
		}
	}

	return nodes, nil
}

// rebuildPolicyStatuses rebuild the policyStatuses cache from the existing ArmorProfile objects.
func (m *StatusManager) rebuildPolicyStatuses() error {
	m.policyStatusesLock.Lock()
	defer m.policyStatusesLock.Unlock()

	nsList, err := m.coreInterface.Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	nodes, err := m.retrieveNodeNameList()
	if err != nil {
		return err
	}

	for _, ns := range nsList.Items {
		apList, err := m.varmorInterface.ArmorProfiles(ns.Name).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ap := range apList.Items {
			// Try to delete the zombie ArmorProfile objects
			if ap.DeletionTimestamp != nil {
				m.log.Info("remove the finalizers of zombie ArmorProfile", "namespace", ap.Namespace, "name", ap.Name)
				varmorutils.RemoveArmorProfileFinalizers(m.varmorInterface, ap.Namespace, ap.Name)
				continue
			}

			statusKey, err := generatePolicyStatusKeyWithArmorProfile(&ap)
			if err != nil {
				continue
			}

			var policyStatus varmortypes.PolicyStatus
			policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)

			// Only count the failed node that is still in the cluster
			for _, condition := range ap.Status.Conditions {
				if varmorutils.InStringArray(condition.NodeName, nodes) {
					policyStatus.FailedNumber += 1
					policyStatus.NodeMessages[condition.NodeName] = condition.Message
				}
			}

			// The node that has not failed must be successful.
			for _, node := range nodes {
				if _, ok := policyStatus.NodeMessages[node]; !ok {
					policyStatus.SuccessedNumber += 1
					policyStatus.NodeMessages[node] = string(varmortypes.ArmorProfileReady)
				}
			}

			// Cache policy status
			m.policyStatuses[statusKey] = policyStatus
		}
	}
	return nil
}

func (m *StatusManager) updateVarmorPolicyStatus(
	vp *varmor.VarmorPolicy,
	ready bool,
	phase varmor.VarmorPolicyPhase) error {

	// Nothing need to be updated.
	if vp.Status.Ready == ready && vp.Status.Phase == phase {
		return nil
	}

	var status v1.ConditionStatus
	var reason, message string

	if ready {
		status = v1.ConditionTrue
		reason = "AllAgentsReady"
	} else {
		status = v1.ConditionFalse
		reason = "Processing"
		if phase == varmortypes.VarmorPolicyError {
			reason = "Error"
			message = fmt.Sprintf("The agents failed processing the profile. Please refer to the status of ArmorProfile object (%s/%s) for more details.",
				vp.Namespace, vp.Status.ProfileName)
		}
	}

	return UpdateVarmorPolicyStatus(m.varmorInterface, vp, "", ready, phase, varmortypes.VarmorPolicyReady, status, reason, message)
}

func (m *StatusManager) updateVarmorClusterPolicyStatus(
	vcp *varmor.VarmorClusterPolicy,
	ready bool,
	phase varmor.VarmorPolicyPhase) error {

	// Nothing need to be updated.
	if vcp.Status.Ready == ready && vcp.Status.Phase == phase {
		return nil
	}

	var status v1.ConditionStatus
	var reason, message string

	if ready {
		status = v1.ConditionTrue
		reason = "AllAgentsReady"
	} else {
		status = v1.ConditionFalse
		reason = "Processing"
		if phase == varmortypes.VarmorPolicyError {
			reason = "Error"
			message = fmt.Sprintf("The agents failed processing the profile. Please refer to the status of ArmorProfile object (%s/%s) for more details.",
				varmorconfig.Namespace, vcp.Status.ProfileName)
		}
	}

	return UpdateVarmorClusterPolicyStatus(m.varmorInterface, vcp, "", ready, phase, varmortypes.VarmorPolicyReady, status, reason, message)
}

// updateAllCRStatus periodically reconcile all of the objects' statuses to avoid the interference from offline nodes
// and to force agents to update profile that do not meet the expectations.
func (m *StatusManager) updateAllCRStatus(logger logr.Logger) {
	// Update DesiredNumber
	err := m.retrieveDesiredNumber()
	if err != nil {
		logger.Error(err, "m.retrieveDesiredNumber() failed")
		return
	}

	// Get the list of nodes where the agents are running.
	nodes, err := m.retrieveNodeNameList()
	if err != nil {
		logger.Error(err, "m.retrieveNodeNameList()")
		return
	}

	var statusKeys []string
	var profiles []struct {
		namespace string
		apName    string
	}

	m.policyStatusesLock.Lock()
	for statusKey, policyStatus := range m.policyStatuses {
		statusKeys = append(statusKeys, statusKey)

		// Remove the offline nodes from PolicyStatus.NodeMessages
		policyStatus.FailedNumber = 0
		policyStatus.SuccessedNumber = 0
		for nodeName, message := range policyStatus.NodeMessages {
			if varmorutils.InStringArray(nodeName, nodes) {
				if message == string(varmortypes.ArmorProfileReady) {
					policyStatus.SuccessedNumber += 1
				} else {
					policyStatus.FailedNumber += 1
				}
			} else {
				delete(policyStatus.NodeMessages, nodeName)
			}
		}
		m.policyStatuses[statusKey] = policyStatus

		// Collect ArmorProfile objects that do not meet the expectations.
		if policyStatus.FailedNumber == 0 && policyStatus.SuccessedNumber != m.desiredNumber {
			namespace, vpName, err := cache.SplitMetaNamespaceKey(statusKey)
			if err != nil {
				logger.Error(err, "fatal error")
				continue
			} else {
				clusterScope := false
				if namespace == "" {
					clusterScope = true
					namespace = varmorconfig.Namespace
				}
				apName := varmorprofile.GenerateArmorProfileName(namespace, vpName, clusterScope)
				profiles = append(profiles, struct {
					namespace string
					apName    string
				}{namespace, apName})
			}
		}
	}
	m.policyStatusesLock.Unlock()

	// Update the objects' status.
	for _, key := range statusKeys {
		m.UpdateStatusCh <- key
	}

	// Force agents to update profile that do not meet the expectations.
	for _, p := range profiles {
		logger.Info("force agents to update the ArmorProfile object", "namespace", p.namespace, "name", p.apName)
		err := retry.RetryOnConflict(retry.DefaultRetry,
			func() error {
				ap, err := m.varmorInterface.ArmorProfiles(p.namespace).Get(context.Background(), p.apName, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if ap.Annotations == nil {
					ap.Annotations = make(map[string]string)
				}
				value := ap.Annotations[varmortypes.ReconcileAnnotation]
				counter, _ := strconv.Atoi(value)
				ap.Annotations[varmortypes.ReconcileAnnotation] = fmt.Sprintf("%d", counter+1)
				_, err = m.varmorInterface.ArmorProfiles(p.namespace).Update(context.Background(), ap, metav1.UpdateOptions{})
				return err
			})
		if err != nil {
			logger.Error(err, "failed to update the reconcile annotation of the ArmorProfile object")
		}
	}
}

// reconcileStatus handles status update events in a loop to reconcile the status of all CRD objects
func (m *StatusManager) reconcileStatus(stopCh <-chan struct{}) {
	logger := m.log.WithName("reconcileStatus")

	ticker := time.NewTicker(m.statusUpdateCycle)
	defer ticker.Stop()

	// Reconcile loop
	for {
		select {
		// Reset the specified status cache.
		case statusKey := <-m.ResetCh:
			logger.V(2).Info("Reset the specified status cache", "key", statusKey)

			m.policyStatusesLock.Lock()
			if policyStatus, ok := m.policyStatuses[statusKey]; ok {
				policyStatus.SuccessedNumber = 0
				policyStatus.FailedNumber = 0
				policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)
				m.policyStatuses[statusKey] = policyStatus
			}
			m.policyStatusesLock.Unlock()

			m.modelingStatusesLock.Lock()
			if modelingStatus, ok := m.modelingStatuses[statusKey]; ok {
				modelingStatus.CompletedNumber = 0
				m.modelingStatuses[statusKey] = modelingStatus
			}
			m.modelingStatusesLock.Unlock()

		// Delete the specified status cache.
		case statusKey := <-m.DeleteCh:
			logger.V(2).Info("Delete the specified status cache", "key", statusKey)

			m.policyStatusesLock.Lock()
			delete(m.policyStatuses, statusKey)
			m.policyStatusesLock.Unlock()

			m.modelingStatusesLock.Lock()
			delete(m.modelingStatuses, statusKey)
			m.modelingStatusesLock.Unlock()

		// Update the specified object status.
		case statusKey := <-m.UpdateStatusCh:
			logger.V(2).Info("Update the specified object status", "key", statusKey)

			m.policyStatusesLock.RLock()
			policyStatus, ok := m.policyStatuses[statusKey]
			m.policyStatusesLock.RUnlock()
			if !ok {
				logger.Error(fmt.Errorf("m.policyStatuses[%s] doesn't exist", statusKey), "fatal error")
				break
			}

			namespace, vpName, err := cache.SplitMetaNamespaceKey(statusKey)
			if err != nil {
				logger.Error(err, "fatal error")
				break
			}

			clusterScope := false
			if namespace == "" {
				clusterScope = true
				namespace = varmorconfig.Namespace
			}

			// Reset DesiredNumber when ArmorProfile was created or updated.
			// The DesiredNumber used for determining the status of the policy,
			// and the status of VarmorPolicy will be set to READY when the
			// number of loaded profiles is equal with the number of agents.
			if m.UpdateDesiredNumber {
				err = m.retrieveDesiredNumber()
				if err != nil {
					logger.Error(err, "m.retrieveDesiredNumber() failed")
				} else {
					logger.Info("DesiredNumber updated", "number", m.desiredNumber)
				}
			}

			// Update ArmorProfile/status
			apName := varmorprofile.GenerateArmorProfileName(namespace, vpName, clusterScope)
			logger.Info("1. update ArmorProfile/status", "namespace", namespace, "name", apName)
			ap, err := m.varmorInterface.ArmorProfiles(namespace).Get(context.Background(), apName, metav1.GetOptions{})
			if err != nil {
				logger.Error(err, "m.varmorInterface.ArmorProfiles().Get()")
				break
			}
			err = UpdateArmorProfileStatus(m.varmorInterface, ap, &policyStatus, m.desiredNumber)
			if err != nil {
				logger.Error(err, "UpdateArmorProfileStatus()")
				break
			}

			// State calculation
			var v interface{}
			var vSpec varmor.VarmorPolicySpec
			var vStatus varmor.VarmorPolicyStatus
			if clusterScope {
				v, err = m.varmorInterface.VarmorClusterPolicies().Get(context.Background(), vpName, metav1.GetOptions{})
				if err != nil {
					if !k8errors.IsNotFound(err) {
						logger.Error(err, "m.varmorInterface.VarmorClusterPolicies().Get()")
					}
					break
				}
				vSpec = v.(*varmor.VarmorClusterPolicy).Spec
				vStatus = v.(*varmor.VarmorClusterPolicy).Status
			} else {
				v, err = m.varmorInterface.VarmorPolicies(namespace).Get(context.Background(), vpName, metav1.GetOptions{})
				if err != nil {
					if !k8errors.IsNotFound(err) {
						logger.Error(err, "m.varmorInterface.VarmorPolicies().Get()")
					}
					break
				}
				vSpec = v.(*varmor.VarmorPolicy).Spec
				vStatus = v.(*varmor.VarmorPolicy).Status
			}
			phase := varmortypes.VarmorPolicyProtecting
			complete := false
			if vSpec.Policy.Mode == varmortypes.BehaviorModelingMode && vSpec.Policy.ModelingOptions != nil {
				phase = varmortypes.VarmorPolicyModeling

				m.modelingStatusesLock.RLock()
				if modelingStatus, ok := m.modelingStatuses[statusKey]; ok {
					if modelingStatus.CompletedNumber >= m.desiredNumber {
						complete = true
					}
				} else {
					if vStatus.Phase == varmortypes.VarmorPolicyCompleted {
						createTime := ap.CreationTimestamp.Time
						if time.Now().After(createTime.Add(time.Duration(vSpec.Policy.ModelingOptions.Duration) * time.Minute)) {
							complete = true
						}
					}
				}
				m.modelingStatusesLock.RUnlock()

				if complete {
					phase = varmortypes.VarmorPolicyCompleted
				}
			}

			ready := false
			if policyStatus.SuccessedNumber >= m.desiredNumber {
				ready = true
			}
			if policyStatus.FailedNumber > 0 {
				phase = varmortypes.VarmorPolicyError
				ready = false
			}

			// Update VarmorPolicy/status or VarmorClusterPolicy/status
			if clusterScope {
				vcp := v.(*varmor.VarmorClusterPolicy)
				logger.Info("2. update VarmorClusterPolicy/status", "name", vcp.Name)
				err = m.updateVarmorClusterPolicyStatus(vcp, ready, phase)
				if err != nil {
					logger.Error(err, "m.updateVarmorClusterPolicyStatus()")
				}
			} else {
				vp := v.(*varmor.VarmorPolicy)
				logger.Info("2. update VarmorPolicy/status", "namespace", vp.Namespace, "name", vp.Name)
				err = m.updateVarmorPolicyStatus(vp, ready, phase)
				if err != nil {
					logger.Error(err, "m.updateVarmorPolicyStatus()")
				}
			}

		// Periodically update all of the objects' statuses to avoid the interference from offline nodes
		// and force agents to update the profile that do not meet the expectations.
		case <-ticker.C:
			logger.Info("periodically update all of the objects' statuses")
			m.updateAllCRStatus(logger)

		// Update ArmorProfile for the BehaviorModeling mode.
		case statusKey := <-m.UpdateModeCh:
			namespace, vpName, err := cache.SplitMetaNamespaceKey(statusKey)
			if err != nil {
				logger.Error(err, "cache.SplitMetaNamespaceKey()")
				break
			}

			clusterScope := false
			if namespace == "" {
				clusterScope = true
				namespace = varmorconfig.Namespace
			}

			// Reset policyStatus
			m.policyStatusesLock.Lock()
			if policyStatus, ok := m.policyStatuses[statusKey]; ok {
				policyStatus.FailedNumber = 0
				policyStatus.SuccessedNumber = 0
				policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)
				m.policyStatuses[statusKey] = policyStatus
			}
			m.policyStatusesLock.Unlock()

			var v interface{}
			var vPolicy varmor.Policy
			if clusterScope {
				v, err = m.varmorInterface.VarmorClusterPolicies().Get(context.Background(), vpName, metav1.GetOptions{})
				if err != nil {
					logger.Error(err, "m.varmorInterface.VarmorClusterPolicies().Get()")
					break
				}
				vPolicy = v.(*varmor.VarmorClusterPolicy).Spec.Policy
			} else {
				v, err = m.varmorInterface.VarmorPolicies(namespace).Get(context.Background(), vpName, metav1.GetOptions{})
				if err != nil {
					logger.Error(err, "m.varmorInterface.VarmorPolicies().Get()")
					break
				}
				vPolicy = v.(*varmor.VarmorPolicy).Spec.Policy
			}

			apName := varmorprofile.GenerateArmorProfileName(namespace, vpName, clusterScope)
			profile, err := varmorprofile.GenerateProfile(vPolicy, apName, namespace, m.varmorInterface, true, logger)
			if err != nil {
				logger.Error(err, "varmorprofile.GenerateProfile()")
				break
			}

			logger.Info("update ArmorProfile (complain mode --> enforce mode)", "namespace", namespace, "name", apName)
			err = retry.RetryOnConflict(retry.DefaultRetry,
				func() error {
					ap, err := m.varmorInterface.ArmorProfiles(namespace).Get(context.Background(), apName, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					ap.Spec.Profile = *profile
					ap.Spec.BehaviorModeling.Enable = false
					_, err = m.varmorInterface.ArmorProfiles(ap.Namespace).Update(context.Background(), ap, metav1.UpdateOptions{})
					return err
				})
			if err != nil {
				logger.Error(err, "update ArmorProfile failed")
			}

		// Break out the status reconcile loop.
		case <-stopCh:
			return
		}
	}
}

// Run begins syncing the status of VarmorPolicy & ArmorPolicy.
func (m *StatusManager) Run(stopCh <-chan struct{}) {

	defer utilruntime.HandleCrash()

	err := m.retrieveDesiredNumber()
	if err != nil {
		m.log.Error(err, "m.retrieveDesiredNumber() failed")
	} else {
		m.log.Info("DesiredNumber initialized", "number", m.desiredNumber)
	}

	err = m.rebuildPolicyStatuses()
	if err != nil {
		m.log.Error(err, "m.rebuildPolicyStatuses() failed")
	}
	m.log.V(2).Info("policyStatuses cache rebuilt", "length", len(m.policyStatuses), "content", m.policyStatuses)

	go m.reconcileStatus(stopCh)
	go wait.Until(m.statusWorker, time.Second, stopCh)
	go wait.Until(m.dataWorker, time.Second, stopCh)
	//go m.syncStatusMetricsLoop()
	<-stopCh
}

// CleanUp shutdown all queues.
func (m *StatusManager) CleanUp() {
	m.statusQueue.ShutDown()
	m.dataQueue.ShutDown()
}
