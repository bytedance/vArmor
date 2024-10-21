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
	"reflect"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
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
)

type StatusManager struct {
	coreInterface       corev1.CoreV1Interface
	appsInterface       appsv1.AppsV1Interface
	varmorInterface     varmorinterface.CrdV1beta1Interface
	UpdateDesiredNumber bool
	desiredNumber       int
	// Use "namespace/VarmorPolicyName" or "VarmorClusterPolicyName" as key.
	// One VarmorPolicy/ClusterPolicyName object corresponds to one PolicyStatus
	PolicyStatuses map[string]varmortypes.PolicyStatus
	// Use "namespace/VarmorPolicyName" as key. One VarmorPolicy object corresponds to one ModelingStatus
	// TODO: Rebuild ModelingStatuses from ArmorProfile object when leader change occurs.
	ModelingStatuses  map[string]varmortypes.ModelingStatus
	ResetCh           chan string
	DeleteCh          chan string
	UpdateStatusCh    chan string
	UpdateModeCh      chan string
	statusQueue       workqueue.RateLimitingInterface
	dataQueue         workqueue.RateLimitingInterface
	statusUpdateCycle time.Duration
	debug             bool
	log               logr.Logger
}

func NewStatusManager(coreInterface corev1.CoreV1Interface, appsInterface appsv1.AppsV1Interface, varmorInterface varmorinterface.CrdV1beta1Interface, statusUpdateCycle time.Duration, debug bool, log logr.Logger) *StatusManager {
	m := StatusManager{
		coreInterface:     coreInterface,
		appsInterface:     appsInterface,
		varmorInterface:   varmorInterface,
		desiredNumber:     0,
		PolicyStatuses:    make(map[string]varmortypes.PolicyStatus),
		ModelingStatuses:  make(map[string]varmortypes.ModelingStatus),
		ResetCh:           make(chan string, 50),
		DeleteCh:          make(chan string, 50),
		UpdateStatusCh:    make(chan string, 100),
		UpdateModeCh:      make(chan string, 50),
		statusQueue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "status"),
		dataQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "data"),
		statusUpdateCycle: statusUpdateCycle,
		debug:             debug,
		log:               log,
	}
	return &m
}

// retrieveDesiredNumber retrieve the desired number of agents.
func (m *StatusManager) retrieveDesiredNumber() error {
	if m.debug {
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

	if m.debug {
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

// rebuildPolicyStatuses rebuild the PolicyStatuses cache from the existing ArmorProfile objects.
func (m *StatusManager) rebuildPolicyStatuses() error {
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
			statusKey, err := generatePolicyStatusKeyWithArmorProfile(&ap)
			if err != nil {
				continue
			}

			var policyStatus varmortypes.PolicyStatus
			policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)

			for _, condition := range ap.Status.Conditions {
				if varmorutils.InStringArray(condition.NodeName, nodes) {
					policyStatus.FailedNumber += 1
					policyStatus.NodeMessages[condition.NodeName] = condition.Message
				}
			}

			for _, node := range nodes {
				if _, ok := policyStatus.NodeMessages[node]; !ok {
					policyStatus.SuccessedNumber += 1
					policyStatus.NodeMessages[node] = string(varmortypes.ArmorProfileReady)
				}
			}

			m.PolicyStatuses[statusKey] = policyStatus
		}
	}
	return nil
}

func (m *StatusManager) updateArmorProfileStatus(
	ap *varmor.ArmorProfile,
	policyStatus *varmortypes.PolicyStatus) (*varmor.ArmorProfile, error) {

	var conditions []varmor.ArmorProfileCondition
	for nodeName, message := range policyStatus.NodeMessages {
		if message != string(varmortypes.ArmorProfileReady) {
			c := newArmorProfileCondition(nodeName, varmortypes.ArmorProfileReady, v1.ConditionFalse, "", message)
			conditions = append(conditions, *c)
		}
	}

	regain := false
	update := func() (err error) {
		if regain {
			ap, err = m.varmorInterface.ArmorProfiles(ap.Namespace).Get(context.Background(), ap.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
		}
		// Nothing needs to be updated.
		if reflect.DeepEqual(ap.Status.Conditions, conditions) &&
			ap.Status.CurrentNumberLoaded == policyStatus.SuccessedNumber &&
			ap.Status.DesiredNumberLoaded == m.desiredNumber {
			return nil
		}
		ap.Status.DesiredNumberLoaded = m.desiredNumber
		ap.Status.CurrentNumberLoaded = policyStatus.SuccessedNumber
		if len(conditions) > 0 {
			ap.Status.Conditions = conditions
		} else {
			ap.Status.Conditions = nil
		}
		ap, err = m.varmorInterface.ArmorProfiles(ap.Namespace).UpdateStatus(context.Background(), ap, metav1.UpdateOptions{})
		if err != nil {
			regain = true
		}
		return err
	}
	return ap, retry.RetryOnConflict(retry.DefaultRetry, update)
}

func (m *StatusManager) updateVarmorPolicyStatus(
	vp *varmor.VarmorPolicy,
	ready bool,
	phase varmor.VarmorPolicyPhase) (*varmor.VarmorPolicy, error) {

	// Nothing need to be updated.
	if vp.Status.Ready == ready && vp.Status.Phase == phase {
		return vp, nil
	}

	condition := varmor.VarmorPolicyCondition{
		Type:               varmortypes.VarmorPolicyReady,
		LastTransitionTime: metav1.Now(),
	}
	if ready {
		condition.Status = v1.ConditionTrue
		condition.Reason = "AllAgentsReady"
	} else {
		condition.Status = v1.ConditionFalse
		condition.Reason = "Processing"
		if phase == varmortypes.VarmorPolicyError {
			condition.Reason = "Error"
			condition.Message = fmt.Sprintf("The agents failed processing the profile. Please refer to the status of ArmorProfile object (%s/%s) for more details.",
				vp.Namespace, vp.Status.ProfileName)
		}
	}
	exist := false
	for i, c := range vp.Status.Conditions {
		if c.Type == varmortypes.VarmorPolicyReady {
			condition.DeepCopyInto(&vp.Status.Conditions[i])
			exist = true
			break
		}
	}
	if !exist {
		vp.Status.Conditions = append(vp.Status.Conditions, condition)
	}

	regain := false
	update := func() (err error) {
		if regain {
			vp, err = m.varmorInterface.VarmorPolicies(vp.Namespace).Get(context.Background(), vp.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
		}
		vp.Status.Ready = ready
		if phase != varmortypes.VarmorPolicyUnchanged {
			vp.Status.Phase = phase
		}
		vp, err = m.varmorInterface.VarmorPolicies(vp.Namespace).UpdateStatus(context.Background(), vp, metav1.UpdateOptions{})
		if err != nil {
			regain = true
		}
		return err
	}
	return vp, retry.RetryOnConflict(retry.DefaultRetry, update)
}

func (m *StatusManager) updateVarmorClusterPolicyStatus(
	vcp *varmor.VarmorClusterPolicy,
	ready bool,
	phase varmor.VarmorPolicyPhase) (*varmor.VarmorClusterPolicy, error) {

	// Nothing need to be updated.
	if vcp.Status.Ready == ready && vcp.Status.Phase == phase {
		return vcp, nil
	}

	condition := varmor.VarmorPolicyCondition{
		Type:               varmortypes.VarmorPolicyReady,
		LastTransitionTime: metav1.Now(),
	}
	if ready {
		condition.Status = v1.ConditionTrue
		condition.Reason = "AllAgentsReady"
	} else {
		condition.Status = v1.ConditionFalse
		condition.Reason = "Processing"
		if phase == varmortypes.VarmorPolicyError {
			condition.Reason = "Error"
			condition.Message = fmt.Sprintf("The agents failed processing the profile. Please refer to the status of ArmorProfile object (%s/%s) for more details.",
				varmorconfig.Namespace, vcp.Status.ProfileName)
		}
	}
	exist := false
	for i, c := range vcp.Status.Conditions {
		if c.Type == varmortypes.VarmorPolicyReady {
			condition.DeepCopyInto(&vcp.Status.Conditions[i])
			exist = true
			break
		}
	}
	if !exist {
		vcp.Status.Conditions = append(vcp.Status.Conditions, condition)
	}

	regain := false
	update := func() (err error) {
		if regain {
			vcp, err = m.varmorInterface.VarmorClusterPolicies().Get(context.Background(), vcp.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
		}
		vcp.Status.Ready = ready
		if phase != varmortypes.VarmorPolicyUnchanged {
			vcp.Status.Phase = phase
		}
		vcp, err = m.varmorInterface.VarmorClusterPolicies().UpdateStatus(context.Background(), vcp, metav1.UpdateOptions{})
		if err != nil {
			regain = true
		}
		return err
	}
	return vcp, retry.RetryOnConflict(retry.DefaultRetry, update)
}

func (m *StatusManager) updateAllCRStatus(logger logr.Logger) {
	if len(m.PolicyStatuses) == 0 {
		return
	}

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

	// Remove the status cache of offline nodes from PolicyStatus.NodeMessages, and update the objects' status.
	for statusKey, policyStatus := range m.PolicyStatuses {
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
		m.PolicyStatuses[statusKey] = policyStatus
		m.UpdateStatusCh <- statusKey
	}
}

func (m *StatusManager) reconcileStatus(stopCh <-chan struct{}) {
	logger := m.log.WithName("reconcileStatus")

	ticker := time.NewTicker(m.statusUpdateCycle)
	defer ticker.Stop()

	// Reconcile loop
	for {
		select {
		// Reset the specified status cache.
		case statusKey := <-m.ResetCh:
			if policyStatus, ok := m.PolicyStatuses[statusKey]; ok {
				policyStatus.SuccessedNumber = 0
				policyStatus.FailedNumber = 0
				policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)
				m.PolicyStatuses[statusKey] = policyStatus
			}

			if modelingStatus, ok := m.ModelingStatuses[statusKey]; ok {
				modelingStatus.CompletedNumber = 0
				m.ModelingStatuses[statusKey] = modelingStatus
			}

		// Delete the specified status cache.
		case statusKey := <-m.DeleteCh:
			delete(m.PolicyStatuses, statusKey)
			delete(m.ModelingStatuses, statusKey)

		// Update the specified object status.
		case statusKey := <-m.UpdateStatusCh:
			var policyStatus varmortypes.PolicyStatus
			var ok bool

			if policyStatus, ok = m.PolicyStatuses[statusKey]; !ok {
				logger.Error(fmt.Errorf("m.PolicyStatuses[%s] doesn't exist", statusKey), "fatal error")
				break
			}

			logger.V(3).Info("PolicyStatus cache", "key", statusKey, "value", policyStatus)

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
			ap, err = m.updateArmorProfileStatus(ap, &policyStatus)
			if err != nil {
				logger.Error(err, "m.updateArmorProfileStatus()")
				break
			}

			// State calculation
			var v interface{}
			var vSpec varmor.VarmorPolicySpec
			var vStatus varmor.VarmorPolicyStatus
			if clusterScope {
				v, err = m.varmorInterface.VarmorClusterPolicies().Get(context.Background(), vpName, metav1.GetOptions{})
				if err != nil {
					logger.Error(err, "m.varmorInterface.VarmorClusterPolicies().Get()")
					break
				}
				vSpec = v.(*varmor.VarmorClusterPolicy).Spec
				vStatus = v.(*varmor.VarmorClusterPolicy).Status
			} else {
				v, err = m.varmorInterface.VarmorPolicies(namespace).Get(context.Background(), vpName, metav1.GetOptions{})
				if err != nil {
					logger.Error(err, "m.varmorInterface.VarmorPolicies().Get()")
					break
				}
				vSpec = v.(*varmor.VarmorPolicy).Spec
				vStatus = v.(*varmor.VarmorPolicy).Status
			}
			phase := varmortypes.VarmorPolicyProtecting
			complete := false
			if vSpec.Policy.Mode == varmortypes.BehaviorModelingMode {
				phase = varmortypes.VarmorPolicyModeling

				if modelingStatus, ok := m.ModelingStatuses[statusKey]; ok {
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
				_, err = m.updateVarmorClusterPolicyStatus(vcp, ready, phase)
				if err != nil {
					logger.Error(err, "m.updateVarmorClusterPolicyStatus()")
				}
			} else {
				vp := v.(*varmor.VarmorPolicy)
				logger.Info("2. update VarmorPolicy/status", "namespace", vp.Namespace, "name", vp.Name)
				_, err = m.updateVarmorPolicyStatus(vp, ready, phase)
				if err != nil {
					logger.Error(err, "m.updateVarmorPolicyStatus()")
				}
			}

		// Periodically update all of the objects' statuses to avoid the interference from offline nodes.
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
			if policyStatus, ok := m.PolicyStatuses[statusKey]; ok {
				policyStatus.FailedNumber = 0
				policyStatus.SuccessedNumber = 0
				policyStatus.NodeMessages = make(map[string]string, m.desiredNumber)
				m.PolicyStatuses[statusKey] = policyStatus
			}

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
			profile, err := varmorprofile.GenerateProfile(vPolicy, apName, namespace, m.varmorInterface, true)
			if err != nil {
				logger.Error(err, "varmorprofile.GenerateProfile()")
				break
			}

			logger.Info("update ArmorProfile (complain mode --> enforce mode)", "namespace", namespace, "name", apName)
			err = retry.RetryOnConflict(retry.DefaultRetry,
				func() error {
					ap, err := m.varmorInterface.ArmorProfiles(namespace).Get(context.Background(), apName, metav1.GetOptions{})
					if err != nil {
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
	m.log.V(3).Info("PolicyStatuses cache rebuilt", "length", len(m.PolicyStatuses), "content", m.PolicyStatuses)

	go m.reconcileStatus(stopCh)
	go wait.Until(m.statusWorker, time.Second, stopCh)
	go wait.Until(m.dataWorker, time.Second, stopCh)

	<-stopCh
}

func (m *StatusManager) CleanUp() {
	m.statusQueue.ShutDown()
	m.dataQueue.ShutDown()
}
