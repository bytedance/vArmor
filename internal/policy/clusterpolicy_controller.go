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

package policy

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	apicorev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	// informers "k8s.io/client-go/informers/core/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	statusmanager "github.com/bytedance/vArmor/internal/status/api/v1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	varmorinformer "github.com/bytedance/vArmor/pkg/client/informers/externalversions/varmor/v1beta1"
	varmorlister "github.com/bytedance/vArmor/pkg/client/listers/varmor/v1beta1"
)

type ClusterPolicyController struct {
	podInterface           corev1.PodInterface
	appsInterface          appsv1.AppsV1Interface
	varmorInterface        varmorinterface.CrdV1beta1Interface
	vcpInformer            varmorinformer.VarmorClusterPolicyInformer
	vcpLister              varmorlister.VarmorClusterPolicyLister
	vcpInformerSynced      cache.InformerSynced
	queue                  workqueue.RateLimitingInterface
	statusManager          *statusmanager.StatusManager
	restartExistWorkloads  bool
	enableBehaviorModeling bool
	bpfExclusiveMode       bool
	debug                  bool
	log                    logr.Logger
}

// NewClusterPolicyController create a new ClusterPolicyController
func NewClusterPolicyController(
	podInterface corev1.PodInterface,
	appsInterface appsv1.AppsV1Interface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	vcpInformer varmorinformer.VarmorClusterPolicyInformer,
	statusManager *statusmanager.StatusManager,
	restartExistWorkloads bool,
	enableBehaviorModeling bool,
	bpfExclusiveMode bool,
	debug bool,
	log logr.Logger) (*ClusterPolicyController, error) {

	c := ClusterPolicyController{
		podInterface:           podInterface,
		appsInterface:          appsInterface,
		varmorInterface:        varmorInterface,
		vcpInformer:            vcpInformer,
		vcpLister:              vcpInformer.Lister(),
		vcpInformerSynced:      vcpInformer.Informer().HasSynced,
		queue:                  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "clusterpolicy"),
		statusManager:          statusManager,
		restartExistWorkloads:  restartExistWorkloads,
		enableBehaviorModeling: enableBehaviorModeling,
		bpfExclusiveMode:       bpfExclusiveMode,
		debug:                  debug,
		log:                    log,
	}

	return &c, nil
}

func (c *ClusterPolicyController) enqueueClusterPolicy(vcp *varmor.VarmorClusterPolicy, logger logr.Logger) {
	key, err := cache.MetaNamespaceKeyFunc(vcp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	c.queue.Add(key)
}

func (c *ClusterPolicyController) addVarmorClusterPolicy(obj interface{}) {
	logger := c.log.WithName("AddFunc()")

	vcp := obj.(*varmor.VarmorClusterPolicy)

	logger.V(3).Info("enqueue VarmorClusterPolicy")
	c.enqueueClusterPolicy(vcp, logger)
}

func (c *ClusterPolicyController) deleteVarmorClusterPolicy(obj interface{}) {
	logger := c.log.WithName("DeleteFunc()")

	vcp := obj.(*varmor.VarmorClusterPolicy)

	logger.V(3).Info("enqueue VarmorClusterPolicy")
	c.enqueueClusterPolicy(vcp, logger)
}

func (c *ClusterPolicyController) updateVarmorClusterPolicy(oldObj, newObj interface{}) {
	logger := c.log.WithName("UpdateFunc()")

	oldVcp := oldObj.(*varmor.VarmorClusterPolicy)
	newVcp := newObj.(*varmor.VarmorClusterPolicy)

	if newVcp.ResourceVersion == oldVcp.ResourceVersion ||
		reflect.DeepEqual(newVcp.Spec, oldVcp.Spec) ||
		!reflect.DeepEqual(newVcp.Status, oldVcp.Status) {
		logger.V(3).Info("nothing need to be updated")
	} else {
		logger.V(3).Info("enqueue VarmorClusterPolicy")
		c.enqueueClusterPolicy(newVcp, logger)
	}
}

func (c *ClusterPolicyController) handleDeleteVarmorClusterPolicy(name string) error {
	logger := c.log.WithName("handleDeleteVarmorPolicy()")

	logger.Info("VarmorClusterPolicy", "name", name)

	apName := varmorprofile.GenerateArmorProfileName("", name, true)

	logger.Info("retrieve ArmorProfile")
	ap, err := c.varmorInterface.ArmorProfiles(varmorconfig.Namespace).Get(context.Background(), apName, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			logger.Info("ArmorProfile object not found", "namespace", varmorconfig.Namespace, "name", apName)
		} else {
			logger.Error(err, "c.varmorInterface.ArmorProfiles().Get()")
			return err
		}
	} else {
		logger.Info("delete ArmorProfile")
		err = c.varmorInterface.ArmorProfiles(varmorconfig.Namespace).Delete(context.Background(), apName, metav1.DeleteOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().Delete()")
			return err
		}
	}

	if c.restartExistWorkloads && ap.Spec.UpdateExistingWorkloads {
		// This will trigger the rolling upgrade of the target workloads
		logger.Info("delete annotations of target workloads to trigger a rolling upgrade asynchronously")
		go updateWorkloadAnnotationsAndEnv(
			c.appsInterface,
			metav1.NamespaceAll,
			ap.Spec.Profile.Enforcer,
			"",
			ap.Spec.Target,
			"", false, logger)
	}

	// Cleanup the PolicyStatus and ModelingStatus of status manager for the deleted VarmorClusterPolicy/ArmorProfile object
	logger.Info("cleanup the policy status of statusmanager.policystatuses")
	c.statusManager.DeleteCh <- name

	return nil
}

func (c *ClusterPolicyController) updateVarmorClusterPolicyStatus(
	vcp *varmor.VarmorClusterPolicy,
	profileName string,
	resetReady bool,
	phase varmor.VarmorPolicyPhase,
	condType varmor.VarmorPolicyConditionType,
	status apicorev1.ConditionStatus,
	reason, message string) error {

	condition := varmor.VarmorPolicyCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
	exist := false
	if condition.Type == varmortypes.VarmorPolicyUpdated {
		for i, c := range vcp.Status.Conditions {
			if c.Type == varmortypes.VarmorPolicyUpdated {
				condition.DeepCopyInto(&vcp.Status.Conditions[i])
				exist = true
				break
			}
		}
	}
	if !exist {
		vcp.Status.Conditions = append(vcp.Status.Conditions, condition)
	}

	if profileName != "" {
		vcp.Status.ProfileName = profileName
	}
	if resetReady {
		vcp.Status.Ready = false
	}
	if phase != varmortypes.VarmorPolicyUnchanged {
		vcp.Status.Phase = phase
	}

	_, err := c.varmorInterface.VarmorClusterPolicies().UpdateStatus(context.Background(), vcp, metav1.UpdateOptions{})

	return err
}

func (c *ClusterPolicyController) ignoreAdd(vcp *varmor.VarmorClusterPolicy, logger logr.Logger) bool {
	if vcp.Spec.Target.Kind != "Deployment" && vcp.Spec.Target.Kind != "StatefulSet" && vcp.Spec.Target.Kind != "DaemonSet" && vcp.Spec.Target.Kind != "Pod" {
		err := fmt.Errorf("Target.Kind is not supported")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(vcp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"This kind of target is not supported.")
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
		}
		return true
	}

	if vcp.Spec.Target.Name == "" && vcp.Spec.Target.Selector == nil {
		err := fmt.Errorf("target.Name and target.Selector are empty")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(vcp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"You should specify the target workload by name or selector.")
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
		}
		return true
	}

	if vcp.Spec.Target.Name != "" && vcp.Spec.Target.Selector != nil {
		err := fmt.Errorf("target.Name and target.Selector are exclusive")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(vcp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"You shouldn't specify the target workload by both name and selector.")
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
		}
		return true
	}

	if !c.enableBehaviorModeling && vcp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
		err := fmt.Errorf("the BehaviorModeling mode is not enabled")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(vcp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"The BehaviorModeling feature is not enabled.")
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
		}
		return true
	}

	// Do not exceed the length of a standard Kubernetes name (63 characters)
	// Note: The advisory length of AppArmor profile name is 100 (See https://bugs.launchpad.net/apparmor/+bug/1499544).
	profileName := varmorprofile.GenerateArmorProfileName("", vcp.Name, true)
	if len(profileName) > 63 {
		err := fmt.Errorf("the length of ArmorProfile name is exceed 63. name: %s, length: %d", profileName, len(profileName))
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		msg := fmt.Sprintf("The length of VarmorClusterPolicy object name is too long, please limit it to %d bytes", 63-len(varmorprofile.ProfileNameTemplate)+4-len(vcp.Namespace))
		err = c.updateVarmorClusterPolicyStatus(vcp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			msg)
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
		}
		return true
	}

	return false
}

func (c *ClusterPolicyController) handleAddVarmorClusterPolicy(vcp *varmor.VarmorClusterPolicy) error {
	logger := c.log.WithName("handleAddVarmorClusterPolicy()")

	logger.Info("VarmorClusterPolicy created", "name", vcp.Name, "labels", vcp.Labels, "target", vcp.Spec.Target)

	if c.ignoreAdd(vcp, logger) {
		return nil
	}

	ap, err := varmorprofile.NewArmorProfile(vcp, c.varmorInterface, true)
	if err != nil {
		logger.Error(err, "NewArmorProfile() failed")
		err = c.updateVarmorClusterPolicyStatus(vcp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Error",
			err.Error())
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
			return err
		}
		return nil
	}

	logger.Info("update VarmorClusterPolicy/status (created=true)")
	err = c.updateVarmorClusterPolicyStatus(vcp, ap.Spec.Profile.Name, true, varmortypes.VarmorPolicyPending, varmortypes.VarmorPolicyCreated, apicorev1.ConditionTrue, "", "")
	if err != nil {
		logger.Error(err, "updateVarmorClusterPolicyStatus()")
		return err
	}

	if vcp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
		err = resetArmorProfileModelStatus(c.varmorInterface, ap.Namespace, ap.Name)
		if err != nil {
			logger.Error(err, "resetArmorProfileModelStatus()")
		}
	}

	c.statusManager.UpdateDesiredNumber = true

	logger.Info("create ArmorProfile")
	ap, err = c.varmorInterface.ArmorProfiles(varmorconfig.Namespace).Create(context.Background(), ap, metav1.CreateOptions{})
	if err != nil {
		logger.Error(err, "ArmorProfile().Create()")
		return err
	}

	if c.restartExistWorkloads && vcp.Spec.UpdateExistingWorkloads {
		// This will trigger the rolling upgrade of the target workloads
		logger.Info("add annotations to target workloads to trigger a rolling upgrade asynchronously")
		go updateWorkloadAnnotationsAndEnv(
			c.appsInterface,
			metav1.NamespaceAll,
			vcp.Spec.Policy.Enforcer,
			vcp.Spec.Policy.Mode,
			vcp.Spec.Target,
			ap.Name,
			c.bpfExclusiveMode,
			logger)
	}

	return nil
}

func (c *ClusterPolicyController) ignoreUpdate(newVp *varmor.VarmorClusterPolicy, oldAp *varmor.ArmorProfile, logger logr.Logger) (bool, error) {
	// Disallow modify the target of VarmorClusterPolicy.
	if !reflect.DeepEqual(newVp.Spec.Target, oldAp.Spec.Target) {
		err := fmt.Errorf("modify spec.target is forbidden")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyUnchanged, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Modify the target of VarmorClusterPolicy is not allowed. You need to recreate the VarmorClusterPolicy object.")
		return true, err
	}

	// Disallow switch mode from others to BehaviorModeling.
	if newVp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode &&
		oldAp.Spec.BehaviorModeling.Duration == 0 {
		err := fmt.Errorf("disallow switch spec.policy.mode from others to BehaviorModeling")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyUnchanged, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Switch the mode from others to BehaviorModeling is not allowed. You need to recreate the VarmorClusterPolicy object.")
		return true, err
	}

	// Disallow switch mode from BehaviorModeling to others.
	if newVp.Spec.Policy.Mode != varmortypes.BehaviorModelingMode &&
		oldAp.Spec.BehaviorModeling.Duration != 0 {
		err := fmt.Errorf("disallow switch spec.policy.mode from BehaviorModeling to others")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyUnchanged, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Switch the mode from BehaviorModeling to others is not allowed. You need to recreate the VarmorClusterPolicy object.")
		return true, err
	}

	// Disallow modify the VarmorClusterPolicy that run as BehaviorModeling mode and already completed.
	if newVp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode &&
		newVp.Status.Phase == varmortypes.VarmorPolicyCompleted {
		err := fmt.Errorf("disallow modify the VarmorClusterPolicy that run as BehaviorModeling mode and already completed")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", false, varmortypes.VarmorPolicyUnchanged, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Modify the VarmorClusterPolicy that run as BehaviorModeling mode and already completed is not allowed. You need to recreate the VarmorClusterPolicy object.")
		return true, err
	}

	// Nothing need to be updated if VarmorClusterPolicy is in the modeling phase and its duration is not changed.
	if newVp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode &&
		newVp.Status.Phase == varmortypes.VarmorPolicyModeling &&
		newVp.Spec.Policy.ModelingOptions.Duration == oldAp.Spec.BehaviorModeling.Duration {
		logger.Info("nothing need to be updated (duration is not changed)")
		return true, nil
	}

	// Disallow shutting down the enforcer that has been activated.
	newEnforcers := varmortypes.GetEnforcerType(newVp.Spec.Policy.Enforcer)
	oldEnforcers := varmortypes.GetEnforcerType(oldAp.Spec.Profile.Enforcer)
	if newEnforcers&oldEnforcers != oldEnforcers {
		err := fmt.Errorf("disallow shutting down the enforcer that has been activated")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyUnchanged, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Modifying a policy to remove an already-set enforcer is not allowed. To remove enforcers, you must recreate the VarmorClusterPolicy object.")
		return true, err
	}

	// Disallow switching the enforcer during modeling.
	if newEnforcers != oldEnforcers && newVp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
		err := fmt.Errorf("disallow switch the enforcer")
		logger.Error(err, "update VarmorClusterPolicy/status with forbidden info")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyUnchanged, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Switch the enforcer during modeling is not allowed. You need to recreate the VarmorClusterPolicy object.")
		return true, err
	}

	return false, nil
}

func (c *ClusterPolicyController) handleUpdateVarmorClusterPolicy(newVp *varmor.VarmorClusterPolicy, oldAp *varmor.ArmorProfile) error {
	logger := c.log.WithName("handleUpdateVarmorClusterPolicy()")

	logger.Info("VarmorClusterPolicy updated", "name", newVp.Name, "labels", newVp.Labels, "target", newVp.Spec.Target)

	if ignore, err := c.ignoreUpdate(newVp, oldAp, logger); ignore {
		if err != nil {
			logger.Error(err, "ignoreUpdate()")
		}
		return err
	}

	// First, reset VarmorClusterPolicy/status
	logger.Info("1. reset VarmorClusterPolicy/status (updated=true)", "name", newVp.Name)
	err := c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyPending, varmortypes.VarmorPolicyUpdated, apicorev1.ConditionTrue, "", "")
	if err != nil {
		logger.Error(err, "updateVarmorClusterPolicyStatus()")
		return err
	}

	// Second, build a new ArmorProfileSpec
	newApSpec := oldAp.Spec.DeepCopy()
	newProfile, err := varmorprofile.GenerateProfile(newVp.Spec.Policy, oldAp.Name, oldAp.Namespace, c.varmorInterface, false)
	if err != nil {
		logger.Error(err, "GenerateProfile() failed")
		err = c.updateVarmorClusterPolicyStatus(newVp, "", true, varmortypes.VarmorPolicyError, varmortypes.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Error",
			err.Error())
		if err != nil {
			logger.Error(err, "updateVarmorClusterPolicyStatus()")
			return err
		}
		return nil
	}
	newApSpec.Profile = *newProfile
	newApSpec.UpdateExistingWorkloads = newVp.Spec.UpdateExistingWorkloads
	if newVp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
		newApSpec.BehaviorModeling.Duration = newVp.Spec.Policy.ModelingOptions.Duration
	}

	// Last, do update
	statusKey := newVp.Name
	c.statusManager.UpdateDesiredNumber = true
	if !reflect.DeepEqual(oldAp.Spec, *newApSpec) {
		// Update object
		logger.Info("2. update the object and its status")

		logger.Info("2.1. reset ArmorProfile/status and ArmorProfileModel/Status", "namespace", oldAp.Namespace, "name", oldAp.Name)
		oldAp.Status.CurrentNumberLoaded = 0
		oldAp.Status.Conditions = nil
		oldAp, err = c.varmorInterface.ArmorProfiles(oldAp.Namespace).UpdateStatus(context.Background(), oldAp, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().UpdateStatus()")
			return err
		}

		if newVp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
			err = resetArmorProfileModelStatus(c.varmorInterface, oldAp.Namespace, oldAp.Name)
			if err != nil {
				logger.Error(err, "resetArmorProfileModelStatus()")
			}
		}

		logger.Info("2.2. reset the status cache", "status key", statusKey)
		c.statusManager.ResetCh <- statusKey

		logger.Info("2.3. update ArmorProfile")
		oldAp.Spec = *newApSpec
		forceSetOwnerReference(oldAp, newVp, true)
		_, err = c.varmorInterface.ArmorProfiles(oldAp.Namespace).Update(context.Background(), oldAp, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().Update()")
			return err
		}
	} else if len(oldAp.OwnerReferences) == 0 {
		// Forward compatibility, add an ownerReference to the existing ArmorProfile object
		forceSetOwnerReference(oldAp, newVp, true)
		_, err = c.varmorInterface.ArmorProfiles(oldAp.Namespace).Update(context.Background(), oldAp, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().Update()")
			return err
		}
	} else {
		// Update status
		logger.Info("2. update the object' status")

		logger.Info("2.1. update VarmorClusterPolicy/status and ArmorProfile/status", "status key", statusKey)
		c.statusManager.UpdateStatusCh <- statusKey
	}
	return nil
}

func (c *ClusterPolicyController) syncClusterPolicy(key string) error {
	logger := c.log.WithName("syncClusterPolicy()")

	startTime := time.Now()
	logger.V(3).Info("started syncing policy", "key", key, "startTime", startTime)
	defer func() {
		logger.V(3).Info("finished syncing policy", "key", key, "processingTime", time.Since(startTime).String())
	}()

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		logger.Error(err, "cache.SplitMetaNamespaceKey()")
		return err
	}

	vcp, err := c.varmorInterface.VarmorClusterPolicies().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			// VarmorClusterPolicy delete event
			logger.V(3).Info("processing VarmorClusterPolicy delete event")
			return c.handleDeleteVarmorClusterPolicy(name)
		} else {
			logger.Error(err, "c.varmorInterface.VarmorClusterPolicies().Get()")
			return err
		}
	}

	apName := varmorprofile.GenerateArmorProfileName("", vcp.Name, true)
	ap, err := c.varmorInterface.ArmorProfiles(varmorconfig.Namespace).Get(context.Background(), apName, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			// VarmorClusterPolicy create event
			logger.V(3).Info("processing VarmorClusterPolicy create event")
			return c.handleAddVarmorClusterPolicy(vcp)
		} else {
			logger.Error(err, "c.varmorInterface.ArmorProfiles().Get()")
			return err
		}
	} else {
		// VarmorClusterPolicy update event
		logger.V(3).Info("processing VarmorClusterPolicy update event")
		return c.handleUpdateVarmorClusterPolicy(vcp, ap)
	}
}

func (c *ClusterPolicyController) handleErr(err error, key interface{}) {
	logger := c.log
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < maxRetries {
		logger.Error(err, "failed to sync policy", "key", key)
		c.queue.AddRateLimited(key)
		return
	}

	utilruntime.HandleError(err)
	logger.V(3).Info("dropping policy out of queue", "key", key)
	c.queue.Forget(key)
}

func (c *ClusterPolicyController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	err := c.syncClusterPolicy(key.(string))
	c.handleErr(err, key)

	return true
}

func (c *ClusterPolicyController) worker() {
	for c.processNextWorkItem() {
	}
}

// Run begins watching and syncing.
func (c *ClusterPolicyController) Run(workers int, stopCh <-chan struct{}) {
	logger := c.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if !cache.WaitForCacheSync(stopCh, c.vcpInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	c.vcpInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addVarmorClusterPolicy,
		UpdateFunc: c.updateVarmorClusterPolicy,
		DeleteFunc: c.deleteVarmorClusterPolicy,
	})

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *ClusterPolicyController) CleanUp() {
	c.log.Info("cleaning up")
	c.queue.ShutDown()
}
