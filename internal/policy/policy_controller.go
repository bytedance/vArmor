// Copyright 2021-2023 vArmor Authors
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

// Package policy implements the VarmorPolicy and VarmorClusterPolicy controllers
package policy

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	apicorev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	// informers "k8s.io/client-go/informers/core/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	statusmanager "github.com/bytedance/vArmor/internal/status/apis/v1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	varmorinformer "github.com/bytedance/vArmor/pkg/client/informers/externalversions/varmor/v1beta1"
	varmorlister "github.com/bytedance/vArmor/pkg/client/listers/varmor/v1beta1"
)

const (
	// maxRetries used for setting the retry times of sync failed
	maxRetries = 5
)

type PolicyController struct {
	kubeClient                    *kubernetes.Clientset
	varmorInterface               varmorinterface.CrdV1beta1Interface
	vpInformer                    varmorinformer.VarmorPolicyInformer
	vpLister                      varmorlister.VarmorPolicyLister
	vpInformerSynced              cache.InformerSynced
	queue                         workqueue.RateLimitingInterface
	statusManager                 *statusmanager.StatusManager
	egressCache                   map[string]varmortypes.EgressInfo
	egressCacheMutex              *sync.RWMutex
	restartExistWorkloads         bool
	enableBehaviorModeling        bool
	enablePodServiceEgressControl bool
	bpfExclusiveMode              bool
	log                           logr.Logger
}

// NewPolicyController create a new PolicyController
func NewPolicyController(
	kubeClient *kubernetes.Clientset,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	vpInformer varmorinformer.VarmorPolicyInformer,
	statusManager *statusmanager.StatusManager,
	egressCache map[string]varmortypes.EgressInfo,
	egressCacheMutex *sync.RWMutex,
	restartExistWorkloads bool,
	enableBehaviorModeling bool,
	enablePodServiceEgressControl bool,
	bpfExclusiveMode bool,
	log logr.Logger) (*PolicyController, error) {

	c := PolicyController{
		kubeClient:                    kubeClient,
		varmorInterface:               varmorInterface,
		vpInformer:                    vpInformer,
		vpLister:                      vpInformer.Lister(),
		vpInformerSynced:              vpInformer.Informer().HasSynced,
		queue:                         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "policy"),
		statusManager:                 statusManager,
		egressCache:                   egressCache,
		egressCacheMutex:              egressCacheMutex,
		restartExistWorkloads:         restartExistWorkloads,
		enableBehaviorModeling:        enableBehaviorModeling,
		enablePodServiceEgressControl: enablePodServiceEgressControl,
		bpfExclusiveMode:              bpfExclusiveMode,
		log:                           log,
	}
	return &c, nil
}

func (c *PolicyController) enqueuePolicy(vp *varmor.VarmorPolicy, logger logr.Logger) {
	key, err := cache.MetaNamespaceKeyFunc(vp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	c.queue.Add(key)
}

func (c *PolicyController) addVarmorPolicy(obj interface{}) {
	logger := c.log.WithName("AddFunc()")

	vp := obj.(*varmor.VarmorPolicy)

	logger.V(2).Info("enqueue VarmorPolicy")
	c.enqueuePolicy(vp, logger)
}

func (c *PolicyController) deleteVarmorPolicy(obj interface{}) {
	logger := c.log.WithName("DeleteFunc()")

	vp := obj.(*varmor.VarmorPolicy)

	logger.V(2).Info("enqueue VarmorPolicy")
	c.enqueuePolicy(vp, logger)
}

func (c *PolicyController) updateVarmorPolicy(oldObj, newObj interface{}) {
	logger := c.log.WithName("UpdateFunc()")

	oldVp := oldObj.(*varmor.VarmorPolicy)
	newVp := newObj.(*varmor.VarmorPolicy)

	if newVp.ResourceVersion == oldVp.ResourceVersion ||
		reflect.DeepEqual(newVp.Spec, oldVp.Spec) ||
		!reflect.DeepEqual(newVp.Status, oldVp.Status) {
		logger.V(2).Info("nothing need to be updated")
	} else {
		logger.V(2).Info("enqueue VarmorPolicy")
		c.enqueuePolicy(newVp, logger)
	}
}

func (c *PolicyController) handleDeleteVarmorPolicy(namespace, name string) error {
	logger := c.log.WithName("handleDeleteVarmorPolicy()")
	logger.Info("VarmorPolicy", "namespace", namespace, "name", name)

	apName := varmorprofile.GenerateArmorProfileName(namespace, name, false)
	logger.Info("retrieve ArmorProfile", "namespace", namespace, "name", apName)
	ap, err := c.varmorInterface.ArmorProfiles(namespace).Get(context.Background(), apName, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			logger.V(2).Info("ArmorProfiles object is not found", "namespace", namespace, "name", apName)
		} else {
			logger.Error(err, "c.varmorInterface.ArmorProfiles().Get()")
			return err
		}
	} else {
		if c.restartExistWorkloads && ap.Spec.UpdateExistingWorkloads {
			// This will trigger the rolling upgrade of the target workload
			logger.Info("delete annotations of target workloads to trigger a rolling upgrade asynchronously")
			go updateWorkloadAnnotationsAndEnv(
				c.kubeClient.AppsV1(),
				namespace,
				ap.Spec.Profile.Enforcer,
				"",
				ap.Spec.Target,
				"", false, logger)
		}

		logger.Info("remove the ArmorProfile's finalizers")
		err := varmorutils.RemoveArmorProfileFinalizers(c.varmorInterface, namespace, apName)
		if err != nil {
			logger.Error(err, "failed to remove the ArmorProfile's finalizers")
		}

		// Cleanup the policy from the egress information cache
		policyKey := namespace + "/" + name
		c.egressCacheMutex.Lock()
		delete(c.egressCache, policyKey)
		c.egressCacheMutex.Unlock()
	}

	// Cleanup the PolicyStatus and ModelingStatus of status manager for the deleted VarmorPolicy/ArmorProfile object
	logger.Info("cleanup the policy status (and if any modeling status) of statusmanager.policystatuses")
	policyStatusKey := namespace + "/" + name
	c.statusManager.DeleteCh <- policyStatusKey

	return nil
}

func (c *PolicyController) ignoreAdd(vp *varmor.VarmorPolicy, logger logr.Logger) (bool, error) {
	if vp.Spec.Target.Kind != "Deployment" && vp.Spec.Target.Kind != "StatefulSet" && vp.Spec.Target.Kind != "DaemonSet" && vp.Spec.Target.Kind != "Pod" {
		err := fmt.Errorf("the target kind is not supported")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"The target kind is not supported.")
		return true, err
	}

	if vp.Spec.Target.Name == "" && vp.Spec.Target.Selector == nil {
		err := fmt.Errorf("the target name and selector are empty")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"You should specify the target workload either by name or selector.")
		return true, err
	}

	if vp.Spec.Target.Name != "" && vp.Spec.Target.Selector != nil {
		err := fmt.Errorf("the target name and selector are exclusive")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"You shouldn't specify the target workload using both name and selector.")
		return true, err
	}

	if vp.Spec.Policy.Mode == varmor.EnhanceProtectMode && vp.Spec.Policy.EnhanceProtect == nil {
		err := fmt.Errorf("the enhanceProtect field is not set when the policy runs in the EnhanceProtect mode")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"The enhanceProtect field should be set when the policy runs in the EnhanceProtect mode.")
		return true, err
	}

	if !c.enableBehaviorModeling && vp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
		err := fmt.Errorf("the BehaviorModeling feature is not enabled")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"The BehaviorModeling feature is not enabled.")
		return true, err
	}

	if c.enableBehaviorModeling && vp.Spec.Policy.Mode == varmor.BehaviorModelingMode && vp.Spec.Policy.ModelingOptions == nil {
		err := fmt.Errorf("the modelingOptions field is not set when the policy runs in the BehaviorModeling mode")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			"The modelingOptions field should be set when the policy runs in the BehaviorModeling mode.")
		return true, err
	}

	// Do not exceed the length of a standard Kubernetes name (63 characters)
	// Note: The advisory length of AppArmor profile name is 100 (See https://bugs.launchpad.net/apparmor/+bug/1499544).
	profileName := varmorprofile.GenerateArmorProfileName(vp.Namespace, vp.Name, false)
	if len(profileName) > 63 {
		err := fmt.Errorf("the length of ArmorProfile name is exceed 63. name: %s, length: %d", profileName, len(profileName))
		logger.Error(err, "update the policy status with forbidden info")
		msg := fmt.Sprintf("The length of policy object name is too long, please limit it to %d bytes.", 63-len(varmorprofile.ProfileNameTemplate)+4-len(vp.Namespace))
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Forbidden",
			msg)
		return true, err
	}

	return false, nil
}

func (c *PolicyController) handleAddVarmorPolicy(vp *varmor.VarmorPolicy) error {
	logger := c.log.WithName("handleAddVarmorPolicy()")

	logger.Info("VarmorPolicy created", "namespace", vp.Namespace, "name", vp.Name, "labels", vp.Labels, "target", vp.Spec.Target)

	if ignore, err := c.ignoreAdd(vp, logger); ignore {
		if err != nil {
			logger.Error(err, "ignoreAdd()")
		}
		return err
	}

	ap, egressInfo, err := varmorprofile.NewArmorProfile(c.kubeClient, c.varmorInterface, vp, false, c.enablePodServiceEgressControl, logger)
	if err != nil {
		logger.Error(err, "NewArmorProfile()")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
			"Error",
			err.Error())
		if err != nil {
			logger.Error(err, "statusmanager.UpdateVarmorPolicyStatus()")
			return err
		}
		return nil
	}

	logger.Info("update VarmorPolicy/status (created=true)")
	err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, vp, ap.Spec.Profile.Name, false, varmor.VarmorPolicyPending, varmor.VarmorPolicyCreated, apicorev1.ConditionTrue, "", "")
	if err != nil {
		logger.Error(err, "statusmanager.UpdateVarmorPolicyStatus()")
		return err
	}

	if vp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
		err = resetArmorProfileModelStatus(c.varmorInterface, ap.Namespace, ap.Name)
		if err != nil {
			logger.Error(err, "resetArmorProfileModelStatus()")
		}
	}

	atomic.StoreInt32(&c.statusManager.UpdateDesiredNumber, 1)

	logger.Info("create ArmorProfile")
	ap, err = c.varmorInterface.ArmorProfiles(vp.Namespace).Create(context.Background(), ap, metav1.CreateOptions{})
	if err != nil {
		logger.Error(err, "ArmorProfile().Create()")
		if varmorutils.IsRequestSizeError(err) {
			return statusmanager.UpdateVarmorPolicyStatus(
				c.varmorInterface, vp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyCreated, apicorev1.ConditionFalse,
				"Error",
				"The profiles are too large to create an ArmorProfile object.")
		}
		return err
	}

	// Cache the egress information for the policy which has network egress rules with toPods and toService fields
	if egressInfo != nil && (len(egressInfo.ToPods) > 0 || len(egressInfo.ToServices) > 0) {
		policyKey := vp.Namespace + "/" + vp.Name
		c.egressCacheMutex.Lock()
		c.egressCache[policyKey] = *egressInfo
		c.egressCacheMutex.Unlock()
		logger.Info("egress cache added", "policy key", policyKey, "egress info", egressInfo)
	}

	if c.restartExistWorkloads && vp.Spec.UpdateExistingWorkloads {
		// This will trigger the rolling upgrade of the target workload.
		logger.Info("add annotations to target workloads to trigger a rolling upgrade asynchronously")
		go updateWorkloadAnnotationsAndEnv(
			c.kubeClient.AppsV1(),
			vp.Namespace,
			vp.Spec.Policy.Enforcer,
			vp.Spec.Policy.Mode,
			vp.Spec.Target,
			ap.Name,
			c.bpfExclusiveMode,
			logger)
	}

	return nil
}

func (c *PolicyController) ignoreUpdate(newVp *varmor.VarmorPolicy, oldAp *varmor.ArmorProfile, logger logr.Logger) (bool, error) {
	newEnforcers := varmortypes.GetEnforcerType(newVp.Spec.Policy.Enforcer)
	oldEnforcers := varmortypes.GetEnforcerType(oldAp.Spec.Profile.Enforcer)

	// Disallow modifying the target field of a policy.
	if !reflect.DeepEqual(newVp.Spec.Target, oldAp.Spec.Target) {
		err := fmt.Errorf("disallow modifying the target field of a policy")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyUnchanged, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Modifying the target field of a policy is not allowed. You need to recreate the policy object.")
		return true, err
	}

	// Disallow switching the mode of a policy from BehaviorModeling to others when behavior modeling is still incomplete.
	if newVp.Spec.Policy.Mode != varmor.BehaviorModelingMode &&
		newVp.Status.Phase == varmor.VarmorPolicyModeling {
		err := fmt.Errorf("disallow switching the mode of a policy from BehaviorModeling to others when behavior modeling is still incomplete")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyUnchanged, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Switching the mode of a policy from BehaviorModeling to others is not allowed when behavior modeling is still incomplete.")
		return true, err
	}

	// Disallow modifying the enforcer field of a policy when behavior modeling is still incomplete.
	if newVp.Spec.Policy.Mode == varmor.BehaviorModelingMode &&
		newVp.Status.Phase == varmor.VarmorPolicyModeling &&
		newEnforcers != oldEnforcers {
		err := fmt.Errorf("disallow modifying the enforcer field of a policy when behavior modeling is still incomplete")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyUnchanged, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Modifying the enforcer field of a policy is not allowed when behavior modeling is still incomplete.")
		return true, err
	}

	// Disallow removing the activated AppArmor or Seccomp enforcer.
	if (newEnforcers&oldEnforcers != oldEnforcers) && (newEnforcers|varmortypes.BPF != oldEnforcers) {
		err := fmt.Errorf("disallow removing the activated AppArmor or Seccomp enforcer")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyUnchanged, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"Modifying a policy to remove the AppArmor or Seccomp enforcer is not allowed. To remove them, you need to recreate the policy object.")
		return true, err
	}

	// Make sure the enhanceProtect field has been set when the policy runs in the EnhanceProtect mode.
	if newVp.Spec.Policy.Mode == varmor.EnhanceProtectMode &&
		newVp.Spec.Policy.EnhanceProtect == nil {
		err := fmt.Errorf("the enhanceProtect field is not set when the policy runs in the EnhanceProtect mode")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"The enhanceProtect field should be set when the policy runs in the EnhanceProtect mode.")
		return true, err
	}

	// Make sure the modelingOptions field has been set when the policy running in BehaviorModeling mode.
	if newVp.Spec.Policy.Mode == varmor.BehaviorModelingMode &&
		newVp.Spec.Policy.ModelingOptions == nil {
		err := fmt.Errorf("the modelingOptions field is not set when the policy runs in the BehaviorModeling mode")
		logger.Error(err, "update the policy status with forbidden info")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Forbidden",
			"The modelingOptions field should be set when the policy runs in the BehaviorModeling mode.")
		return true, err
	}

	return false, nil
}

func (c *PolicyController) handleUpdateVarmorPolicy(newVp *varmor.VarmorPolicy, oldAp *varmor.ArmorProfile) error {
	logger := c.log.WithName("handleUpdateVarmorPolicy()")

	logger.Info("VarmorPolicy updated", "namespace", newVp.Namespace, "name", newVp.Name, "labels", newVp.Labels, "target", newVp.Spec.Target)

	if ignore, err := c.ignoreUpdate(newVp, oldAp, logger); ignore {
		if err != nil {
			logger.Error(err, "ignoreUpdate()")
		}
		return err
	}

	statusKey := newVp.Namespace + "/" + newVp.Name

	// First, reset VarmorPolicy/status
	logger.Info("1. reset VarmorPolicy/status (updated=true)", "namesapce", newVp.Namespace, "name", newVp.Name)
	err := statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyPending, varmor.VarmorPolicyUpdated, apicorev1.ConditionTrue, "", "")
	if err != nil {
		logger.Error(err, "statusmanager.UpdateVarmorPolicyStatus()")
		return err
	}

	// Second, create a new ArmorProfileSpec with the updated policy
	complete := false
	if newVp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
		if newVp.Spec.Policy.ModelingOptions != nil {
			createTime := oldAp.CreationTimestamp.Time
			Duration := time.Duration(newVp.Spec.Policy.ModelingOptions.Duration) * time.Minute
			if time.Now().After(createTime.Add(Duration)) {
				complete = true
			}
		}
	}

	newProfile, egressInfo, err := varmorprofile.GenerateProfile(c.kubeClient, c.varmorInterface, newVp.Spec.Policy, oldAp.Name, oldAp.Namespace, complete, c.enablePodServiceEgressControl, logger)
	if err != nil {
		logger.Error(err, "GenerateProfile()")
		err = statusmanager.UpdateVarmorPolicyStatus(c.varmorInterface, newVp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
			"Error",
			err.Error())
		if err != nil {
			logger.Error(err, "statusmanager.UpdateVarmorPolicyStatus()")
			return err
		}
		return nil
	}

	newApSpec := oldAp.Spec.DeepCopy()
	newApSpec.Profile = *newProfile
	newApSpec.UpdateExistingWorkloads = newVp.Spec.UpdateExistingWorkloads
	if newVp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
		// Update the BehaviorModeling duration
		if newVp.Spec.Policy.ModelingOptions != nil {
			newApSpec.BehaviorModeling.Duration = newVp.Spec.Policy.ModelingOptions.Duration
		}

		// Reset the status cache if the BehaviorModeling duration has not expired
		if !complete {
			newApSpec.BehaviorModeling.Enable = true
			logger.Info("reset the status cache", "status key", statusKey)
			atomic.StoreInt32(&c.statusManager.UpdateDesiredNumber, 1)
			c.statusManager.ResetCh <- statusKey
		}
	}

	// Third, cache the egress information for the policy which has network egress rules with toPods and toService fields
	if egressInfo != nil {
		policyKey := statusKey
		c.egressCacheMutex.Lock()
		delete(c.egressCache, policyKey)
		if len(egressInfo.ToPods) > 0 || len(egressInfo.ToServices) > 0 {
			c.egressCache[policyKey] = *egressInfo
		}
		c.egressCacheMutex.Unlock()
		logger.Info("egress cache updated", "policy key", policyKey, "egress info", egressInfo)
	}

	// Last, do update
	if !reflect.DeepEqual(oldAp.Spec, *newApSpec) {
		// Update the objects and their statuses if the spec of ArmorProfile has changed
		logger.Info("2. update the object and its status")

		logger.Info("2.1. reset ArmorProfile/status and ArmorProfileModel/Status", "namespace", oldAp.Namespace, "name", oldAp.Name)
		oldAp.Status.CurrentNumberLoaded = 0
		oldAp.Status.Conditions = nil
		oldAp, err = c.varmorInterface.ArmorProfiles(newVp.Namespace).UpdateStatus(context.Background(), oldAp, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().UpdateStatus()")
			return err
		}

		if newVp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
			err = resetArmorProfileModelStatus(c.varmorInterface, oldAp.Namespace, oldAp.Name)
			if err != nil {
				logger.Error(err, "resetArmorProfileModelStatus()")
			}
		}

		logger.Info("2.2. update ArmorProfile")
		oldAp.Spec = *newApSpec
		forceSetOwnerReference(oldAp, newVp, false)
		_, err = c.varmorInterface.ArmorProfiles(oldAp.Namespace).Update(context.Background(), oldAp, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().Update()")
			if varmorutils.IsRequestSizeError(err) {
				return statusmanager.UpdateVarmorPolicyStatus(
					c.varmorInterface, newVp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
					"Error",
					"The profiles are too large to update the existing ArmorProfile object.")
			}
			return err
		}
	} else if len(oldAp.OwnerReferences) == 0 {
		// Forward compatibility, add an ownerReference to the existing ArmorProfile object
		forceSetOwnerReference(oldAp, newVp, false)
		_, err = c.varmorInterface.ArmorProfiles(oldAp.Namespace).Update(context.Background(), oldAp, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "ArmorProfile().Update()")
			if varmorutils.IsRequestSizeError(err) {
				return statusmanager.UpdateVarmorPolicyStatus(
					c.varmorInterface, newVp, "", false, varmor.VarmorPolicyError, varmor.VarmorPolicyUpdated, apicorev1.ConditionFalse,
					"Error",
					"The profiles are too large to update the existing ArmorProfile object.")
			}
			return err
		}
	} else {
		// Update the objects' statuses
		logger.Info("2. update the object' status")

		logger.Info("2.1. update VarmorPolicy/status and ArmorProfile/status", "status key", statusKey)
		c.statusManager.UpdateStatusCh <- statusKey
	}
	return nil
}

func (c *PolicyController) syncPolicy(key string) error {
	logger := c.log.WithName("syncPolicy()")

	startTime := time.Now()
	logger.V(2).Info("started syncing policy", "key", key, "startTime", startTime)
	defer func() {
		logger.V(2).Info("finished syncing policy", "key", key, "processingTime", time.Since(startTime).String())
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		logger.Error(err, "cache.SplitMetaNamespaceKey()")
		return err
	}

	vp, err := c.varmorInterface.VarmorPolicies(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			// VarmorPolicy delete event
			logger.V(2).Info("processing VarmorPolicy delete event")
			return c.handleDeleteVarmorPolicy(namespace, name)
		} else {
			logger.Error(err, "c.varmorInterface.VarmorPolicies().Get()")
			return err
		}
	}

	newPolicy := false
	apName := varmorprofile.GenerateArmorProfileName(vp.Namespace, vp.Name, false)
	ap, err := c.varmorInterface.ArmorProfiles(vp.Namespace).Get(context.Background(), apName, metav1.GetOptions{})
	if err == nil {
		if policyOwnArmorProfile(vp, ap, false) {
			// VarmorPolicy update event
			logger.V(2).Info("processing VarmorPolicy update event")
			return c.handleUpdateVarmorPolicy(vp, ap)
		} else {
			logger.Info("remove the finalizers of zombie ArmorProfile", "namespace", ap.Namespace, "name", ap.Name)
			err := varmorutils.RemoveArmorProfileFinalizers(c.varmorInterface, ap.Namespace, ap.Name)
			if err != nil {
				return err
			}
			newPolicy = true
		}
	}

	if k8errors.IsNotFound(err) || newPolicy {
		// VarmorPolicy create event
		logger.V(2).Info("processing VarmorPolicy create event")
		return c.handleAddVarmorPolicy(vp)
	}

	return err
}

func (c *PolicyController) handleErr(err error, key interface{}) {
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
	logger.V(2).Info("dropping policy out of queue", "key", key)
	c.queue.Forget(key)
}

func (c *PolicyController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	err := c.syncPolicy(key.(string))
	c.handleErr(err, key)

	return true
}

func (c *PolicyController) worker() {
	for c.processNextWorkItem() {
	}
}

// Run begins watching and syncing.
func (c *PolicyController) Run(workers int, stopCh <-chan struct{}) {
	logger := c.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if !cache.WaitForCacheSync(stopCh, c.vpInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	c.vpInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addVarmorPolicy,
		UpdateFunc: c.updateVarmorPolicy,
		DeleteFunc: c.deleteVarmorPolicy,
	})

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *PolicyController) CleanUp() {
	c.log.Info("cleaning up")
	c.queue.ShutDown()
}
