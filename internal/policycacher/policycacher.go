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

package policycacher

import (
	"fmt"

	"github.com/go-logr/logr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorinformer "github.com/bytedance/vArmor/pkg/client/informers/externalversions/varmor/v1beta1"
	varmorlister "github.com/bytedance/vArmor/pkg/client/listers/varmor/v1beta1"
)

type PolicyCacher struct {
	vcpInformer           varmorinformer.VarmorClusterPolicyInformer
	vcpLister             varmorlister.VarmorClusterPolicyLister
	vcpInformerSynced     cache.InformerSynced
	vpInformer            varmorinformer.VarmorPolicyInformer
	vpLister              varmorlister.VarmorPolicyLister
	vpInformerSynced      cache.InformerSynced
	ClusterPolicyTargets  map[string]varmor.Target
	ClusterPolicyEnforcer map[string]string
	PolicyTargets         map[string]varmor.Target
	PolicyEnforcer        map[string]string
	debug                 bool
	log                   logr.Logger
}

func NewPolicyCacher(
	vcpInformer varmorinformer.VarmorClusterPolicyInformer,
	vpInformer varmorinformer.VarmorPolicyInformer,
	debug bool,
	log logr.Logger) (*PolicyCacher, error) {

	cacher := PolicyCacher{
		vcpInformer:           vcpInformer,
		vcpLister:             vcpInformer.Lister(),
		vcpInformerSynced:     vcpInformer.Informer().HasSynced,
		vpInformer:            vpInformer,
		vpLister:              vpInformer.Lister(),
		vpInformerSynced:      vpInformer.Informer().HasSynced,
		ClusterPolicyTargets:  make(map[string]varmor.Target),
		ClusterPolicyEnforcer: make(map[string]string),
		PolicyTargets:         make(map[string]varmor.Target),
		PolicyEnforcer:        make(map[string]string),
		debug:                 debug,
		log:                   log,
	}

	return &cacher, nil
}

func (c *PolicyCacher) addVarmorClusterPolicy(obj interface{}) {
	logger := c.log.WithName("addVarmorClusterPolicy()")
	vcp := obj.(*varmor.VarmorClusterPolicy)
	key, err := cache.MetaNamespaceKeyFunc(vcp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	c.ClusterPolicyTargets[key] = vcp.Spec.DeepCopy().Target
	c.ClusterPolicyEnforcer[key] = vcp.Spec.Policy.Enforcer
}

func (c *PolicyCacher) updateVarmorClusterPolicy(oldObj, newObj interface{}) {
	logger := c.log.WithName("updateVarmorClusterPolicy()")
	vcp := newObj.(*varmor.VarmorClusterPolicy)
	key, err := cache.MetaNamespaceKeyFunc(vcp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	c.ClusterPolicyTargets[key] = vcp.Spec.DeepCopy().Target
	c.ClusterPolicyEnforcer[key] = vcp.Spec.Policy.Enforcer
}

func (c *PolicyCacher) deleteVarmorClusterPolicy(obj interface{}) {
	logger := c.log.WithName("deleteVarmorClusterPolicy()")
	vcp := obj.(*varmor.VarmorClusterPolicy)
	key, err := cache.MetaNamespaceKeyFunc(vcp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	delete(c.ClusterPolicyTargets, key)
	delete(c.ClusterPolicyEnforcer, key)
}

func (c *PolicyCacher) addVarmorPolicy(obj interface{}) {
	logger := c.log.WithName("addVarmorPolicy()")
	vp := obj.(*varmor.VarmorPolicy)
	key, err := cache.MetaNamespaceKeyFunc(vp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	c.PolicyTargets[key] = vp.Spec.DeepCopy().Target
	c.PolicyEnforcer[key] = vp.Spec.Policy.Enforcer
}

func (c *PolicyCacher) updateVarmorPolicy(oldObj, newObj interface{}) {
	logger := c.log.WithName("updateVarmorPolicy()")
	vp := newObj.(*varmor.VarmorPolicy)
	key, err := cache.MetaNamespaceKeyFunc(vp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	c.PolicyTargets[key] = vp.Spec.DeepCopy().Target
	c.PolicyEnforcer[key] = vp.Spec.Policy.Enforcer
}

func (c *PolicyCacher) deleteVarmorPolicy(obj interface{}) {
	logger := c.log.WithName("deleteVarmorPolicy()")
	vp := obj.(*varmor.VarmorPolicy)
	key, err := cache.MetaNamespaceKeyFunc(vp)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	delete(c.PolicyTargets, key)
	delete(c.PolicyEnforcer, key)
}

func (c *PolicyCacher) Run(stopCh <-chan struct{}) {
	logger := c.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if !cache.WaitForCacheSync(stopCh, c.vcpInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	if !cache.WaitForCacheSync(stopCh, c.vpInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	c.vcpInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addVarmorClusterPolicy,
		UpdateFunc: c.updateVarmorClusterPolicy,
		DeleteFunc: c.deleteVarmorClusterPolicy,
	})

	c.vpInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addVarmorPolicy,
		UpdateFunc: c.updateVarmorPolicy,
		DeleteFunc: c.deleteVarmorPolicy,
	})
}
