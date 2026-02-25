// Copyright 2025 vArmor Authors
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

// Package ipwatcher watches the IP and port changes of pods, services and endpointslices
package ipwatcher

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

const (
	// maxRetries used for setting the retry times of sync failed
	maxRetries = 5
)

type SlimObject struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	EventType  string
	IPs        []string
	AddedIPs   []string
	DeletedIPs []string
	Ports      []varmor.Port
}

type IPWatcher struct {
	varmorInterface  varmorinterface.CrdV1beta1Interface
	podinformer      coreinformers.PodInformer
	podLister        corelisters.PodLister
	serviceinformer  coreinformers.ServiceInformer
	serviceLister    corelisters.ServiceLister
	epsinformer      discoveryinformers.EndpointSliceInformer
	epsLister        discoverylisters.EndpointSliceLister
	queue            workqueue.RateLimitingInterface
	ipPortCache      *IPPortCache
	egressCache      map[string]varmortypes.EgressInfo
	egressCacheMutex *sync.RWMutex
	log              logr.Logger
}

func NewIPWatcher(
	varmorInterface varmorinterface.CrdV1beta1Interface,
	podinformer coreinformers.PodInformer,
	serviceinformer coreinformers.ServiceInformer,
	epsinformer discoveryinformers.EndpointSliceInformer,
	egressCache map[string]varmortypes.EgressInfo,
	egressCacheMutex *sync.RWMutex,
	log logr.Logger,
) (*IPWatcher, error) {

	i := IPWatcher{
		varmorInterface:  varmorInterface,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ip"),
		ipPortCache:      &IPPortCache{},
		egressCache:      egressCache,
		egressCacheMutex: egressCacheMutex,
		log:              log,
	}

	if podinformer != nil {
		i.podinformer = podinformer
		i.podLister = podinformer.Lister()
	}

	if serviceinformer != nil {
		i.serviceinformer = serviceinformer
		i.serviceLister = serviceinformer.Lister()
	}

	if epsinformer != nil {
		i.epsinformer = epsinformer
		i.epsLister = epsinformer.Lister()
	}

	return &i, nil
}

func (i *IPWatcher) handleErr(err error, key interface{}) {
	logger := i.log
	if err == nil {
		i.queue.Forget(key)
		return
	}

	if i.queue.NumRequeues(key) < maxRetries {
		logger.Error(err, "failed to sync policy", "key", key)
		i.queue.AddRateLimited(key)
		return
	}

	utilruntime.HandleError(err)
	logger.V(2).Info("dropping policy out of queue", "key", key)
	i.queue.Forget(key)
}

func (i *IPWatcher) processNextWorkItem() bool {
	obj, quit := i.queue.Get()
	if quit {
		return false
	}
	defer i.queue.Done(obj)
	err := i.sync(obj.(*SlimObject))
	i.handleErr(err, obj)

	return true
}

func (i *IPWatcher) worker() {
	for i.processNextWorkItem() {
	}
}

func (i *IPWatcher) Run(workers int, stopCh <-chan struct{}) {
	logger := i.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if i.podinformer != nil {
		if !cache.WaitForCacheSync(stopCh, i.podinformer.Informer().HasSynced) {
			logger.Error(fmt.Errorf("failed to sync pod informer cache"), "cache.WaitForCacheSync()")
			return
		}
	}

	if i.serviceinformer != nil {
		if !cache.WaitForCacheSync(stopCh, i.serviceinformer.Informer().HasSynced) {
			logger.Error(fmt.Errorf("failed to sync service informer cache"), "cache.WaitForCacheSync()")
			return
		}
	}

	if i.epsinformer != nil {
		if !cache.WaitForCacheSync(stopCh, i.epsinformer.Informer().HasSynced) {
			logger.Error(fmt.Errorf("failed to sync endpointslice informer cache"), "cache.WaitForCacheSync()")
			return
		}
	}

	// Register event handlers for Pod.
	// We assume that the IPs of a Pod can be added but not changed during its lifecircle.
	if i.podinformer != nil {
		i.podinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: i.updatePod,
			DeleteFunc: i.deletePod,
		})
	}

	// Register event handlers for Service.
	if i.serviceinformer != nil {
		i.serviceinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    i.addService,
			UpdateFunc: i.updateService,
			DeleteFunc: i.deleteService})
	}

	// Register event handlers for EndpointSlice.
	if i.epsinformer != nil {
		i.epsinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    i.addEndpointSlice,
			UpdateFunc: i.updateEndpointSlice,
			DeleteFunc: i.deleteEndpointSlice})
	}

	for index := 0; index < workers; index++ {
		go wait.Until(i.worker, time.Second, stopCh)
	}

	go func() {
		for {
			// Wait for the policy controllers to finish processing all policies
			time.Sleep(time.Second * 30)

			// Synchronize the IP cache hourly
			i.log.Info("Synchronize the IP cache regularly")
			ec := make(map[string]varmortypes.EgressInfo)
			i.egressCacheMutex.RLock()
			for key, egressInfo := range i.egressCache {
				if len(egressInfo.ToServices) != 0 {
					ec[key] = varmortypes.EgressInfo{
						ToServices: egressInfo.DeepCopy().ToServices,
					}
				}
			}
			i.egressCacheMutex.RUnlock()
			i.ipPortCache.SyncCache(ec, i.serviceLister, i.epsLister)

			// Clean up the IP cache hourly
			time.Sleep(time.Hour * 1)
			i.log.Info("Clean up the IP cache regularly")
			if err := i.ipPortCache.CleanupStaleEntries(i.serviceLister, i.epsLister); err != nil {
				i.log.Error(err, "Resync cleanup failed")
			}
		}
	}()

	<-stopCh
}
