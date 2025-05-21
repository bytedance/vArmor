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

package ipwatcher

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	// discoveryinformers "k8s.io/client-go/kubernetes/typed/discovery/v1"

	statusmanager "github.com/bytedance/vArmor/internal/status/apis/v1"
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
	IPs        []string
	AddedIPs   []string
	DeletedIPs []string
	EventType  string
}

type IPWatcher struct {
	varmorInterface  varmorinterface.CrdV1beta1Interface
	podInterface     typedcore.PodInterface
	podinformer      coreinformers.PodInformer
	podLister        corelisters.PodLister
	serviceInterface typedcore.ServiceInterface
	serviceinformer  coreinformers.ServiceInformer
	serviceLister    corelisters.ServiceLister
	nsLister         corelisters.NamespaceLister
	epsinformer      discoveryinformers.EndpointSliceInformer
	epsLister        discoverylisters.EndpointSliceLister
	statusManager    *statusmanager.StatusManager
	queue            workqueue.RateLimitingInterface
	ipCache          *IPCache
	egressCache      map[string]varmortypes.EgressInfo
	egressCacheMutex *sync.RWMutex
	log              logr.Logger
}

func NewIPWatcher(
	varmorInterface varmorinterface.CrdV1beta1Interface,
	podInterface typedcore.PodInterface,
	serviceInterface typedcore.ServiceInterface,
	podinformer coreinformers.PodInformer,
	serviceinformer coreinformers.ServiceInformer,
	nsinformer coreinformers.NamespaceInformer,
	epsinformer discoveryinformers.EndpointSliceInformer,
	statusManager *statusmanager.StatusManager,
	egressCache map[string]varmortypes.EgressInfo,
	egressCacheMutex *sync.RWMutex,
	log logr.Logger,
) (*IPWatcher, error) {

	i := IPWatcher{
		varmorInterface:  varmorInterface,
		podInterface:     podInterface,
		serviceInterface: serviceInterface,
		podinformer:      podinformer,
		podLister:        podinformer.Lister(),
		serviceinformer:  serviceinformer,
		serviceLister:    serviceinformer.Lister(),
		nsLister:         nsinformer.Lister(),
		epsinformer:      epsinformer,
		epsLister:        epsinformer.Lister(),
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ip"),
		ipCache:          &IPCache{},
		egressCache:      egressCache,
		egressCacheMutex: egressCacheMutex,
		log:              log,
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

	if !cache.WaitForCacheSync(stopCh, i.podinformer.Informer().HasSynced) {
		logger.Error(fmt.Errorf("failed to sync pod informer cache"), "cache.WaitForCacheSync()")
		return
	}

	if !cache.WaitForCacheSync(stopCh, i.serviceinformer.Informer().HasSynced) {
		logger.Error(fmt.Errorf("failed to sync service informer cache"), "cache.WaitForCacheSync()")
		return
	}

	if !cache.WaitForCacheSync(stopCh, i.epsinformer.Informer().HasSynced) {
		logger.Error(fmt.Errorf("failed to sync endpointslice informer cache"), "cache.WaitForCacheSync()")
		return
	}

	// Register event handlers for Pod.
	// We assume that the IPs of a Pod can be added but not changed during its lifecircle.
	i.podinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			logger := i.log.WithName("UpdateFunc()")
			pod := newObj.(*corev1.Pod)
			oldPod := oldObj.(*corev1.Pod)

			if !reflect.DeepEqual(pod.Status.PodIPs, oldPod.Status.PodIPs) ||
				!reflect.DeepEqual(pod.Labels, oldPod.Labels) {
				logger.V(2).Info("pod updated", "new", pod, "old", oldPod)

				IPs := []string{}
				for _, ip := range pod.Status.PodIPs {
					IPs = append(IPs, ip.IP)
				}

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "Pod",
					},
					ObjectMeta: pod.ObjectMeta,
					IPs:        IPs,
					AddedIPs:   IPs,
					DeletedIPs: []string{},
					EventType:  "UPDATE",
				})
			}
		},
		DeleteFunc: func(obj interface{}) {
			logger := i.log.WithName("DeleteFunc()")
			pod := obj.(*corev1.Pod)

			if len(pod.Status.PodIPs) != 0 {
				logger.V(2).Info("pod deleted", "pod", pod)

				IPs := []string{}
				for _, ip := range pod.Status.PodIPs {
					IPs = append(IPs, ip.IP)
				}

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "Pod",
					},
					ObjectMeta: pod.ObjectMeta,
					IPs:        IPs,
					AddedIPs:   []string{},
					DeletedIPs: IPs,
					EventType:  "DELETE",
				})
			}
		},
	})

	// Register event handlers for Service.
	i.serviceinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			logger := i.log.WithName("AddFunc()")
			svc := obj.(*corev1.Service)

			if len(svc.Spec.ClusterIPs) != 0 {
				logger.V(2).Info("service added", "service", svc)

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "Service",
					},
					ObjectMeta: svc.ObjectMeta,
					IPs:        svc.Spec.ClusterIPs,
					AddedIPs:   svc.Spec.ClusterIPs,
					DeletedIPs: []string{},
					EventType:  "ADD",
				})
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			logger := i.log.WithName("UpdateFunc()")
			svc := newObj.(*corev1.Service)
			oldSvc := oldObj.(*corev1.Service)

			addedIPs := svc.Spec.ClusterIPs

			var deletedIPs []string
			lastIPs, ok := i.ipCache.Get(string(svc.UID))
			if !ok {
				lastIPs = oldSvc.Spec.ClusterIPs
			}
			for _, lastIP := range lastIPs {
				found := false
				for _, ip := range addedIPs {
					if lastIP == ip {
						found = true
						break
					}
				}
				if !found {
					deletedIPs = append(deletedIPs, lastIP)
				}
			}

			if len(deletedIPs) != 0 ||
				!reflect.DeepEqual(addedIPs, lastIPs) ||
				!reflect.DeepEqual(svc.Labels, oldSvc.Labels) {
				logger.V(2).Info("service updated", "new", svc, "old", oldSvc)

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "Service",
					},
					ObjectMeta: svc.ObjectMeta,
					IPs:        addedIPs,
					AddedIPs:   addedIPs,
					DeletedIPs: deletedIPs,
					EventType:  "UPDATE",
				})
			}
		},
		DeleteFunc: func(obj interface{}) {
			logger := i.log.WithName("DeleteFunc()")
			svc := obj.(*corev1.Service)

			if len(svc.Spec.ClusterIPs) != 0 {
				logger.V(2).Info("service deleted", "service", svc)

				var deletedIPs []string
				lastIPs, ok := i.ipCache.Get(string(svc.UID))
				if ok {
					deletedIPs = lastIPs
				} else {
					deletedIPs = svc.Spec.ClusterIPs
				}

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "Service",
					},
					ObjectMeta: svc.ObjectMeta,
					IPs:        deletedIPs,
					AddedIPs:   []string{},
					DeletedIPs: deletedIPs,
					EventType:  "DELETE",
				})
			}
		}})

	// Register event handlers for EndpointSlice.
	i.epsinformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			logger := i.log.WithName("AddFunc()")
			eps := obj.(*discoveryv1.EndpointSlice)

			if _, ok := eps.Labels["kubernetes.io/service-name"]; ok && len(eps.Endpoints) != 0 {
				logger.V(2).Info("endpointslice added", "endpointslice", eps)

				var addedIPs []string
				for _, ep := range eps.Endpoints {
					addedIPs = append(addedIPs, ep.Addresses...)
				}

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "EndpointSlice",
					},
					ObjectMeta: eps.ObjectMeta,
					IPs:        addedIPs,
					AddedIPs:   addedIPs,
					DeletedIPs: []string{},
					EventType:  "ADD",
				})
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			logger := i.log.WithName("UpdateFunc()")
			eps := newObj.(*discoveryv1.EndpointSlice)
			oldEps := oldObj.(*discoveryv1.EndpointSlice)

			if _, ok := eps.Labels["kubernetes.io/service-name"]; !ok {
				return
			}

			var addedIPs []string
			for _, ep := range eps.Endpoints {
				addedIPs = append(addedIPs, ep.Addresses...)
			}

			var deletedIPs []string
			lastIPs, ok := i.ipCache.Get(string(eps.UID))
			if !ok {
				for _, ep := range oldEps.Endpoints {
					lastIPs = append(lastIPs, ep.Addresses...)
				}
			}
			for _, lastIP := range lastIPs {
				found := false
				for _, ip := range addedIPs {
					if lastIP == ip {
						found = true
						break
					}
				}
				if !found {
					deletedIPs = append(deletedIPs, lastIP)
				}
			}

			if len(deletedIPs) != 0 ||
				!reflect.DeepEqual(addedIPs, lastIPs) ||
				!reflect.DeepEqual(eps.Labels, oldEps.Labels) {
				logger.V(2).Info("endpointslice updated", "new", eps, "old", oldEps, "lastIPs", lastIPs)

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "EndpointSlice",
					},
					ObjectMeta: eps.ObjectMeta,
					IPs:        addedIPs,
					AddedIPs:   addedIPs,
					DeletedIPs: deletedIPs,
					EventType:  "UPDATE",
				})
			}
		},
		DeleteFunc: func(obj interface{}) {
			logger := i.log.WithName("DeleteFunc()")
			eps := obj.(*discoveryv1.EndpointSlice)

			if _, ok := eps.Labels["kubernetes.io/service-name"]; ok && len(eps.Endpoints) != 0 {
				logger.V(2).Info("endpointslice deleted", "endpointslice", eps)

				var deletedIPs []string
				lastIPs, ok := i.ipCache.Get(string(eps.UID))
				if ok {
					deletedIPs = lastIPs
				} else {
					for _, ep := range eps.Endpoints {
						deletedIPs = append(deletedIPs, ep.Addresses...)
					}
				}

				i.queue.Add(&SlimObject{
					TypeMeta: metav1.TypeMeta{
						Kind: "EndpointSlice",
					},
					ObjectMeta: eps.ObjectMeta,
					IPs:        deletedIPs,
					AddedIPs:   []string{},
					DeletedIPs: deletedIPs,
					EventType:  "DELETE",
				})
			}
		}})

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
			i.ipCache.SyncCache(ec, i.serviceLister, i.epsLister)

			// Clean up the IP cache hourly
			time.Sleep(time.Hour * 1)
			i.log.Info("Clean up the IP cache regularly")
			if err := i.ipCache.CleanupStaleEntries(i.serviceLister, i.epsLister); err != nil {
				i.log.Error(err, "Resync cleanup failed")
			}
		}
	}()

	<-stopCh
}
