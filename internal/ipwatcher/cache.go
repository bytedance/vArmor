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
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"

	varmortypes "github.com/bytedance/vArmor/internal/types"
)

type IPCache struct {
	cache sync.Map // key: UID (string), value: []string (IPs)
}

func (c *IPCache) Get(uid string) ([]string, bool) {
	value, ok := c.cache.Load(uid)
	if !ok {
		return []string{}, false
	}
	ips, ok := value.([]string)
	if !ok {
		return []string{}, false
	}
	return ips, true
}

func (c *IPCache) Update(uid string, ips []string) {
	c.cache.Store(uid, ips)
}

func (c *IPCache) Delete(uid string) {
	c.cache.Delete(uid)
}

func (c *IPCache) GetAllEntries() map[string][]string {
	m := make(map[string][]string)

	c.cache.Range(func(key, value interface{}) bool {
		uid := key.(string)
		ips := value.([]string)
		m[uid] = ips
		return true
	})

	return m
}

func (c *IPCache) SyncCache(ec map[string]varmortypes.EgressInfo, svcLister corelisters.ServiceLister, epsLister discoverylisters.EndpointSliceLister) {
	for _, egressInfo := range ec {
		for _, toService := range egressInfo.ToServices {
			if toService.ServiceSelector != nil {
				serviceSelector, err := metav1.LabelSelectorAsSelector(toService.ServiceSelector)
				if err != nil {
					continue
				}

				services, err := svcLister.List(serviceSelector)
				if err != nil {
					continue
				}
				for _, service := range services {
					if len(service.Spec.ClusterIPs) != 0 {
						if _, ok := c.Get(string(service.UID)); !ok {
							c.Update(string(service.UID), service.Spec.ClusterIPs)
						}
					}
				}

				endpointSlices, err := epsLister.List(serviceSelector)
				if err != nil {
					continue
				}
				for _, endpointSlice := range endpointSlices {
					var IPs []string
					for _, endpoint := range endpointSlice.Endpoints {
						IPs = append(IPs, endpoint.Addresses...)
					}
					if len(IPs) != 0 {
						if _, ok := c.Get(string(endpointSlice.UID)); !ok {
							c.Update(string(endpointSlice.UID), IPs)
						}
					}
				}
			} else {
				service, err := svcLister.Services(toService.Namespace).Get(toService.Name)
				if err != nil {
					continue
				}
				if len(service.Spec.ClusterIPs) != 0 {
					if _, ok := c.Get(string(service.UID)); !ok {
						c.Update(string(service.UID), service.Spec.ClusterIPs)
					}
				}

				labelSelector := labels.SelectorFromSet(labels.Set{
					"kubernetes.io/service-name": toService.Name,
				})
				endpointSlices, err := epsLister.EndpointSlices(toService.Namespace).List(labelSelector)
				if err != nil {
					continue
				}
				for _, endpointSlice := range endpointSlices {
					var IPs []string
					for _, endpoint := range endpointSlice.Endpoints {
						IPs = append(IPs, endpoint.Addresses...)
					}
					if len(IPs) != 0 {
						if _, ok := c.Get(string(endpointSlice.UID)); !ok {
							c.Update(string(endpointSlice.UID), IPs)
						}
					}
				}
			}
		}
	}
}

func (c *IPCache) CleanupStaleEntries(svcLister corelisters.ServiceLister, epsLister discoverylisters.EndpointSliceLister) error {
	currentUIDs := make(map[string]bool)

	epsList, err := epsLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, eps := range epsList {
		currentUIDs[string(eps.UID)] = true
	}

	svcList, err := svcLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, svc := range svcList {
		currentUIDs[string(svc.UID)] = true
	}

	c.cache.Range(func(key, value interface{}) bool {
		uid := key.(string)
		if !currentUIDs[uid] {
			c.Delete(uid)
		}
		return true
	})

	return nil
}
