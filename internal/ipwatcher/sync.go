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
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmorbpfprofile "github.com/bytedance/vArmor/internal/profile/bpf"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func (i *IPWatcher) updateArmorProfile(policyKey string, mode uint32, addedIPs []string, deletedIPs []string, ports []varmor.Port) (bool, error) {
	updated := false
	namespace, name, err := cache.SplitMetaNamespaceKey(policyKey)
	if err != nil {
		return updated, err
	}
	apName := varmorprofile.GenerateArmorProfileName(namespace, name, namespace == "")

	return updated, retry.RetryOnConflict(retry.DefaultRetry,
		func() error {
			ap, err := i.varmorInterface.ArmorProfiles(namespace).Get(context.TODO(), apName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			if len(addedIPs) != 0 && ap.Spec.Profile.Bpf == nil {
				ap.Spec.Profile.Bpf = &varmor.BpfContent{}
			} else if len(deletedIPs) != 0 && (ap.Spec.Profile.Bpf == nil || ap.Spec.Profile.Bpf.Networks == nil) {
				return nil
			}

			// Remove rules from the ArmorProfile object
			var newNetworks []varmor.NetworkContent
			for _, network := range ap.Spec.Profile.Bpf.Networks {
				if network.Address == nil {
					newNetworks = append(newNetworks, network)
					continue
				}
				found := false
				for _, IP := range deletedIPs {
					if IP == network.Address.IP {
						found = true
						updated = true
						break
					}
				}
				if !found {
					newNetworks = append(newNetworks, network)
				}
			}
			ap.Spec.Profile.Bpf.Networks = newNetworks

			// Add rules to the ArmorProfile object
			for _, IP := range addedIPs {
				found := false
				for _, network := range ap.Spec.Profile.Bpf.Networks {
					if network.Address != nil && network.Address.IP == IP {
						found = true
						break
					}
				}
				if !found {
					updated = true
					b := varmor.BpfContent{}
					err = varmorbpfprofile.GenerateRawNetworkEgressRuleWithIPCidrPorts(&b, mode, "", IP, ports)
					if err != nil {
						continue
					}
					ap.Spec.Profile.Bpf.Networks = append(ap.Spec.Profile.Bpf.Networks, b.Networks...)
				}
			}

			if len(ap.Spec.Profile.Bpf.Networks) > bpfenforcer.MaxBpfNetworkRuleCount {
				return fmt.Errorf("the maximum number of BPF network rules exceeded (max: %d, expected: %d)",
					bpfenforcer.MaxBpfNetworkRuleCount, len(ap.Spec.Profile.Bpf.Networks))
			}

			_, err = i.varmorInterface.ArmorProfiles(ap.Namespace).Update(context.Background(), ap, metav1.UpdateOptions{})
			return err
		})
}

func (i *IPWatcher) sync(obj *SlimObject) error {
	logger := i.log.WithName("syncPolicy()")

	switch obj.Kind {
	case "Pod":
		// Copy the egressCache
		ec := make(map[string]varmortypes.EgressInfo)
		i.egressCacheMutex.RLock()
		for key, egressInfo := range i.egressCache {
			if len(egressInfo.ToPods) != 0 {
				ec[key] = varmortypes.EgressInfo{
					ToPods: egressInfo.DeepCopy().ToPods,
				}
			}
		}
		i.egressCacheMutex.RUnlock()
		logger.V(2).Info("processing pod", "object", obj, "egress cache", ec)

		// Traverse all policies that contains network egress rules.
		for policyKey, egressInfo := range ec {
			// Traverse all network egress rules of the policy.
			for _, toPod := range egressInfo.ToPods {
				// Check If the podSelector of the rule matches the pod.
				selector, _ := metav1.LabelSelectorAsSelector(toPod.PodSelector)
				if !selector.Matches(labels.Set(obj.Labels)) {
					continue
				}
				// Check If the namespace of the rule matches the pod.
				if toPod.Namespace != "" && toPod.Namespace != obj.Namespace {
					continue
				}

				// Update the ArmorProfile object with the Pod's IPs.
				logger.Info("the pod matched by the policy", "policy key", policyKey, "rule", toPod,
					"name", obj.Name, "namespace", obj.Namespace, "labels", obj.Labels,
					"event type", obj.EventType, "added ips", obj.AddedIPs, "deleted ips", obj.DeletedIPs)
				updated, err := i.updateArmorProfile(policyKey, toPod.Mode, obj.AddedIPs, obj.DeletedIPs, toPod.Ports)
				if err != nil {
					logger.Error(fmt.Errorf("failed to update ArmorProfile for the pod object. error: %w", err),
						"policy key", policyKey, "name", obj.Name, "namespace", obj.Namespace)
				} else {
					// We assume that there is only one pod item in the policy's toPods array that matches the pod.
					// So we can just break out of this iteration.
					if updated {
						break
					}
				}
			}
		}

	case "Service":
		// Copy the egressCache
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
		logger.V(2).Info("processing service", "object", obj, "egress cache", ec)

		// Traverse all policies that contains network egress rules.
		for policyKey, egressInfo := range ec {
			// Traverse all network egress rules of the policy.
			for _, toService := range egressInfo.ToServices {
				// Check If the rule matches the service.
				if toService.ServiceSelector != nil {
					selector, _ := metav1.LabelSelectorAsSelector(toService.ServiceSelector)
					if !selector.Matches(labels.Set(obj.Labels)) {
						continue
					}
					if toService.Namespace != "" && toService.Namespace != obj.Namespace {
						continue
					}
				} else if toService.Name != obj.Name || toService.Namespace != obj.Namespace {
					continue
				}

				// Update the ArmorProfile object with the Service's cluster IPs
				logger.Info("the service matched by the policy", "policy key", policyKey, "rule", toService,
					"name", obj.Name, "namespace", obj.Namespace, "labels", obj.Labels,
					"event type", obj.EventType, "added ips", obj.AddedIPs, "deleted ips", obj.DeletedIPs, "ports", obj.Ports)
				updated, err := i.updateArmorProfile(policyKey, toService.Mode, obj.AddedIPs, obj.DeletedIPs, obj.Ports)
				if err != nil {
					logger.Error(fmt.Errorf("failed to update ArmorProfile for the service object. error: %w", err),
						"policy key", policyKey, "name", obj.Name, "namespace", obj.Namespace)
				} else {
					if obj.EventType == "DELETE" {
						i.ipPortCache.Delete(string(obj.UID))
					} else {
						i.ipPortCache.Update(string(obj.UID), ipPort{
							IPs:   obj.IPs,
							Ports: obj.Ports,
						})
					}
					// We assume that there is only one service item in the policy's toServices array that matches the service.
					// So we can just break out of this iteration.
					if updated {
						break
					}
				}
			}
		}
	case "EndpointSlice":
		// Copy the egressCache
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
		logger.V(2).Info("processing endpointslice", "object", obj, "egress cache", ec)

		// Traverse all policies that contains network egress rules.
		for policyKey, egressInfo := range ec {
			// Traverse all network egress rules of the policy.
			for _, toService := range egressInfo.ToServices {
				// Check If the rule matches the endpointslice.
				if toService.ServiceSelector != nil {
					selector, _ := metav1.LabelSelectorAsSelector(toService.ServiceSelector)
					if !selector.Matches(labels.Set(obj.Labels)) {
						continue
					}
					if toService.Namespace != "" && toService.Namespace != obj.Namespace {
						continue
					}
				} else if toService.Name != obj.Labels["kubernetes.io/service-name"] ||
					toService.Namespace != obj.Namespace {
					continue
				}

				// Update the ArmorProfile object with the endpoints' IPs
				logger.Info("the endpointslice matched by the policy", "policy key", policyKey, "rule", toService,
					"name", obj.Name, "namespace", obj.Namespace, "labels", obj.Labels,
					"event type", obj.EventType, "added ips", obj.AddedIPs, "deleted ips", obj.DeletedIPs, "ports", obj.Ports)
				updated, err := i.updateArmorProfile(policyKey, toService.Mode, obj.AddedIPs, obj.DeletedIPs, obj.Ports)
				if err != nil {
					logger.Error(fmt.Errorf("failed to update ArmorProfile for the endpointslice object. error: %w", err),
						"policy key", policyKey, "name", obj.Name, "namespace", obj.Namespace)
				} else {
					if obj.EventType == "DELETE" {
						i.ipPortCache.Delete(string(obj.UID))
					} else {
						i.ipPortCache.Update(string(obj.UID), ipPort{
							IPs:   obj.IPs,
							Ports: obj.Ports,
						})
					}
					// We assume that there is only one service item in the policy's toServices array that matches the endpoint.
					// So we can just break out of this iteration.
					if updated {
						break
					}
				}
			}
		}
	}

	return nil
}
