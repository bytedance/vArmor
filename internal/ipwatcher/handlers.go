package ipwatcher

import (
	"reflect"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func (i *IPWatcher) updatePod(oldObj, newObj interface{}) {
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
			EventType:  "UPDATE",
			IPs:        IPs,
			AddedIPs:   IPs,
		})
	}
}

func (i *IPWatcher) deletePod(obj interface{}) {
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
			EventType:  "DELETE",
			IPs:        IPs,
			DeletedIPs: IPs,
		})
	}
}

func (i *IPWatcher) addService(obj interface{}) {
	logger := i.log.WithName("AddFunc()")
	svc := obj.(*corev1.Service)

	if len(svc.Spec.ClusterIPs) != 0 {
		logger.V(2).Info("service added", "service", svc)

		i.queue.Add(&SlimObject{
			TypeMeta: metav1.TypeMeta{
				Kind: "Service",
			},
			ObjectMeta: svc.ObjectMeta,
			EventType:  "ADD",
			IPs:        svc.Spec.ClusterIPs,
			AddedIPs:   svc.Spec.ClusterIPs,
		})
	}
}

func (i *IPWatcher) updateService(oldObj, newObj interface{}) {
	logger := i.log.WithName("UpdateFunc()")
	svc := newObj.(*corev1.Service)
	oldSvc := oldObj.(*corev1.Service)

	addedIPs := svc.Spec.ClusterIPs

	var deletedIPs []string
	lastIPPort, ok := i.ipPortCache.Get(string(svc.UID))
	if !ok {
		lastIPPort.IPs = oldSvc.Spec.ClusterIPs
	}
	for _, lastIP := range lastIPPort.IPs {
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
		!reflect.DeepEqual(addedIPs, lastIPPort.IPs) ||
		!reflect.DeepEqual(svc.Labels, oldSvc.Labels) {
		logger.V(2).Info("service updated", "new", svc, "old", oldSvc)

		i.queue.Add(&SlimObject{
			TypeMeta: metav1.TypeMeta{
				Kind: "Service",
			},
			ObjectMeta: svc.ObjectMeta,
			EventType:  "UPDATE",
			IPs:        addedIPs,
			AddedIPs:   addedIPs,
			DeletedIPs: deletedIPs,
		})
	}
}

func (i *IPWatcher) deleteService(obj interface{}) {
	logger := i.log.WithName("DeleteFunc()")
	svc := obj.(*corev1.Service)

	if len(svc.Spec.ClusterIPs) != 0 {
		logger.V(2).Info("service deleted", "service", svc)

		var deletedIPs []string
		lastIPPort, ok := i.ipPortCache.Get(string(svc.UID))
		if ok {
			deletedIPs = lastIPPort.IPs
		} else {
			deletedIPs = svc.Spec.ClusterIPs
		}

		i.queue.Add(&SlimObject{
			TypeMeta: metav1.TypeMeta{
				Kind: "Service",
			},
			ObjectMeta: svc.ObjectMeta,
			EventType:  "DELETE",
			IPs:        deletedIPs,
			DeletedIPs: deletedIPs,
		})
	}
}

func (i *IPWatcher) addEndpointSlice(obj interface{}) {
	logger := i.log.WithName("AddFunc()")
	eps := obj.(*discoveryv1.EndpointSlice)

	if _, ok := eps.Labels["kubernetes.io/service-name"]; ok && len(eps.Endpoints) != 0 {
		logger.V(2).Info("endpointslice added", "endpointslice", eps)

		var addedIPs []string
		for _, ep := range eps.Endpoints {
			addedIPs = append(addedIPs, ep.Addresses...)
		}

		var ports []varmor.Port
		for _, port := range eps.Ports {
			if port.Port != nil {
				ports = append(ports, varmor.Port{
					Port: uint16(*port.Port),
				})
			}
		}

		i.queue.Add(&SlimObject{
			TypeMeta: metav1.TypeMeta{
				Kind: "EndpointSlice",
			},
			ObjectMeta: eps.ObjectMeta,
			EventType:  "ADD",
			IPs:        addedIPs,
			AddedIPs:   addedIPs,
			Ports:      ports,
		})
	}
}

func (i *IPWatcher) updateEndpointSlice(oldObj, newObj interface{}) {
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

	var ports []varmor.Port
	for _, port := range eps.Ports {
		if port.Port != nil {
			ports = append(ports, varmor.Port{
				Port: uint16(*port.Port),
			})
		}
	}

	var deletedIPs []string
	lastIPPort, ok := i.ipPortCache.Get(string(eps.UID))
	if !ok {
		for _, ep := range oldEps.Endpoints {
			lastIPPort.IPs = append(lastIPPort.IPs, ep.Addresses...)
		}
		for _, port := range oldEps.Ports {
			if port.Port != nil {
				lastIPPort.Ports = append(lastIPPort.Ports, varmor.Port{
					Port: uint16(*port.Port),
				})
			}
		}
	}
	isPortsNotChanged := reflect.DeepEqual(lastIPPort.Ports, ports)
	for _, lastIP := range lastIPPort.IPs {
		found := false
		for _, ip := range addedIPs {
			if lastIP == ip {
				if isPortsNotChanged {
					found = true
				}
				break
			}
		}
		if !found {
			deletedIPs = append(deletedIPs, lastIP)
		}
	}

	if len(deletedIPs) != 0 ||
		!reflect.DeepEqual(addedIPs, lastIPPort.IPs) ||
		!reflect.DeepEqual(eps.Labels, oldEps.Labels) {
		logger.V(2).Info("endpointslice updated", "new", eps, "old", oldEps, "lastIPPort", lastIPPort)

		i.queue.Add(&SlimObject{
			TypeMeta: metav1.TypeMeta{
				Kind: "EndpointSlice",
			},
			ObjectMeta: eps.ObjectMeta,
			EventType:  "UPDATE",
			IPs:        addedIPs,
			AddedIPs:   addedIPs,
			DeletedIPs: deletedIPs,
			Ports:      ports,
		})
	}
}

func (i *IPWatcher) deleteEndpointSlice(obj interface{}) {
	logger := i.log.WithName("DeleteFunc()")
	eps := obj.(*discoveryv1.EndpointSlice)

	if _, ok := eps.Labels["kubernetes.io/service-name"]; ok && len(eps.Endpoints) != 0 {
		logger.V(2).Info("endpointslice deleted", "endpointslice", eps)

		var deletedIPs []string
		lastIPPort, ok := i.ipPortCache.Get(string(eps.UID))
		if ok {
			deletedIPs = lastIPPort.IPs
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
			EventType:  "DELETE",
			IPs:        deletedIPs,
			DeletedIPs: deletedIPs,
		})
	}
}
