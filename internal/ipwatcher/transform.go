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
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Transform(obj interface{}) (interface{}, error) {
	switch v := obj.(type) {
	case *corev1.Pod:
		return transformPodFunc(v)
	case *corev1.Service:
		return transformServiceFunc(v)
	case *discoveryv1.EndpointSlice:
		return transformEndpointSliceFunc(v)
	default:
		return obj, nil
	}
}

func transformPodFunc(obj interface{}) (interface{}, error) {
	if pod, ok := obj.(*corev1.Pod); ok {
		return &corev1.Pod{
			TypeMeta: pod.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            pod.Name,
				Namespace:       pod.Namespace,
				Labels:          pod.Labels,
				ResourceVersion: pod.ResourceVersion,
				UID:             pod.UID,
			},
			Status: corev1.PodStatus{
				PodIPs: pod.Status.PodIPs,
			},
		}, nil
	}
	return obj, nil
}

func transformServiceFunc(obj interface{}) (interface{}, error) {
	if svc, ok := obj.(*corev1.Service); ok {
		return &corev1.Service{
			TypeMeta: svc.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            svc.Name,
				Namespace:       svc.Namespace,
				Labels:          svc.Labels,
				ResourceVersion: svc.ResourceVersion,
				UID:             svc.UID,
			},
			Spec: corev1.ServiceSpec{
				ClusterIPs: svc.Spec.ClusterIPs,
			},
		}, nil
	}
	return obj, nil
}

func transformEndpointSliceFunc(obj interface{}) (interface{}, error) {
	if eps, ok := obj.(*discoveryv1.EndpointSlice); ok {
		return &discoveryv1.EndpointSlice{
			TypeMeta: eps.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            eps.Name,
				Namespace:       eps.Namespace,
				Labels:          eps.Labels,
				ResourceVersion: eps.ResourceVersion,
				UID:             eps.UID,
			},
			Endpoints: eps.Endpoints,
			Ports:     eps.Ports,
		}, nil
	}
	return obj, nil
}
