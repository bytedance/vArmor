// Copyright 2026 vArmor Authors
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

// Package profile generates the Envoy xDS resources from the network proxy rules.
package profile

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortypes "github.com/bytedance/vArmor/internal/types"
)

var (
	envoyBootstrapTemplate = `node:
  id: varmor-network-proxy
  cluster: varmor-network-proxy
admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: %d
dynamic_resources:
  lds_config:
    path_config_source:
      path: /etc/envoy/lds.yaml
      watched_directory:
        path: /etc/envoy
  cds_config:
    path_config_source:
      path: /etc/envoy/cds.yaml
      watched_directory:
        path: /etc/envoy`
)

func DeleteNetworkProxyConfigMap(kubeClient *kubernetes.Clientset, namespace string, name string) error {
	err := kubeClient.CoreV1().ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

func RemoveNetworkProxyConfigMapFinalizers(kubeClient *kubernetes.Clientset, namespace string, name string) error {
	removeFinalizers := func() error {
		cm, err := kubeClient.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			if k8errors.IsNotFound(err) {
				return nil
			}
			return err
		}
		cm.Finalizers = []string{}
		_, err = kubeClient.CoreV1().ConfigMaps(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, removeFinalizers)
}

func CreateNetworkProxyConfigMap(
	kubeClient *kubernetes.Clientset,
	obj interface{},
	namespace string,
	clusterScope bool,
	logger logr.Logger) (err error) {

	cm, err := GenerateEnvoyConfigMaps(obj, namespace, clusterScope)
	if err != nil {
		return fmt.Errorf("generate config map failed: %w, namespace: %s, name: %s", err, cm.Namespace, cm.Name)
	}

	if cm == nil {
		return nil
	}

	_, err = kubeClient.CoreV1().ConfigMaps(cm.Namespace).Create(context.Background(), cm, metav1.CreateOptions{})
	if err != nil {
		if k8errors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create config map failed: %w, namespace: %s, name: %s", err, cm.Namespace, cm.Name)
	}

	return nil
}

func UpdateNetworkProxyConfigMap(
	kubeClient *kubernetes.Clientset,
	obj interface{},
	namespace string,
	clusterScope bool,
	logger logr.Logger) (err error) {

	cm, err := GenerateEnvoyConfigMaps(obj, namespace, clusterScope)
	if err != nil {
		return fmt.Errorf("generate config map failed: %w, namespace: %s, name: %s", err, cm.Namespace, cm.Name)
	}

	if cm == nil {
		return nil
	}

	// Update the config map
	envoyCm, err := kubeClient.CoreV1().ConfigMaps(cm.Namespace).Get(context.Background(), cm.Name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			_, err = kubeClient.CoreV1().ConfigMaps(cm.Namespace).Create(context.Background(), cm, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("create config map failed: %w, namespace: %s, name: %s", err, cm.Namespace, cm.Name)
			}
			return nil
		}
		return fmt.Errorf("get config map failed: %w, namespace: %s, name: %s", err, cm.Namespace, cm.Name)
	}

	regain := false
	updateEnvoyCm := func() error {
		if regain {
			envoyCm, err = kubeClient.CoreV1().ConfigMaps(envoyCm.Namespace).Get(context.Background(), envoyCm.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			regain = false
		}
		envoyCm.Data = cm.Data
		_, err = kubeClient.CoreV1().ConfigMaps(envoyCm.Namespace).Update(context.Background(), envoyCm, metav1.UpdateOptions{})
		if err == nil {
			logger.Info("the config map has been updated", "namespace", envoyCm.Namespace, "name", envoyCm.Name)
		} else {
			regain = true
		}
		return err
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, updateEnvoyCm)
	if err != nil {
		logger.Error(err, "failed to update the config map", "namespace", envoyCm.Namespace, "name", envoyCm.Name)
		return err
	}

	return nil
}

func GenerateEnvoyConfigMaps(obj interface{}, namespace string, clusterScope bool) (cm *v1.ConfigMap, err error) {
	var name string
	var lds, cds string
	var labels map[string]string

	ownerReferences := []metav1.OwnerReference{}
	controller := true
	finalizers := []string{}
	proxyAdminPort := varmorconfig.DefaultProxyAdminPort

	if clusterScope {
		vcp := obj.(*varmor.VarmorClusterPolicy)

		lds, cds, err = GenerateEnvoyConfig(vcp.Spec.Policy, vcp.Generation)
		if err != nil {
			return nil, fmt.Errorf("generate envoy config failed: %w", err)
		}

		if lds == "" || cds == "" {
			return nil, nil
		}

		name = varmorprofile.GenerateArmorProfileName(varmorconfig.Namespace, vcp.Name, clusterScope)
		ownerReferences = append(ownerReferences, metav1.OwnerReference{
			APIVersion: "crd.varmor.org/v1beta1",
			Kind:       "VarmorClusterPolicy",
			Name:       vcp.Name,
			UID:        vcp.UID,
			Controller: &controller,
		})
		labels = vcp.ObjectMeta.DeepCopy().Labels

		if vcp.Spec.Policy.NetworkProxyConfig != nil && vcp.Spec.Policy.NetworkProxyConfig.ProxyAdminPort != nil {
			proxyAdminPort = *vcp.Spec.Policy.NetworkProxyConfig.ProxyAdminPort
		}
	} else {
		vp := obj.(*varmor.VarmorPolicy)

		lds, cds, err = GenerateEnvoyConfig(vp.Spec.Policy, vp.Generation)
		if err != nil {
			return nil, fmt.Errorf("generate envoy config failed: %w", err)
		}

		if lds == "" || cds == "" {
			return nil, nil
		}

		name = varmorprofile.GenerateArmorProfileName(vp.Namespace, vp.Name, clusterScope)
		ownerReferences = append(ownerReferences, metav1.OwnerReference{
			APIVersion: "crd.varmor.org/v1beta1",
			Kind:       "VarmorPolicy",
			Name:       vp.Name,
			UID:        vp.UID,
			Controller: &controller,
		})
		labels = vp.ObjectMeta.DeepCopy().Labels
		// Note that we only add finalizer to the config map for namespace scoped policy.
		// Otherwise, the config map for cluster scoped policy will block the deletion of the namespace
		finalizers = []string{"varmor.org/ap-protection"}

		if vp.Spec.Policy.NetworkProxyConfig != nil && vp.Spec.Policy.NetworkProxyConfig.ProxyAdminPort != nil {
			proxyAdminPort = *vp.Spec.Policy.NetworkProxyConfig.ProxyAdminPort
		}
	}

	cm = &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			Labels:          labels,
			OwnerReferences: ownerReferences,
			Finalizers:      finalizers,
		},
		Data: map[string]string{
			"bootstrap.yaml": fmt.Sprintf(envoyBootstrapTemplate, proxyAdminPort),
			"lds.yaml":       lds,
			"cds.yaml":       cds,
		},
	}

	return cm, nil
}

func GenerateEnvoyConfig(policy varmor.Policy, version int64) (lds string, cds string, err error) {
	e := varmortypes.GetEnforcerType(policy.Enforcer)

	if e == varmortypes.Unknown {
		return "", "", fmt.Errorf("unknown enforcer")
	}

	// No need to generate envoy config if the NetworkProxy enforcer is not declared
	if (e & varmortypes.NetworkProxy) == 0 {
		return "", "", nil
	}

	// Get the proxy port from the policy. Default is 15001.
	proxyPort := varmorconfig.DefaultProxyPort
	if policy.NetworkProxyConfig != nil && policy.NetworkProxyConfig.ProxyPort != nil {
		proxyPort = *policy.NetworkProxyConfig.ProxyPort
	}

	switch policy.Mode {
	case varmor.AlwaysAllowMode:
		return GenerateAllowAllEgressRules(version, proxyPort)
	case varmor.RuntimeDefaultMode:
		return GenerateAllowAllEgressRules(version, proxyPort)
	case varmor.EnhanceProtectMode:
		if policy.EnhanceProtect == nil {
			return "", "", fmt.Errorf("the policy.enhanceProtect field cannot be nil")
		}

		if policy.EnhanceProtect.NetworkProxyRawRules != nil && policy.EnhanceProtect.NetworkProxyRawRules.Egress != nil {
			return GenerateNetworkProxyEgressRules(policy.EnhanceProtect.NetworkProxyRawRules.Egress, version, proxyPort)
		} else {
			return GenerateAllowAllEgressRules(version, proxyPort)
		}

	case varmor.BehaviorModelingMode:
		return "", "", fmt.Errorf("not supported by the NetworkProxy enforcer for now")
	case varmor.DefenseInDepthMode:
		if policy.DefenseInDepth == nil {
			return "", "", fmt.Errorf("the policy.defenseInDepth field cannot be nil")
		}

		if policy.DefenseInDepth.NetworkProxy != nil && policy.DefenseInDepth.NetworkProxy.Egress != nil {
			return GenerateNetworkProxyEgressRules(policy.DefenseInDepth.NetworkProxy.Egress, version, proxyPort)
		} else {
			return GenerateDenyAllEgressRules(version, proxyPort)
		}
	}

	return "", "", nil
}

func GenerateAllowAllEgressRules(version int64, proxyPort uint16) (string, string, error) {
	return renderAllowAllListenerYAML(version, proxyPort), renderClustersYAML(version), nil
}

func GenerateDenyAllEgressRules(version int64, proxyPort uint16) (string, string, error) {
	return renderDenyAllListenerYAML(version, proxyPort), renderClustersYAML(version), nil
}

func GenerateNetworkProxyEgressRules(egress *varmor.NetworkProxyEgress, version int64, proxyPort uint16) (string, string, error) {
	result, err := TranslateEgressRules(egress, version, proxyPort)
	if err != nil {
		return "", "", err
	}
	return result.LDS, result.CDS, nil
}
