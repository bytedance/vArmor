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

// Package networkproxy hosts the Kubernetes-facing orchestration for the
// NetworkProxy enforcer: it translates a VarmorPolicy / VarmorClusterPolicy
// into an Envoy xDS profile via internal/networkproxy/profile, then creates
// and maintains the ConfigMap (and, in a future iteration, Secret) that
// projects bootstrap / LDS / CDS / MITM material into the proxy sidecar and
// target container.
//
// The file that used to live at internal/networkproxy/profile/networkproxy.go
// was moved here because its responsibility is orchestration, not rendering:
// it calls into the translator as a black box and owns the Kubernetes
// object lifecycle. Keeping the translator package free of client-go keeps
// its tests hermetic.
package networkproxy

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
	"github.com/bytedance/vArmor/internal/networkproxy/mitm"
	"github.com/bytedance/vArmor/internal/networkproxy/profile"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
)

// ConfigMap data key names. The xDS keys keep their historic names so the
// sidecar bootstrap references (/etc/envoy/lds.yaml, /etc/envoy/cds.yaml)
// remain stable across the ConfigMap -> Secret migration.
//
// The MITM-prefixed keys are written only when the policy enables MITM.
// They intentionally sit alongside the xDS keys in the same resource so
// that a single kubelet volume sync keeps Envoy's watched_directory
// consistent across LDS/CDS and tls_certificates updates.
const (
	// CMKeyBootstrap is the Envoy bootstrap YAML consumed by the sidecar
	// at startup. The path to this key is referenced by the sidecar
	// command line (-c /etc/envoy/bootstrap.yaml).
	CMKeyBootstrap = "bootstrap.yaml"
	// CMKeyLDS is the Listener Discovery Service document; the Envoy
	// bootstrap points dynamic_resources.lds_config.path_config_source
	// at /etc/envoy/lds.yaml.
	CMKeyLDS = "lds.yaml"
	// CMKeyCDS is the Cluster Discovery Service document, consumed via
	// dynamic_resources.cds_config.path_config_source.
	CMKeyCDS = "cds.yaml"

	// CMKeyMITMCACert holds the per-policy MITM CA certificate (PEM).
	// It is not directly mounted into any container; the controller
	// reads it back on subsequent reconciles to reuse the same CA when
	// re-signing the leaf, so that the CA bundle exposed to application
	// containers does not churn on every update.
	CMKeyMITMCACert = "mitm-ca.crt"
	// CMKeyMITMCAKey holds the MITM CA private key (PEM). Same contract
	// as CMKeyMITMCACert -- used solely to re-sign the leaf on reconcile.
	//
	// KNOWN DEBT (MVP): storing the CA private key in a ConfigMap is a
	// security compromise accepted to accelerate end-to-end verification
	// of the TLS MITM pipeline. A follow-up migration (planned in
	// Phase2.md section 5) will move this material into a Secret with
	// identical key names, at which point only the write-side code path
	// changes.
	CMKeyMITMCAKey = "mitm-ca.key"
	// CMKeyMITMLeafCert holds the leaf certificate (PEM) presented by
	// Envoy's DownstreamTlsContext when impersonating the upstream.
	// Mounted into the sidecar at varmorconfig.MITMLeafCertPath.
	CMKeyMITMLeafCert = "mitm-leaf.crt"
	// CMKeyMITMLeafKey holds the leaf private key (PEM). Also MVP debt
	// as described on CMKeyMITMCAKey.
	CMKeyMITMLeafKey = "mitm-leaf.key"
	// CMKeyMITMCABundle is the Mozilla trust store with the per-policy
	// MITM CA appended. Mounted into:
	//   - the Envoy sidecar at varmorconfig.MITMUpstreamTrustedCAPath
	//     for UpstreamTlsContext validation_context, and
	//   - every target container at varmorconfig.MITMCABundlePath, so
	//     that standard TLS clients pick up the synthetic CA via
	//     SSL_CERT_FILE / REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS /
	//     CURL_CA_BUNDLE.
	CMKeyMITMCABundle = "mitm-ca-bundle.crt"
)

// envoyBootstrapTemplate is the sidecar's static bootstrap YAML. Only the
// admin port is parameterised; the LDS/CDS paths are fixed to the volume
// mount point /etc/envoy so the template does not depend on the volume
// layout emitted by buildNetworkProxyPatch / proxyVolume.
var envoyBootstrapTemplate = `node:
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

	cm, err := GenerateEnvoyConfigMaps(kubeClient, obj, namespace, clusterScope)
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

	cm, err := GenerateEnvoyConfigMaps(kubeClient, obj, namespace, clusterScope)
	if err != nil {
		return fmt.Errorf("generate config map failed: %w", err)
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

// GenerateEnvoyConfigMaps assembles the ConfigMap that projects the Envoy
// bootstrap / LDS / CDS documents, and -- when the policy enables MITM --
// the per-policy CA, leaf certificate, leaf key, and CA bundle into the
// sidecar (/etc/envoy and /etc/envoy/tls) and target container
// (/etc/varmor/ca-bundle).
//
// MITM material lifecycle:
//
//	On the very first reconcile for a policy the CA is generated from
//	scratch. On subsequent reconciles the existing ConfigMap is read back
//	and -- if it carries a valid CA pair -- the CA is reused and only the
//	leaf is re-signed. This keeps the CA bundle projected into the target
//	container stable across updates so that long-lived TLS connections and
//	HTTP client caches do not see the trust store churn unnecessarily.
func GenerateEnvoyConfigMaps(kubeClient *kubernetes.Clientset, obj interface{}, namespace string, clusterScope bool) (cm *v1.ConfigMap, err error) {
	var name string
	var lds, cds string
	var labels map[string]string
	var npc *varmor.NetworkProxyConfig

	ownerReferences := []metav1.OwnerReference{}
	controller := true
	finalizers := []string{}
	proxyAdminPort := varmorconfig.DefaultProxyAdminPort

	if clusterScope {
		vcp := obj.(*varmor.VarmorClusterPolicy)
		npc = vcp.Spec.Policy.NetworkProxyConfig

		// Resolve MITM config (including any SecretRef lookups) BEFORE
		// handing the policy to the translator. For cluster-scoped
		// policies the referenced Secret lives in the workload namespace
		// (this ConfigMap's target namespace), not the policy's own scope.
		mitmInput, err := profile.ResolveMITMInput(kubeClient, namespace, npc)
		if err != nil {
			return nil, fmt.Errorf("resolve MITM config failed: %w", err)
		}

		lds, cds, err = profile.GenerateEnvoyConfig(vcp.Spec.Policy, vcp.Generation, mitmInput)
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

		if npc != nil && npc.ProxyAdminPort != nil {
			proxyAdminPort = *npc.ProxyAdminPort
		}
	} else {
		vp := obj.(*varmor.VarmorPolicy)
		npc = vp.Spec.Policy.NetworkProxyConfig

		// Resolve MITM config (including any SecretRef lookups) BEFORE
		// handing the policy to the translator. For namespace-scoped
		// policies the Secret lives in the policy's own namespace, which
		// is also the ConfigMap's target namespace.
		mitmInput, err := profile.ResolveMITMInput(kubeClient, vp.Namespace, npc)
		if err != nil {
			return nil, fmt.Errorf("resolve MITM config failed: %w", err)
		}

		lds, cds, err = profile.GenerateEnvoyConfig(vp.Spec.Policy, vp.Generation, mitmInput)
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

		if npc != nil && npc.ProxyAdminPort != nil {
			proxyAdminPort = *npc.ProxyAdminPort
		}
	}

	data := map[string]string{
		CMKeyBootstrap: fmt.Sprintf(envoyBootstrapTemplate, proxyAdminPort),
		CMKeyLDS:       lds,
		CMKeyCDS:       cds,
	}

	// MITM material: inspect the policy directly (rather than the
	// translator MITMInput) so this branch is independent of whether
	// the translator actually emitted any MITM filter chains. A policy
	// may declare MITM.Domains but all egress rules might land in the
	// non-MITM path; we still need the Envoy sidecar and target
	// containers to see the same trust store so TLS probes do not break
	// during e.g. a rolling policy rollout.
	if npc != nil && npc.MITM != nil && len(npc.MITM.Domains) > 0 {
		material, err := buildOrReuseMITMMaterial(kubeClient, namespace, name, npc.MITM.Domains)
		if err != nil {
			return nil, fmt.Errorf("prepare MITM material: %w", err)
		}
		data[CMKeyMITMCACert] = string(material.CA.CertPEM)
		data[CMKeyMITMCAKey] = string(material.CA.KeyPEM)
		data[CMKeyMITMLeafCert] = string(material.Leaf.CertPEM)
		data[CMKeyMITMLeafKey] = string(material.Leaf.KeyPEM)
		data[CMKeyMITMCABundle] = string(material.Bundle)
	}

	cm = &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			Labels:          labels,
			OwnerReferences: ownerReferences,
			Finalizers:      finalizers,
		},
		Data: data,
	}

	return cm, nil
}

// buildOrReuseMITMMaterial returns the MITM CA / leaf / bundle tuple that
// should be projected into the policy's ConfigMap. When a ConfigMap with
// a valid CA already exists in the target namespace, the CA is reused and
// only the leaf is re-signed for the current domain set; otherwise a
// fresh CA is generated.
//
// The reuse path is critical: regenerating the CA on every reconcile
// would churn the CA bundle mounted into every target container, which
// is the user-visible trust store. By pinning the CA across reconciles
// we limit churn to the leaf material, which is only read by the Envoy
// sidecar and can be hot-reloaded via Envoy's watched_directory.
func buildOrReuseMITMMaterial(kubeClient *kubernetes.Clientset, namespace, cmName string, domains []string) (*mitm.MITMMaterial, error) {
	// Attempt to reuse an existing CA embedded in the policy's
	// ConfigMap. Any error other than "already carries a valid CA" is
	// treated as "no reusable CA" and we fall through to generating a
	// fresh one, so that malformed / partial ConfigMap state
	// self-heals on the next reconcile.
	if kubeClient != nil {
		existing, err := kubeClient.CoreV1().ConfigMaps(namespace).Get(context.Background(), cmName, metav1.GetOptions{})
		if err == nil && existing != nil {
			certPEM := []byte(existing.Data[CMKeyMITMCACert])
			keyPEM := []byte(existing.Data[CMKeyMITMCAKey])
			if len(certPEM) > 0 && len(keyPEM) > 0 {
				ca, parseErr := mitm.ParseCA(certPEM, keyPEM)
				if parseErr == nil {
					leaf, err := mitm.RenewLeaf(ca, domains)
					if err != nil {
						return nil, fmt.Errorf("renew leaf: %w", err)
					}
					bundle, err := mitm.BuildCABundle(ca.CertPEM)
					if err != nil {
						return nil, fmt.Errorf("rebuild CA bundle: %w", err)
					}
					return &mitm.MITMMaterial{CA: ca, Leaf: leaf, Bundle: bundle}, nil
				}
			}
		}
	}

	// No reusable CA found. Generate a fresh one. The caller is
	// responsible for ensuring this happens only on first reconcile
	// (or on self-healing), since fresh CAs force every target
	// container in the policy to pick up a new CA bundle.
	return mitm.GenerateMITMMaterial(domains)
}
