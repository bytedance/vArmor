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
// and maintains the Secret that projects bootstrap / LDS / CDS / MITM material
// into the proxy sidecar and target container.
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

// Secret data key names. The xDS keys keep their historic names so the
// sidecar bootstrap references (/etc/envoy/lds.yaml, /etc/envoy/cds.yaml)
// remain stable.
//
// The MITM-prefixed keys are written only when the policy enables MITM.
// They intentionally sit alongside the xDS keys in the same resource so
// that a single kubelet volume sync keeps Envoy's watched_directory
// consistent across LDS/CDS and tls_certificates updates.
const (
	// SecretKeyBootstrap is the Envoy bootstrap YAML consumed by the sidecar
	// at startup. The path to this key is referenced by the sidecar
	// command line (-c /etc/envoy/bootstrap.yaml).
	SecretKeyBootstrap = "bootstrap.yaml"
	// SecretKeyLDS is the Listener Discovery Service document; the Envoy
	// bootstrap points dynamic_resources.lds_config.path_config_source
	// at /etc/envoy/lds.yaml.
	SecretKeyLDS = "lds.yaml"
	// SecretKeyCDS is the Cluster Discovery Service document, consumed via
	// dynamic_resources.cds_config.path_config_source.
	SecretKeyCDS = "cds.yaml"

	// SecretKeyMITMCACert holds the per-policy MITM CA certificate (PEM).
	// It is not directly mounted into any container; the controller
	// reads it back on subsequent reconciles to reuse the same CA when
	// re-signing the leaf, so that the CA bundle exposed to application
	// containers does not churn on every update.
	SecretKeyMITMCACert = "mitm-ca.crt"
	// SecretKeyMITMCAKey holds the MITM CA private key (PEM). Same contract
	// as SecretKeyMITMCACert — used solely to re-sign the leaf on reconcile.
	SecretKeyMITMCAKey = "mitm-ca.key"
	// SecretKeyMITMLeafCert holds the leaf certificate (PEM) presented by
	// Envoy's DownstreamTlsContext when impersonating the upstream.
	// Mounted into the sidecar at varmorconfig.MITMLeafCertPath.
	SecretKeyMITMLeafCert = "mitm-leaf.crt"
	// SecretKeyMITMLeafKey holds the leaf private key (PEM).
	SecretKeyMITMLeafKey = "mitm-leaf.key"
	// SecretKeyMITMCABundle is the Mozilla trust store with the per-policy
	// MITM CA appended. Mounted into:
	//   - the Envoy sidecar at varmorconfig.MITMUpstreamTrustedCAPath
	//     for UpstreamTlsContext validation_context, and
	//   - every target container at varmorconfig.MITMCABundlePath, so
	//     that standard TLS clients pick up the synthetic CA via
	//     SSL_CERT_FILE / REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS /
	//     CURL_CA_BUNDLE.
	SecretKeyMITMCABundle = "mitm-ca-bundle.crt"
)

// Secret size thresholds. Kubernetes imposes a hard 1 MiB (1,048,576 bytes)
// limit on Secret data. With the Mozilla CA bundle (~226 KB) already
// consuming a large portion, a policy with many rules could approach the
// limit. We define two thresholds:
//   - WarnThreshold: emit a warning log so operators notice before failure.
//   - MaxThreshold: reject the Secret before attempting the API call; the
//     100 KB headroom above 900 KB accounts for Kubernetes-internal JSON
//     encoding overhead and etcd value-size margin.
const (
	SecretSizeWarnThreshold = 700 * 1024 // 700 KB
	SecretSizeMaxThreshold  = 900 * 1024 // 900 KB
)

// computeSecretDataSize returns the total byte count of all values stored
// in the Secret (both StringData and Data). This approximates the
// wire-format size that counts toward the 1 MiB Kubernetes limit.
func computeSecretDataSize(secret *v1.Secret) int {
	total := 0
	for _, v := range secret.StringData {
		total += len(v)
	}
	for _, v := range secret.Data {
		total += len(v)
	}
	return total
}

// checkSecretSize computes the total data size of the Secret and returns
// an error if it exceeds MaxThreshold. A warning is logged (but not
// rejected) when it exceeds WarnThreshold.
func checkSecretSize(secret *v1.Secret, logger logr.Logger) error {
	size := computeSecretDataSize(secret)
	if size > SecretSizeMaxThreshold {
		return fmt.Errorf(
			"secret %s/%s data size (%d bytes) exceeds the maximum allowed threshold (%d bytes); "+
				"reduce the number of egress rules, MITM domains, or header mutations",
			secret.Namespace, secret.Name, size, SecretSizeMaxThreshold)
	}
	if size > SecretSizeWarnThreshold {
		logger.Info("WARNING: proxy secret size is approaching the Kubernetes 1 MiB limit",
			"namespace", secret.Namespace,
			"name", secret.Name,
			"size_bytes", size,
			"warn_threshold", SecretSizeWarnThreshold,
			"max_threshold", SecretSizeMaxThreshold)
	}
	return nil
}

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

func DeleteNetworkProxySecret(kubeClient *kubernetes.Clientset, namespace string, name string) error {
	err := kubeClient.CoreV1().Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

func RemoveNetworkProxySecretFinalizers(kubeClient *kubernetes.Clientset, namespace string, name string) error {
	removeFinalizers := func() error {
		cm, err := kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			if k8errors.IsNotFound(err) {
				return nil
			}
			return err
		}
		cm.Finalizers = []string{}
		_, err = kubeClient.CoreV1().Secrets(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, removeFinalizers)
}

func CreateNetworkProxySecret(
	kubeClient *kubernetes.Clientset,
	obj interface{},
	namespace string,
	clusterScope bool,
	logger logr.Logger) (err error) {

	secret, err := GenerateEnvoySecret(kubeClient, obj, namespace, clusterScope)
	if err != nil {
		return fmt.Errorf("generate secret failed: %w", err)
	}

	if secret == nil {
		return nil
	}

	// Size guard: reject before hitting the Kubernetes 1 MiB hard limit.
	if err := checkSecretSize(secret, logger); err != nil {
		return err
	}

	_, err = kubeClient.CoreV1().Secrets(secret.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		if k8errors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create secret failed: %w, namespace: %s, name: %s", err, secret.Namespace, secret.Name)
	}

	return nil
}

func UpdateNetworkProxySecret(
	kubeClient *kubernetes.Clientset,
	obj interface{},
	namespace string,
	clusterScope bool,
	logger logr.Logger) (err error) {

	secret, err := GenerateEnvoySecret(kubeClient, obj, namespace, clusterScope)
	if err != nil {
		return fmt.Errorf("generate secret failed: %w", err)
	}

	if secret == nil {
		return nil
	}

	// Size guard: reject before hitting the Kubernetes 1 MiB hard limit.
	if err := checkSecretSize(secret, logger); err != nil {
		return err
	}

	// Update the secret
	envoySecret, err := kubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			_, err = kubeClient.CoreV1().Secrets(secret.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("create secret failed: %w, namespace: %s, name: %s", err, secret.Namespace, secret.Name)
			}
			return nil
		}
		return fmt.Errorf("get secret failed: %w, namespace: %s, name: %s", err, secret.Namespace, secret.Name)
	}

	regain := false
	updateEnvoySecret := func() error {
		if regain {
			envoySecret, err = kubeClient.CoreV1().Secrets(envoySecret.Namespace).Get(context.Background(), envoySecret.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			regain = false
		}
		envoySecret.StringData = secret.StringData
		_, err = kubeClient.CoreV1().Secrets(envoySecret.Namespace).Update(context.Background(), envoySecret, metav1.UpdateOptions{})
		if err == nil {
			logger.Info("the secret has been updated", "namespace", envoySecret.Namespace, "name", envoySecret.Name)
		} else {
			regain = true
		}
		return err
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, updateEnvoySecret)
	if err != nil {
		logger.Error(err, "failed to update the secret", "namespace", envoySecret.Namespace, "name", envoySecret.Name)
		return err
	}

	return nil
}

// GenerateEnvoySecret assembles the Secret that projects the Envoy
// bootstrap / LDS / CDS documents, and -- when the policy enables MITM --
// the per-policy CA, leaf certificate, leaf key, and CA bundle into the
// sidecar (/etc/envoy and /etc/envoy/tls) and target container
// (/etc/varmor/ca-bundle).
//
// MITM material lifecycle:
//
//	On the very first reconcile for a policy the CA is generated from
//	scratch. On subsequent reconciles the existing Secret is read back
//	and -- if it carries a valid CA pair -- the CA is reused and only the
//	leaf is re-signed. This keeps the CA bundle projected into the target
//	container stable across updates so that long-lived TLS connections and
//	HTTP client caches do not see the trust store churn unnecessarily.
func GenerateEnvoySecret(kubeClient *kubernetes.Clientset, obj interface{}, namespace string, clusterScope bool) (secret *v1.Secret, err error) {
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
		// (this Secret's target namespace), not the policy's own scope.
		mitmInput, err := profile.ResolveMITMInput(kubeClient, namespace, npc)
		if err != nil {
			return nil, fmt.Errorf("resolve MITM config failed: %w", err)
		}

		ipStack := profile.DetectIPStack()
		lds, cds, err = profile.GenerateEnvoyConfig(vcp.Spec.Policy, vcp.Generation, mitmInput, ipStack)
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
		// is also the Secret's target namespace.
		mitmInput, err := profile.ResolveMITMInput(kubeClient, vp.Namespace, npc)
		if err != nil {
			return nil, fmt.Errorf("resolve MITM config failed: %w", err)
		}

		ipStack := profile.DetectIPStack()
		lds, cds, err = profile.GenerateEnvoyConfig(vp.Spec.Policy, vp.Generation, mitmInput, ipStack)
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
		// Note that we only add finalizer to the secret for namespace scoped policy.
		// Otherwise, the secret for cluster scoped policy will block the deletion of the namespace
		finalizers = []string{"varmor.org/ap-protection"}

		if npc != nil && npc.ProxyAdminPort != nil {
			proxyAdminPort = *npc.ProxyAdminPort
		}
	}

	data := map[string]string{
		SecretKeyBootstrap: fmt.Sprintf(envoyBootstrapTemplate, proxyAdminPort),
		SecretKeyLDS:       lds,
		SecretKeyCDS:       cds,
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
		data[SecretKeyMITMCACert] = string(material.CA.CertPEM)
		data[SecretKeyMITMCAKey] = string(material.CA.KeyPEM)
		data[SecretKeyMITMLeafCert] = string(material.Leaf.CertPEM)
		data[SecretKeyMITMLeafKey] = string(material.Leaf.KeyPEM)
		data[SecretKeyMITMCABundle] = string(material.Bundle)
	}

	secret = &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			Labels:          labels,
			OwnerReferences: ownerReferences,
			Finalizers:      finalizers,
		},
		Type:       v1.SecretTypeOpaque,
		StringData: data,
	}

	return secret, nil
}

// buildOrReuseMITMMaterial returns the MITM CA / leaf / bundle tuple that
// should be projected into the policy's Secret. When a Secret with
// a valid CA already exists in the target namespace, the CA is reused and
// only the leaf is re-signed for the current domain set; otherwise a
// fresh CA is generated.
//
// The reuse path is critical: regenerating the CA on every reconcile
// would churn the CA bundle mounted into every target container, which
// is the user-visible trust store. By pinning the CA across reconciles
// we limit churn to the leaf material, which is only read by the Envoy
// sidecar and can be hot-reloaded via Envoy's watched_directory.
func buildOrReuseMITMMaterial(kubeClient *kubernetes.Clientset, namespace, secretName string, domains []string) (*mitm.MITMMaterial, error) {
	// Attempt to reuse an existing CA embedded in the policy's
	// Secret. Any error other than "already carries a valid CA" is
	// treated as "no reusable CA" and we fall through to generating a
	// fresh one, so that malformed / partial Secret state
	// self-heals on the next reconcile.
	if kubeClient != nil {
		existing, err := kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
		if err == nil && existing != nil {
			certPEM := existing.Data[SecretKeyMITMCACert]
			keyPEM := existing.Data[SecretKeyMITMCAKey]
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
