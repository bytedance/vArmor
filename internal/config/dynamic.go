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

package config

import (
	"sync"

	"github.com/go-logr/logr"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	// DynamicConfigMapName is the name of the ConfigMap that carries vArmor's
	// dynamic, hot-reloadable configuration. It lives in the vArmor namespace
	// and is watched by the manager via an informer, so edits take effect
	// without restarting the manager.
	DynamicConfigMapName = "varmor-config"

	// DynamicConfigMapKey is the single data key inside DynamicConfigMapName
	// that holds the whole configuration document as embedded YAML. This
	// follows the Kubernetes ComponentConfig convention (kube-scheduler,
	// kubelet, kube-proxy) of embedding a typed, versionable config document
	// under one key rather than spreading it across flat scalar keys, because
	// vArmor's dynamic config contains lists of structs (e.g. per-vendor
	// micro-VM detection rules) that do not flatten cleanly.
	DynamicConfigMapKey = "config.yaml"
)

// DynamicConfig is the root of vArmor's hot-reloadable configuration document
// embedded under DynamicConfigMapKey. New dynamic settings should be added as
// additional top-level fields here so the single ConfigMap can grow into
// vArmor's central dynamic-config surface.
type DynamicConfig struct {
	// MicroVMDetection decides, at admission time, whether a workload's Pods run
	// under a micro-VM runtime (kata / serverless sandbox). It is consulted only
	// to pick the NetworkProxy ALS audit volume topology (hostPath for runc vs.
	// no hostPath for micro-VM); it does not affect any runtime behaviour.
	MicroVMDetection MicroVMDetection `yaml:"microVMDetection"`
}

// MicroVMDetection is a set of signals; a Pod matching ANY of them is treated
// as running under a micro-VM runtime. A generic runtimeClassName list plus per-vendor annotation
// and label lists are supported because different providers surface the
// micro-VM decision differently: upstream kata uses RuntimeClass, some
// serverless providers such as Volcengine VKE use a Pod annotation, and others
// such as Alibaba Cloud ECI use a Pod label (alibabacloud.com/eci: "true") to
// opt Pods into the elastic container instance (micro-VM) runtime.
type MicroVMDetection struct {
	// RuntimeClassNames matches Pod.Spec.RuntimeClassName exactly. Typical
	// values are the upstream kata RuntimeClasses (kata, kata-qemu, kata-clh).
	RuntimeClassNames []string `yaml:"runtimeClassNames"`

	// Annotations matches Pod template annotations. A Pod is micro-VM if it
	// carries any listed annotation key (with a matching value when Value is set).
	Annotations []AnnotationRule `yaml:"annotations"`

	// Labels matches Pod template labels. A Pod is micro-VM if it carries any
	// listed label key (with a matching value when Value is set). Some providers such as
	// Alibaba Cloud ECI schedule Pods to the micro-VM runtime via a Pod label
	// (alibabacloud.com/eci: "true") rather than a RuntimeClass or annotation.
	Labels []LabelRule `yaml:"labels"`
}

// AnnotationRule matches a single Pod annotation. An empty Value means "match
// when the Key is present regardless of its value"; a non-empty Value requires
// an exact value match.
type AnnotationRule struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// LabelRule matches a single Pod label. An empty Value means "match when the
// Key is present regardless of its value"; a non-empty Value requires an exact
// value match.
type LabelRule struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// defaultDynamicConfig is the built-in fallback used before the ConfigMap is
// loaded, when the ConfigMap is absent, or when its content fails to parse. It
// mirrors the rules shipped in the default ConfigMap so behaviour is identical
// whether or not the ConfigMap exists.
func defaultDynamicConfig() DynamicConfig {
	return DynamicConfig{
		MicroVMDetection: MicroVMDetection{
			RuntimeClassNames: []string{"kata", "kata-qemu", "kata-clh"},
			Annotations: []AnnotationRule{
				// Volcengine VKE burst-to-VCI (serverless micro-VM).
				{Key: "vke.volcengine.com/burst-to-vci", Value: "enforce"},
			},
			Labels: []LabelRule{
				// Volcengine VKE burst-to-VCI (serverless micro-VM).
				{Key: "vke.volcengine.com/burst-to-vci", Value: "enforce"},
				// Alibaba Cloud ECI: opt a Pod into the elastic container
				// instance (micro-VM) runtime via a Pod label.
				{Key: "alibabacloud.com/eci", Value: "true"},
			},
		},
	}
}

// dynamicConfigStore holds the current dynamic configuration snapshot behind an
// RWMutex. Reads (IsMicroVMPod) take the read lock and are lock-free of each
// other; the informer's event handlers swap the whole snapshot under the write
// lock, so readers always observe a consistent config.
type dynamicConfigStore struct {
	mu  sync.RWMutex
	cfg DynamicConfig
}

// currentDynamicConfig is the process-wide snapshot. It is seeded with the
// built-in defaults so callers get sane behaviour even before the informer has
// synced (or when running without a ConfigMap, e.g. in unit tests).
var currentDynamicConfig = &dynamicConfigStore{cfg: defaultDynamicConfig()}

func (s *dynamicConfigStore) get() DynamicConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *dynamicConfigStore) set(cfg DynamicConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// parseDynamicConfig decodes the embedded YAML document. On any parse error it
// returns the built-in defaults so a malformed ConfigMap never wipes out the
// detection rules.
func parseDynamicConfig(raw string, log logr.Logger) DynamicConfig {
	if raw == "" {
		return defaultDynamicConfig()
	}
	var cfg DynamicConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		log.Error(err, "failed to parse dynamic config, falling back to built-in defaults")
		return defaultDynamicConfig()
	}
	return cfg
}

// applyConfigMap extracts the embedded document from a ConfigMap and swaps it
// into the process-wide snapshot.
func applyConfigMap(cm *corev1.ConfigMap, log logr.Logger) {
	raw := ""
	if cm.Data != nil {
		raw = cm.Data[DynamicConfigMapKey]
	}
	currentDynamicConfig.set(parseDynamicConfig(raw, log))
	log.Info("dynamic config reloaded", "configMap", cm.Name)
}

// resetDynamicConfigToDefault restores the built-in defaults, used when the
// ConfigMap is deleted so stale rules do not linger.
func resetDynamicConfigToDefault() {
	currentDynamicConfig.set(defaultDynamicConfig())
}

// StartDynamicConfigInformer wires a ConfigMap informer (already scoped to the
// vArmor namespace by the caller's factory) so edits to varmor-config are
// hot-reloaded into the process-wide snapshot without a manager restart. Only
// the ConfigMap named DynamicConfigMapName is acted upon; other ConfigMaps in
// the namespace are ignored.
func StartDynamicConfigInformer(cmInformer coreinformer.ConfigMapInformer, log logr.Logger) {
	_, err := cmInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Name == DynamicConfigMapName {
				applyConfigMap(cm, log)
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			if cm, ok := newObj.(*corev1.ConfigMap); ok && cm.Name == DynamicConfigMapName {
				applyConfigMap(cm, log)
			}
		},
		DeleteFunc: func(obj interface{}) {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok {
				// Handle the tombstone wrapper delivered on missed deletes.
				tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown)
				if !isTombstone {
					return
				}
				cm, ok = tombstone.Obj.(*corev1.ConfigMap)
				if !ok {
					return
				}
			}
			if cm.Name == DynamicConfigMapName {
				log.Info("dynamic config ConfigMap deleted, restoring built-in defaults", "configMap", cm.Name)
				resetDynamicConfigToDefault()
			}
		},
	})
	if err != nil {
		utilruntime.HandleError(err)
	}
}

// GetDynamicConfig returns a copy of the current dynamic configuration
// snapshot. Intended for read-only inspection/tests.
func GetDynamicConfig() DynamicConfig {
	return currentDynamicConfig.get()
}

// IsMicroVMPod reports whether a Pod with the given template labels, annotations
// and runtimeClassName should be treated as running under a micro-VM runtime
// (kata / serverless sandbox), per the current dynamic configuration. It is
// evaluated at admission time to decide the NetworkProxy ALS audit volume
// topology: runc Pods get the shared hostPath socket volume, micro-VM Pods get
// none (the in-sidecar sink binds the socket in the container's own writable
// rootfs).
//
// runtimeClassName may be nil (no RuntimeClass set). Matching is OR across all
// configured signals (runtimeClassName, annotations, labels).
func IsMicroVMPod(labels, annotations map[string]string, runtimeClassName *string) bool {
	cfg := currentDynamicConfig.get()

	if runtimeClassName != nil && *runtimeClassName != "" {
		for _, name := range cfg.MicroVMDetection.RuntimeClassNames {
			if *runtimeClassName == name {
				return true
			}
		}
	}

	if len(annotations) > 0 {
		for _, rule := range cfg.MicroVMDetection.Annotations {
			if rule.Key == "" {
				continue
			}
			v, ok := annotations[rule.Key]
			if !ok {
				continue
			}
			// Empty rule value => match on key presence alone.
			if rule.Value == "" || rule.Value == v {
				return true
			}
		}
	}

	if len(labels) > 0 {
		for _, rule := range cfg.MicroVMDetection.Labels {
			if rule.Key == "" {
				continue
			}
			v, ok := labels[rule.Key]
			if !ok {
				continue
			}
			// Empty rule value => match on key presence alone.
			if rule.Value == "" || rule.Value == v {
				return true
			}
		}
	}

	return false
}
