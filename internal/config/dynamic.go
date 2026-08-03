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
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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

	// NetworkProxy carries cluster-level defaults for the NetworkProxy enforcer,
	// currently the global proxy-sidecar resource defaults. It is the middle
	// layer of the sidecar resource merge chain (see ResolveProxyResources):
	// per-policy override > this global config > built-in defaults.
	NetworkProxy NetworkProxyDynamicConfig `yaml:"networkProxy"`
}

// NetworkProxyDynamicConfig holds cluster-level, hot-reloadable settings for
// the NetworkProxy enforcer.
type NetworkProxyDynamicConfig struct {
	// DefaultResources are the cluster-wide default resource requirements for
	// the proxy sidecar container. An administrator can tune sidecar resources
	// once here instead of per policy. It is split into two independent tiers
	// (nonMitm / mitm), mirroring the built-in defaults, because MITM sidecars
	// run heavier (double TLS handshakes) than non-MITM ones.
	DefaultResources ProxyDefaultResources `yaml:"defaultResources"`
}

// ProxyDefaultResources carries the global sidecar resource defaults as two
// independent tiers, mirroring the built-in defaults: NonMITM applies to
// sidecars without MITM, MITM applies to sidecars with MITM enabled. The tiers
// are NOT inherited from one another — a MITM sidecar reads ONLY the mitm tier
// and a non-MITM sidecar reads ONLY the nonMitm tier.
//
// Values are kept as strings (Kubernetes quantity syntax, e.g. "200m",
// "256Mi") so the embedded YAML stays human-authorable; they are parsed into
// corev1 quantities on read, and invalid values are ignored (and warned about
// at load time) rather than rejecting the whole config.
type ProxyDefaultResources struct {
	// NonMITM is the tier applied to sidecars without MITM enabled.
	NonMITM ProxyResourceTier `yaml:"nonMitm"`

	// MITM is the tier applied to sidecars with MITM enabled.
	MITM ProxyResourceTier `yaml:"mitm"`
}

// ProxyResourceTier is one resource tier (requests + limits) expressed as
// quantity strings keyed by resource name (cpu, memory).
type ProxyResourceTier struct {
	Requests map[string]string `yaml:"requests"`
	Limits   map[string]string `yaml:"limits"`
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
	warnInvalidProxyResourceValues(cfg.NetworkProxy.DefaultResources, log)
	return cfg
}

// knownProxyResourceNames is the set of resource names the proxy sidecar
// understands. Any other key (e.g. "cpuu") is almost certainly a typo: it would
// otherwise be attached to the sidecar as a bogus resource while the intended
// cpu/memory silently kept the built-in default. Such keys are dropped on read
// (see parseResourceList) and warned about at load time.
var knownProxyResourceNames = map[corev1.ResourceName]struct{}{
	corev1.ResourceCPU:    {},
	corev1.ResourceMemory: {},
}

// validateProxyResourceEntry validates one (name, value) entry from the global
// proxy-resource config. It returns the parsed quantity when the entry is
// usable, or a non-nil error explaining why it must be ignored:
//   - an unknown resource name (typo; only cpu and memory are supported),
//   - an unparseable Kubernetes quantity,
//   - a non-positive quantity (zero or negative; ParseQuantity accepts "0" and
//     "-5m", but neither is a meaningful sidecar request/limit).
//
// Both the load-time warner and the read-time parser call this, so the "what is
// a valid entry" rule lives in exactly one place and the log warnings always
// match what actually gets dropped.
func validateProxyResourceEntry(name, value string) (resource.Quantity, error) {
	if _, ok := knownProxyResourceNames[corev1.ResourceName(name)]; !ok {
		return resource.Quantity{}, fmt.Errorf("unknown resource name %q (only cpu and memory are supported)", name)
	}
	q, err := resource.ParseQuantity(value)
	if err != nil {
		return resource.Quantity{}, err
	}
	if q.Sign() <= 0 {
		return resource.Quantity{}, fmt.Errorf("quantity must be greater than zero, got %q", value)
	}
	return q, nil
}

// warnInvalidProxyResourceValues surfaces, at load time, every global
// proxy-resource entry that will be ignored on read, plus any tier whose limit
// is below its request. Nothing here rejects the config: invalid entries
// degrade to the built-in default for that field (see parseResourceList) and a
// limit-below-request only fails later at the kube-apiserver, so warning is the
// only feedback channel for an otherwise silent, cluster-wide misconfiguration.
func warnInvalidProxyResourceValues(dr ProxyDefaultResources, log logr.Logger) {
	// Per-entry checks: typo / unparseable / non-positive.
	checkEntries := func(path string, m map[string]string) {
		for k, v := range m {
			if v == "" {
				continue
			}
			if _, err := validateProxyResourceEntry(k, v); err != nil {
				log.Error(err, "ignoring invalid entry in global proxy resource config",
					"path", path, "resource", k, "value", v)
			}
		}
	}
	checkEntries("networkProxy.defaultResources.nonMitm.requests", dr.NonMITM.Requests)
	checkEntries("networkProxy.defaultResources.nonMitm.limits", dr.NonMITM.Limits)
	checkEntries("networkProxy.defaultResources.mitm.requests", dr.MITM.Requests)
	checkEntries("networkProxy.defaultResources.mitm.limits", dr.MITM.Limits)

	// Per-tier check: within a tier, a valid limit must not be below its valid
	// request. We only compare entries that are themselves valid (invalid ones
	// are already reported above and dropped on read).
	warnLimitBelowRequest := func(tier string, requests, limits map[string]string) {
		for name, reqStr := range requests {
			limStr, ok := limits[name]
			if !ok {
				continue
			}
			reqQ, reqErr := validateProxyResourceEntry(name, reqStr)
			limQ, limErr := validateProxyResourceEntry(name, limStr)
			if reqErr != nil || limErr != nil {
				continue
			}
			if limQ.Cmp(reqQ) < 0 {
				log.Error(
					fmt.Errorf("limits.%s (%s) < requests.%s (%s)", name, limStr, name, reqStr),
					"global proxy resource config has a limit below its request; "+
						"the kube-apiserver will reject the sidecar Pod unless a per-policy override corrects it",
					"tier", tier, "resource", name)
			}
		}
	}
	warnLimitBelowRequest("non-mitm", dr.NonMITM.Requests, dr.NonMITM.Limits)
	warnLimitBelowRequest("mitm", dr.MITM.Requests, dr.MITM.Limits)
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

// SetDynamicConfigForTest overrides the process-wide dynamic config snapshot and
// returns a function that restores the built-in defaults. It exists so tests in
// other packages (e.g. the injection chain) can exercise config-dependent
// behaviour. Production code must never call it: the ConfigMap informer is the
// sole writer of the snapshot at runtime.
func SetDynamicConfigForTest(cfg DynamicConfig) (restore func()) {
	currentDynamicConfig.set(cfg)
	return resetDynamicConfigToDefault
}

// GetNetworkProxyDefaultResources returns the cluster-global proxy sidecar
// resource defaults from the current dynamic config snapshot, as two ready-to-
// merge corev1.ResourceRequirements: nonMITM and mitm. Only successfully parsed
// quantities are populated; unset or invalid values are omitted so callers can
// overlay them field-by-field on top of the built-in defaults. When nothing is
// configured, both returned values are empty (nil maps), which makes the merge
// a no-op and preserves the built-in defaults.
func GetNetworkProxyDefaultResources() (nonMITM, mitm corev1.ResourceRequirements) {
	dr := currentDynamicConfig.get().NetworkProxy.DefaultResources
	nonMITM = corev1.ResourceRequirements{
		Requests: parseResourceList(dr.NonMITM.Requests),
		Limits:   parseResourceList(dr.NonMITM.Limits),
	}
	mitm = corev1.ResourceRequirements{
		Requests: parseResourceList(dr.MITM.Requests),
		Limits:   parseResourceList(dr.MITM.Limits),
	}
	return nonMITM, mitm
}

// parseResourceList converts a map of quantity strings (keyed by resource name)
// into a corev1.ResourceList, skipping empty or invalid entries (unknown
// resource name, unparseable quantity, or non-positive value). It returns nil
// when nothing valid is present so the result overlays cleanly (a nil map
// contributes no fields to the merge). The per-entry rule is shared with the
// load-time warner via validateProxyResourceEntry, so what is dropped here is
// exactly what gets warned about at load time.
func parseResourceList(m map[string]string) corev1.ResourceList {
	if len(m) == 0 {
		return nil
	}
	rl := corev1.ResourceList{}
	for k, v := range m {
		if v == "" {
			continue
		}
		q, err := validateProxyResourceEntry(k, v)
		if err != nil {
			// Invalid entries are dropped here and warned about at load time
			// (warnInvalidProxyResourceValues), so a typo/negative/zero degrades
			// to the built-in default for that field instead of producing a
			// bogus sidecar resource or breaking admission.
			continue
		}
		rl[corev1.ResourceName(k)] = q
	}
	if len(rl) == 0 {
		return nil
	}
	return rl
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
