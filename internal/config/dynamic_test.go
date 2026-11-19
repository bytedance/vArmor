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
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"gotest.tools/assert"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/bytedance/vArmor/pkg/workload"
	workloadbuiltin "github.com/bytedance/vArmor/pkg/workload/builtin"
	"github.com/bytedance/vArmor/pkg/workload/workloadtest"
)

// testAdapters returns the built-in adapters plus the package-local test
// adapter, mirroring a manager binary with one custom adapter compiled in.
// Every test builds its own slice/registry; there is no process-global
// registry.
func testAdapters() []workload.Adapter {
	return append(workloadbuiltin.Adapters(), customTestAdapter())
}

// testRegistry mirrors testAdapters as an immutable registry for tests that
// drive the adapter-facing lookup APIs. The custom adapter stays
// package-local; registry construction is shared through workloadtest.
func testRegistry(t *testing.T) *workload.Registry {
	t.Helper()
	return workloadtest.NewRegistry(t, customTestAdapter())
}

func TestResolveWorkloadAdapterOptions_PrecedenceAndValidation(t *testing.T) {
	a := customTestAdapter().(workloadtest.FakeAdapter)
	a.Options = workload.WebhookOptions{
		FailurePolicy: admissionregistrationv1.Fail, TimeoutSeconds: 7,
		MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "default", Expression: "true"}},
	}
	defaults := WorkloadAdapterDefaults(a, logr.Discard())
	for _, tc := range []struct {
		name       string
		raw        string
		timeout    int32
		policy     admissionregistrationv1.FailurePolicyType
		conditions int
	}{
		{"defaults", "", 7, admissionregistrationv1.Fail, 1},
		{"override", "failurePolicy: Ignore\n    timeoutSeconds: 12\n    matchConditions: []", 12, admissionregistrationv1.Ignore, 0},
		{"zero timeout", "timeoutSeconds: 0", int32(WebhookTimeout), admissionregistrationv1.Fail, 1},
		{"invalid policy", "failurePolicy: Fial", 7, admissionregistrationv1.Fail, 1},
		// timeoutSeconds is not client-side validated; the API server enforces
		// the [1, 30] range at apply time, so an out-of-range value is passed
		// through unchanged here.
		{"out-of-range timeout passes through", "timeoutSeconds: 31", 31, admissionregistrationv1.Fail, 1},
		// validateMatchConditions is structural-only (CEL semantics are
		// enforced by the API server at apply time), so only shape-level
		// failures (duplicate names, bad names, empty expressions) fall back
		// to the adapter's default condition list.
		{"duplicate name", "matchConditions:\n    - name: duplicate\n      expression: 'true'\n    - name: duplicate\n      expression: 'false'", 7, admissionregistrationv1.Fail, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := parseDynamicConfig("workloadAdapters:\n  unit-custom:\n    "+tc.raw, logr.Discard(), testAdapters())
			opts := ResolveWorkloadAdapterOptions(cfg, a, defaults, int32(WebhookTimeout))
			assert.Equal(t, opts.TimeoutSeconds, tc.timeout)
			assert.Equal(t, opts.FailurePolicy, tc.policy)
			assert.Equal(t, len(opts.MatchConditions), tc.conditions)
		})
	}
}

func TestValidateMatchConditions_Structural(t *testing.T) {
	assert.NilError(t, validateMatchConditions(nil))
	assert.NilError(t, validateMatchConditions([]admissionregistrationv1.MatchCondition{
		{Name: "valid-name", Expression: `request.operation == 'CREATE'`},
	}))

	for _, tc := range []struct {
		name string
		cond []admissionregistrationv1.MatchCondition
	}{
		{"duplicate name", []admissionregistrationv1.MatchCondition{{Name: "dupe", Expression: "a"}, {Name: "dupe", Expression: "b"}}},
		{"invalid name", []admissionregistrationv1.MatchCondition{{Name: "bad name!", Expression: "a"}}},
		{"empty expression", []admissionregistrationv1.MatchCondition{{Name: "empty", Expression: "   "}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMatchConditions(tc.cond)
			assert.Assert(t, err != nil, "expected error for %s", tc.name)
		})
	}
}

func TestStartDynamicConfigInformer_InitialDeliveryAndHotReloadNotification(t *testing.T) {
	previous := currentDynamicConfig.get()
	defer currentDynamicConfig.set(previous)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: DynamicConfigMapName, Namespace: "test"},
		Data:       map[string]string{DynamicConfigMapKey: "workloadAdapters:\n  builtin:\n    enabled: false\n  unit-custom:\n    enabled: true\n    failurePolicy: Fail"},
	})
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace("test"))
	informer := factory.Core().V1().ConfigMaps()
	handlerSynced := StartDynamicConfigInformer(informer, logr.Discard(), testAdapters())
	changes := DynamicConfigChanges()
	for len(changes) > 0 {
		<-changes
	}
	factory.Start(ctx.Done())
	assert.Assert(t, cache.WaitForCacheSync(ctx.Done(), informer.Informer().HasSynced, handlerSynced))
	assert.Assert(t, !IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "Deployment")))
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), customTestAdapter()))
	// Initial notification has been delivered by the handler sync barrier.
	<-changes
	cm, err := client.CoreV1().ConfigMaps("test").Get(ctx, DynamicConfigMapName, metav1.GetOptions{})
	assert.NilError(t, err)
	cm.Data[DynamicConfigMapKey] = "workloadAdapters:\n  unit-custom:\n    failurePolicy: Ignore"
	_, err = client.CoreV1().ConfigMaps("test").Update(ctx, cm, metav1.UpdateOptions{})
	assert.NilError(t, err)
	select {
	case <-changes:
		a := customTestAdapter()
		opts := ResolveWorkloadAdapterOptions(GetDynamicConfig(), a, WorkloadAdapterDefaults(a, logr.Discard()), int32(WebhookTimeout))
		assert.Equal(t, opts.FailurePolicy, admissionregistrationv1.Ignore)
	case <-ctx.Done():
		t.Fatal("ConfigMap update did not notify reconciliation")
	}
	cancel()
	factory.Shutdown()
}

func TestDynamicConfigChanges_CoalescesUpdates(t *testing.T) {
	changes := DynamicConfigChanges()
	for len(changes) > 0 {
		<-changes
	}
	restore := SetDynamicConfigForTest(DynamicConfig{})
	defer restore()
	for i := 0; i < 100; i++ {
		currentDynamicConfig.set(DynamicConfig{})
	}
	assert.Equal(t, len(changes), 1)
	<-changes
	currentDynamicConfig.set(defaultDynamicConfig())
	assert.Equal(t, len(changes), 1)
	<-changes
	assert.Assert(t, len(GetDynamicConfig().MicroVMDetection.RuntimeClassNames) > 0)
}

func customTestAdapter() workload.Adapter {
	return workloadtest.FakeAdapter{
		AdapterName: "unit-custom",
		AdapterGVK:  schema.GroupVersionKind{Group: "unit.test", Version: "v1", Kind: "UnitCustom"},
		AdapterGVR:  schema.GroupVersionResource{Group: "unit.test", Version: "v1", Resource: "unitcustoms"},
	}
}

func mustAdapter(t *testing.T, kind string) workload.Adapter {
	t.Helper()
	a, ok := testRegistry(t).LookupByKind(kind)
	assert.Assert(t, ok, "adapter %q must be present in the test registry", kind)
	return a
}

// strPtr returns a pointer to s for table-driven test fixtures.
func strPtr(s string) *string { return &s }

// withConfig swaps the process-wide snapshot for the duration of a test and
// restores the built-in defaults afterwards.
func withConfig(t *testing.T, cfg DynamicConfig) {
	t.Helper()
	currentDynamicConfig.set(cfg)
	t.Cleanup(resetDynamicConfigToDefault)
}

func TestIsMicroVMPod_DefaultRules(t *testing.T) {
	resetDynamicConfigToDefault()
	t.Cleanup(resetDynamicConfigToDefault)

	// Volcengine VKE burst-to-VCI annotation (exact value match).
	assert.Assert(t, IsMicroVMPod(nil, map[string]string{"vke.volcengine.com/burst-to-vci": "enforce"}, nil),
		"burst-to-vci=enforce should be micro-VM")
	// Wrong value must not match when the default rule requires "enforce".
	assert.Assert(t, !IsMicroVMPod(nil, map[string]string{"vke.volcengine.com/burst-to-vci": "auto"}, nil),
		"burst-to-vci=auto should not match the enforce rule")

	// Upstream kata RuntimeClasses.
	assert.Assert(t, IsMicroVMPod(nil, nil, strPtr("kata")), "runtimeClassName kata should be micro-VM")
	assert.Assert(t, IsMicroVMPod(nil, nil, strPtr("kata-qemu")), "runtimeClassName kata-qemu should be micro-VM")
	assert.Assert(t, IsMicroVMPod(nil, nil, strPtr("kata-clh")), "runtimeClassName kata-clh should be micro-VM")

	// Alibaba Cloud ECI opt-in label (exact value match).
	assert.Assert(t, IsMicroVMPod(map[string]string{"alibabacloud.com/eci": "true"}, nil, nil),
		"alibabacloud.com/eci=true label should be micro-VM")
	assert.Assert(t, !IsMicroVMPod(map[string]string{"alibabacloud.com/eci": "false"}, nil, nil),
		"alibabacloud.com/eci=false label should not match the true rule")

	// Plain runc: no annotation, no runtimeClassName.
	assert.Assert(t, !IsMicroVMPod(nil, nil, nil), "runc pod should not be micro-VM")
	assert.Assert(t, !IsMicroVMPod(nil, map[string]string{"foo": "bar"}, strPtr("runc")), "runc pod should not be micro-VM")
	assert.Assert(t, !IsMicroVMPod(nil, nil, strPtr("")), "empty runtimeClassName should not be micro-VM")
}

func TestIsMicroVMPod_AnnotationKeyPresenceOnly(t *testing.T) {
	withConfig(t, DynamicConfig{
		MicroVMDetection: MicroVMDetection{
			Annotations: []AnnotationRule{{Key: "example.com/serverless", Value: ""}},
		},
	})

	// Empty rule value => match on key presence regardless of value.
	assert.Assert(t, IsMicroVMPod(nil, map[string]string{"example.com/serverless": "anything"}, nil),
		"key presence with empty rule value should match")
	assert.Assert(t, IsMicroVMPod(nil, map[string]string{"example.com/serverless": ""}, nil),
		"key present with empty value should match")
	assert.Assert(t, !IsMicroVMPod(nil, map[string]string{"other": "x"}, nil),
		"absent key should not match")
}

func TestIsMicroVMPod_LabelRules(t *testing.T) {
	withConfig(t, DynamicConfig{
		MicroVMDetection: MicroVMDetection{
			Labels: []LabelRule{
				{Key: "alibabacloud.com/eci", Value: "true"},
				{Key: "example.com/serverless", Value: ""},
			},
		},
	})

	// Exact value match.
	assert.Assert(t, IsMicroVMPod(map[string]string{"alibabacloud.com/eci": "true"}, nil, nil),
		"label exact value should match")
	assert.Assert(t, !IsMicroVMPod(map[string]string{"alibabacloud.com/eci": "false"}, nil, nil),
		"label wrong value should not match")
	// Empty rule value => match on key presence regardless of value.
	assert.Assert(t, IsMicroVMPod(map[string]string{"example.com/serverless": "anything"}, nil, nil),
		"label key presence with empty rule value should match")
	// Absent label.
	assert.Assert(t, !IsMicroVMPod(map[string]string{"other": "x"}, nil, nil),
		"absent label should not match")
}

func TestIsMicroVMPod_OrSemantics(t *testing.T) {
	withConfig(t, DynamicConfig{
		MicroVMDetection: MicroVMDetection{
			RuntimeClassNames: []string{"kata"},
			Annotations:       []AnnotationRule{{Key: "vendor/vm", Value: "on"}},
			Labels:            []LabelRule{{Key: "vendor/vm-label", Value: "on"}},
		},
	})

	// Matching any single signal is sufficient.
	assert.Assert(t, IsMicroVMPod(nil, nil, strPtr("kata")))
	assert.Assert(t, IsMicroVMPod(nil, map[string]string{"vendor/vm": "on"}, strPtr("runc")))
	assert.Assert(t, IsMicroVMPod(map[string]string{"vendor/vm-label": "on"}, nil, strPtr("runc")))
	assert.Assert(t, !IsMicroVMPod(map[string]string{"vendor/vm-label": "off"}, map[string]string{"vendor/vm": "off"}, strPtr("runc")))
}

func TestParseDynamicConfig_Valid(t *testing.T) {
	raw := `
microVMDetection:
  runtimeClassNames:
    - kata-qemu
    - my-vm
  annotations:
    - key: a.com/x
      value: "1"
    - key: b.com/y
  labels:
    - key: alibabacloud.com/eci
      value: "true"
    - key: c.com/z
`
	cfg := parseDynamicConfig(raw, logr.Discard(), nil)
	assert.DeepEqual(t, cfg.MicroVMDetection.RuntimeClassNames, []string{"kata-qemu", "my-vm"})
	assert.Equal(t, len(cfg.MicroVMDetection.Annotations), 2)
	assert.Equal(t, cfg.MicroVMDetection.Annotations[0].Key, "a.com/x")
	assert.Equal(t, cfg.MicroVMDetection.Annotations[0].Value, "1")
	assert.Equal(t, cfg.MicroVMDetection.Annotations[1].Key, "b.com/y")
	assert.Equal(t, cfg.MicroVMDetection.Annotations[1].Value, "")
	assert.Equal(t, len(cfg.MicroVMDetection.Labels), 2)
	assert.Equal(t, cfg.MicroVMDetection.Labels[0].Key, "alibabacloud.com/eci")
	assert.Equal(t, cfg.MicroVMDetection.Labels[0].Value, "true")
	assert.Equal(t, cfg.MicroVMDetection.Labels[1].Key, "c.com/z")
	assert.Equal(t, cfg.MicroVMDetection.Labels[1].Value, "")
}

func TestParseDynamicConfig_EmptyAndMalformedFallBackToDefaults(t *testing.T) {
	def := defaultDynamicConfig()

	empty := parseDynamicConfig("", logr.Discard(), nil)
	assert.DeepEqual(t, empty, def)

	bad := parseDynamicConfig("microVMDetection: [this is not a map", logr.Discard(), nil)
	assert.DeepEqual(t, bad, def)
}

func TestWorkloadAdapters_Defaults(t *testing.T) {
	resetDynamicConfigToDefault()
	t.Cleanup(resetDynamicConfigToDefault)

	// The four built-in kinds are enabled out of the box.
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "Deployment")))
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "StatefulSet")))
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "DaemonSet")))
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "Pod")))
	// A custom adapter is disabled until explicitly enabled.
	assert.Assert(t, !IsAdapterEnabled(GetDynamicConfig(), customTestAdapter()))
}

func TestWorkloadAdapters_EnabledOverride(t *testing.T) {
	withConfig(t, DynamicConfig{
		WorkloadAdapters: map[string]WorkloadAdapterConfig{
			WorkloadAdapterBuiltinRollup: {Enabled: boolPtr(false)},
			"unit-custom":                {Enabled: boolPtr(true)},
		},
	})

	// The rollup switch disables all three apps/v1 adapters together.
	assert.Assert(t, !IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "Deployment")))
	assert.Assert(t, !IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "StatefulSet")))
	assert.Assert(t, !IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "DaemonSet")))
	// Pod has its own key and is untouched by the rollup switch.
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), mustAdapter(t, "Pod")))
	// The explicitly enabled custom adapter is now active.
	assert.Assert(t, IsAdapterEnabled(GetDynamicConfig(), customTestAdapter()))
}

func TestWorkloadAdapters_HotReloadedFields(t *testing.T) {
	failurePolicy := admissionregistrationv1.Fail
	timeout := int32(7)
	matchConditions := []admissionregistrationv1.MatchCondition{
		{Name: "opt-in", Expression: "has(object.metadata.annotations['example.com/opt-in'])"},
	}

	// Unset: fallbacks and zero values apply.
	resetDynamicConfigToDefault()
	t.Cleanup(resetDynamicConfigToDefault)
	custom := customTestAdapter()
	defaults := WorkloadAdapterDefaults(custom, logr.Discard())
	opts := ResolveWorkloadAdapterOptions(GetDynamicConfig(), custom, defaults, int32(WebhookTimeout))
	assert.Equal(t, opts.FailurePolicy, admissionregistrationv1.Ignore)
	assert.Equal(t, opts.TimeoutSeconds, int32(WebhookTimeout))
	assert.Assert(t, opts.MatchConditions == nil)

	// Configured: overrides are returned.
	withConfig(t, DynamicConfig{
		WorkloadAdapters: map[string]WorkloadAdapterConfig{
			"unit-custom": {
				FailurePolicy:   &failurePolicy,
				TimeoutSeconds:  &timeout,
				MatchConditions: matchConditions,
			},
		},
	})
	opts = ResolveWorkloadAdapterOptions(GetDynamicConfig(), custom, defaults, int32(WebhookTimeout))
	assert.Equal(t, opts.FailurePolicy, admissionregistrationv1.Fail)
	assert.Equal(t, opts.TimeoutSeconds, timeout)
	assert.DeepEqual(t, opts.MatchConditions, matchConditions)
}

func TestConfigKeyFor(t *testing.T) {
	testCases := []struct {
		name string
		kind string
		want string
	}{
		{"deployment rolls up", "Deployment", WorkloadAdapterBuiltinRollup},
		{"statefulset rolls up", "StatefulSet", WorkloadAdapterBuiltinRollup},
		{"daemonset rolls up", "DaemonSet", WorkloadAdapterBuiltinRollup},
		{"pod is standalone", "Pod", WorkloadAdapterPod},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, configKeyFor(mustAdapter(t, tc.kind)), tc.want)
		})
	}
	// A custom adapter is keyed by its own Name().
	assert.Equal(t, configKeyFor(customTestAdapter()), "unit-custom")
	// Other apps-group kinds must not inherit the built-in rollup or defaults.
	otherApps := workloadtest.FakeAdapter{
		AdapterName: "replicaset",
		AdapterGVK:  schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"},
	}
	assert.Equal(t, configKeyFor(otherApps), "replicaset")
	assert.Assert(t, !enabledByDefault(otherApps))
}

func TestWarnUnknownWorkloadAdapters_Tolerated(t *testing.T) {
	// An unknown key (e.g. an adapter from a newer/older binary) must never
	// crash parsing; it is logged and ignored.
	warnUnknownWorkloadAdapters(
		map[string]WorkloadAdapterConfig{"does-not-exist": {Enabled: boolPtr(true)}},
		logr.Discard(),
		nil,
	)
}

func TestParseDynamicConfig_WorkloadAdapters(t *testing.T) {
	raw := `
workloadAdapters:
  builtin:
    enabled: false
  pod:
    enabled: true
  unit-custom:
    enabled: true
    failurePolicy: Fail
    timeoutSeconds: 8
`
	cfg := parseDynamicConfig(raw, logr.Discard(), testAdapters())

	assert.Equal(t, *cfg.WorkloadAdapters[WorkloadAdapterBuiltinRollup].Enabled, false)
	assert.Equal(t, *cfg.WorkloadAdapters[WorkloadAdapterPod].Enabled, true)
	custom := cfg.WorkloadAdapters["unit-custom"]
	assert.Equal(t, *custom.Enabled, true)
	assert.Equal(t, *custom.FailurePolicy, admissionregistrationv1.Fail)
	assert.Equal(t, *custom.TimeoutSeconds, int32(8))
}
