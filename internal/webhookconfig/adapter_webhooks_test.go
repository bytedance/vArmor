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

package webhookconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	admissionregistrationapi "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"

	"github.com/bytedance/vArmor/internal/config"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	"github.com/bytedance/vArmor/pkg/workload"
	"github.com/bytedance/vArmor/pkg/workload/workloadtest"
)

func TestBuiltinClassification(t *testing.T) {
	testCases := []struct {
		name string
		a    workload.Adapter
		want bool
	}{
		{"deployment", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}}, true},
		{"statefulset", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}}, true},
		{"daemonset", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}}, true},
		{"pod", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}}, true},
		{"custom namespaced CR", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Application"}}, false},
		{"custom core-group non-pod", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}}, false},
		{"other apps kind", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}}, false},
		{"deployment in custom group", workloadtest.FakeAdapter{AdapterGVK: schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Deployment"}}, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := workload.IsBuiltin(tc.a.GVK().GroupKind()); got != tc.want {
				t.Fatalf("IsBuiltin(%s) = %t, want %t", tc.a.GVK(), got, tc.want)
			}
		})
	}
}

func TestAdapterWebhookName(t *testing.T) {
	testCases := []struct {
		name string
		a    workload.Adapter
		want string
	}{
		{
			name: "namespaced group",
			a: workloadtest.FakeAdapter{
				AdapterGVK: schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Application"},
				AdapterGVR: schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "applications"},
			},
			want: "mutate-applications.example.com.varmor.org",
		},
		{
			name: "empty group renders core",
			a: workloadtest.FakeAdapter{
				AdapterGVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"},
				AdapterGVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"},
			},
			want: "mutate-nodes.core.varmor.org",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := adapterWebhookName(tc.a); got != tc.want {
				t.Fatalf("adapterWebhookName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAdapterWebhookRule(t *testing.T) {
	a := workloadtest.FakeAdapter{
		AdapterGVK: schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Application"},
		AdapterGVR: schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "applications"},
	}
	rule := adapterWebhookRule(a)

	if len(rule.APIGroups) != 1 || rule.APIGroups[0] != "example.com" {
		t.Errorf("APIGroups = %v, want [example.com]", rule.APIGroups)
	}
	if len(rule.APIVersions) != 1 || rule.APIVersions[0] != "v1" {
		t.Errorf("APIVersions = %v, want [v1]", rule.APIVersions)
	}
	if len(rule.Resources) != 1 || rule.Resources[0] != "applications" {
		t.Errorf("Resources = %v, want [applications]", rule.Resources)
	}
	for _, r := range rule.Resources {
		if r == "applications/status" || r == "applications/*" {
			t.Errorf("rule must target the main resource only, got %q", r)
		}
	}
}

// widget identities are declared once so constructors, assertions and fixtures
// cannot drift apart.
var (
	widgetGVK  = schema.GroupVersionKind{Group: "webhookconfig.test.varmor.org", Version: "v1", Kind: "TestWidget"}
	widgetGVR  = schema.GroupVersionResource{Group: "webhookconfig.test.varmor.org", Version: "v1", Resource: "testwidgets"}
	widget2GVK = schema.GroupVersionKind{Group: "webhookconfig.test.varmor.org", Version: "v1", Kind: "TestWidget2"}
	widget2GVR = schema.GroupVersionResource{Group: "webhookconfig.test.varmor.org", Version: "v1", Resource: "testwidgets2"}
)

// widgetDefaultOptions is the shared non-builtin webhook option set both
// custom fakes expose. Keeping it in one helper guarantees the two adapters
// stay co-groupable by customAdapterWebhooks.
func widgetDefaultOptions() workload.WebhookOptions {
	return workload.WebhookOptions{
		FailurePolicy:   admissionregistrationapi.Ignore,
		TimeoutSeconds:  8,
		MatchConditions: []admissionregistrationapi.MatchCondition{{Name: "default", Expression: "true"}},
	}
}

// registeredFake is a custom adapter added to the test-local registry for the
// create-or-update builder test. Its identifiers are unique to this package so
// it can never collide with a built-in adapter. It embeds
// workloadtest.FakeAdapter for identity and no-op PodTemplates; each test
// builds its own registry.
type registeredFake struct {
	workloadtest.FakeAdapter
}

// newRegisteredFake builds a registeredFake with its fixed identity and the
// package's non-builtin default options.
func newRegisteredFake() registeredFake {
	return registeredFake{FakeAdapter: workloadtest.FakeAdapter{
		AdapterName: "testwidget",
		AdapterGVK:  widgetGVK,
		AdapterGVR:  widgetGVR,
		Options:     widgetDefaultOptions(),
	}}
}

type compatibleFake struct {
	workloadtest.FakeAdapter
}

// newCompatibleFake mirrors newRegisteredFake under a second identity so the
// grouping tests have two custom adapters with identical webhook options.
func newCompatibleFake() compatibleFake {
	return compatibleFake{FakeAdapter: workloadtest.FakeAdapter{
		AdapterName: "testwidget2",
		AdapterGVK:  widget2GVK,
		AdapterGVR:  widget2GVR,
		Options:     widgetDefaultOptions(),
	}}
}

// testRegistry builds an isolated registry holding the built-in adapters plus
// the package's two custom fakes. Tests never touch process-global state.
func testRegistry(t *testing.T) *workload.Registry {
	t.Helper()
	return workloadtest.NewRegistry(t, newRegisteredFake(), newCompatibleFake())
}

// registryOf builds an isolated registry from an explicit adapter slice. It
// lets tests model a manager binary whose compiled-in adapter set differs from
// the default (e.g. builtins only, or only custom adapters). With
// registry-based enablement, a disabled adapter is simply omitted from the
// slice.
func registryOf(t *testing.T, adapters ...workload.Adapter) *workload.Registry {
	t.Helper()
	r, err := workload.NewRegistry(adapters...)
	if err != nil {
		t.Fatalf("workload.NewRegistry: %v", err)
	}
	return r
}

func newTestRegister(t *testing.T) *Register {
	t.Helper()
	r := testRegistry(t)
	return &Register{timeoutSeconds: int32(config.WebhookTimeout), registry: r, adapterDefaults: newAdapterDefaults(r, logr.Discard())}
}

// newRegisterWithRegistry builds a Register backed by an arbitrary registry,
// for tests that need to model a non-default compiled-in adapter set.
func newRegisterWithRegistry(t *testing.T, r *workload.Registry) *Register {
	t.Helper()
	return &Register{timeoutSeconds: int32(config.WebhookTimeout), registry: r, adapterDefaults: newAdapterDefaults(r, logr.Discard())}
}

func TestCustomAdapterWebhooks_UpstreamDefaultSkipsDisabled(t *testing.T) {
	// Under the upstream default binary no custom adapters are compiled in, so
	// the registry holds only the four built-in kinds and customAdapterWebhooks
	// returns nil, preserving the historical two-entry (built-in only) form.
	// A disabled adapter is modelled by leaving it out of the registry, here
	// by passing no custom extras to workloadtest.NewRegistry.
	got := newRegisterWithRegistry(t, workloadtest.NewRegistry(t)).customAdapterWebhooks(
		config.GetDynamicConfig(),
		admissionregistrationapi.WebhookClientConfig{},
		admissionregistrationapi.IfNeededReinvocationPolicy,
	)
	if got != nil {
		t.Fatalf("expected nil custom webhooks under default config, got %d entries", len(got))
	}
}

func TestCustomAdapterWebhooks_EnabledCustomAdapter(t *testing.T) {
	// An enabled adapter is simply one present in the registry. Register only
	// registeredFake (testwidget) so the output has a single custom entry
	// carrying a single rule.
	got := newRegisterWithRegistry(t, registryOf(t, newRegisteredFake())).customAdapterWebhooks(
		config.GetDynamicConfig(),
		admissionregistrationapi.WebhookClientConfig{},
		admissionregistrationapi.IfNeededReinvocationPolicy,
	)
	if len(got) != 1 {
		t.Fatalf("expected 1 custom webhook entry, got %d", len(got))
	}
	entry := got[0]

	// Deterministic name: mutate-<resource>.<group>.varmor.org.
	wantName := "mutate-testwidgets.webhookconfig.test.varmor.org.varmor.org"
	if entry.Name != wantName {
		t.Fatalf("entry name = %q, want %q", entry.Name, wantName)
	}

	if entry.FailurePolicy == nil || *entry.FailurePolicy != admissionregistrationapi.Ignore {
		t.Errorf("failure policy = %v, want Ignore", entry.FailurePolicy)
	}
	if entry.TimeoutSeconds == nil || *entry.TimeoutSeconds != 8 {
		t.Errorf("timeout = %v, want adapter default 8", entry.TimeoutSeconds)
	}
	if len(entry.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(entry.Rules))
	}
	rule := entry.Rules[0].Rule
	if len(rule.Resources) != 1 || rule.Resources[0] != "testwidgets" {
		t.Errorf("rule resources = %v, want [testwidgets]", rule.Resources)
	}
}

func TestGenerateMutatingWebhookConfig_OptionsAndGrouping(t *testing.T) {
	timeout := int32(12)
	fail := admissionregistrationapi.Fail
	restore := config.SetDynamicConfigForTest(config.DynamicConfig{
		WorkloadAdapters: map[string]config.WorkloadAdapterConfig{
			"testwidget":  {FailurePolicy: &fail, TimeoutSeconds: &timeout, MatchConditions: []admissionregistrationapi.MatchCondition{}},
			"testwidget2": {FailurePolicy: &fail, TimeoutSeconds: &timeout, MatchConditions: []admissionregistrationapi.MatchCondition{}},
		},
	})
	defer restore()
	// Register only the two custom fakes; built-in kinds are intentionally
	// absent from this registry so the generated configuration contains only
	// custom-adapter entries. Both customs share identical options, so they
	// must collapse into a single webhook entry carrying both rules.
	wrc := newRegisterWithRegistry(t, registryOf(t, newRegisteredFake(), newCompatibleFake()))
	generate := func() *admissionregistrationapi.MutatingWebhookConfiguration {
		return wrc.generateMutatingWebhookConfig("test", admissionregistrationapi.WebhookClientConfig{}, admissionregistrationapi.IfNeededReinvocationPolicy)
	}
	got := generate()
	if len(got.Webhooks) != 1 || len(got.Webhooks[0].Rules) != 2 {
		t.Fatalf("compatible adapters should share one entry: %+v", got.Webhooks)
	}
	entry := got.Webhooks[0]
	if *entry.FailurePolicy != fail || *entry.TimeoutSeconds != timeout || len(entry.MatchConditions) != 0 {
		t.Fatalf("overrides not applied: %+v", entry)
	}
	if got.Webhooks[0].Name != generate().Webhooks[0].Name {
		t.Fatal("entry names changed on repeated generation")
	}
	cfg := config.GetDynamicConfig()
	ignore := admissionregistrationapi.Ignore
	second := cfg.WorkloadAdapters["testwidget2"]
	second.FailurePolicy = &ignore
	// Copy the map before publishing the changed immutable snapshot.
	cfg.WorkloadAdapters = map[string]config.WorkloadAdapterConfig{
		"testwidget": cfg.WorkloadAdapters["testwidget"], "testwidget2": second,
	}
	undo := config.SetDynamicConfigForTest(cfg)
	defer undo()
	if len(generate().Webhooks) != 2 {
		t.Fatal("different failure policies must not share an entry")
	}
}

func TestCustomAdapterWebhooks_InvalidOptionsFallBackPerField(t *testing.T) {
	invalidPolicy := admissionregistrationapi.FailurePolicyType("Fial")
	for _, tc := range []struct {
		name  string
		entry config.WorkloadAdapterConfig
	}{
		{"policy", config.WorkloadAdapterConfig{FailurePolicy: &invalidPolicy}},
		{"condition name", config.WorkloadAdapterConfig{MatchConditions: []admissionregistrationapi.MatchCondition{{Name: "invalid name", Expression: "true"}}}},
		{"duplicate conditions", config.WorkloadAdapterConfig{MatchConditions: []admissionregistrationapi.MatchCondition{{Name: "duplicate", Expression: "true"}, {Name: "duplicate", Expression: "false"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := config.SetDynamicConfigForTest(config.DynamicConfig{WorkloadAdapters: map[string]config.WorkloadAdapterConfig{"testwidget": tc.entry}})
			defer restore()
			entries := newTestRegister(t).customAdapterWebhooks(config.GetDynamicConfig(), admissionregistrationapi.WebhookClientConfig{}, admissionregistrationapi.IfNeededReinvocationPolicy)
			if len(entries) != 1 {
				t.Fatalf("entries=%d", len(entries))
			}
			entry := entries[0]
			if *entry.FailurePolicy != admissionregistrationapi.Ignore || *entry.TimeoutSeconds != 8 || len(entry.MatchConditions) != 1 || entry.MatchConditions[0].Name != "default" {
				t.Fatalf("invalid option did not fall back: %+v", entry)
			}
		})
	}
}

func TestUpsertWebhookConfigurations_CreateRaceAndConflictExhaustion(t *testing.T) {
	for _, validating := range []bool{false, true} {
		for _, conflicts := range []bool{false, true} {
			t.Run(fmt.Sprintf("validating=%t/conflicts=%t", validating, conflicts), func(t *testing.T) {
				client := fake.NewSimpleClientset()
				resource := "mutatingwebhookconfigurations"
				var stale runtime.Object = &admissionregistrationapi.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "race"}, Webhooks: []admissionregistrationapi.MutatingWebhook{{Name: "stale"}}}
				if validating {
					resource = "validatingwebhookconfigurations"
					stale = &admissionregistrationapi.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "race"}, Webhooks: []admissionregistrationapi.ValidatingWebhook{{Name: "stale"}}}
				}
				client.PrependReactor("create", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
					if err := client.Tracker().Create(schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: resource}, stale, ""); err != nil {
						return true, nil, err
					}
					return true, nil, k8errors.NewAlreadyExists(schema.GroupResource{Resource: resource}, "race")
				})
				updates := 0
				client.PrependReactor("update", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
					updates++
					if conflicts {
						return true, nil, k8errors.NewConflict(schema.GroupResource{Resource: resource}, "race", fmt.Errorf("conflict"))
					}
					return false, nil, nil
				})
				wrc := &Register{mutateInterface: client.AdmissionregistrationV1().MutatingWebhookConfigurations(), validateInterface: client.AdmissionregistrationV1().ValidatingWebhookConfigurations(), log: logr.Discard()}
				var err error
				if validating {
					err = wrc.upsertValidatingWebhookConfiguration(t.Context(), &admissionregistrationapi.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "race"}, Webhooks: []admissionregistrationapi.ValidatingWebhook{{Name: "desired"}}})
				} else {
					err = wrc.upsertMutatingWebhookConfiguration(t.Context(), &admissionregistrationapi.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "race"}, Webhooks: []admissionregistrationapi.MutatingWebhook{{Name: "desired"}}})
				}
				if conflicts {
					if err == nil || updates != maxUpdateRetries {
						t.Fatalf("expected bounded conflict failure: updates=%d err=%v", updates, err)
					}
					return
				}
				if err != nil || updates != 1 {
					t.Fatalf("create race not reconciled: updates=%d err=%v", updates, err)
				}
				var name string
				if validating {
					got, getErr := wrc.validateInterface.Get(t.Context(), "race", metav1.GetOptions{})
					if getErr != nil {
						t.Fatal(getErr)
					}
					name = got.Webhooks[0].Name
				} else {
					got, getErr := wrc.mutateInterface.Get(t.Context(), "race", metav1.GetOptions{})
					if getErr != nil {
						t.Fatal(getErr)
					}
					name = got.Webhooks[0].Name
				}
				if name != "desired" {
					t.Fatalf("stale webhook survived: %s", name)
				}
			})
		}
	}
}

func TestRunConfigReconciliation_HotReloadRetryAndCancellation(t *testing.T) {
	props, err := varmortls.GetTLSCertProps(&rest.Config{Host: "https://api.test"})
	if err != nil {
		t.Fatal(err)
	}
	_, caPEM, caErr := varmortls.GenerateCACert(time.Hour)
	if caErr != nil {
		t.Fatal(caErr)
	}
	client := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: varmortls.GenerateRootCASecretName(props), Namespace: config.Namespace}, Data: map[string][]byte{varmortls.RootCAKey: caPEM.Certificate}},
		&admissionregistrationapi.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: config.MutatingWebhookConfigurationName, UID: "preserved"}},
	)
	fail := admissionregistrationapi.Fail
	restore := config.SetDynamicConfigForTest(config.DynamicConfig{WorkloadAdapters: map[string]config.WorkloadAdapterConfig{
		"testwidget": {FailurePolicy: &fail},
	}})
	defer restore()
	// Exercise the retry timer without a queued startup config notification.
	for len(config.DynamicConfigChanges()) > 0 {
		<-config.DynamicConfigChanges()
	}
	written := make(chan *admissionregistrationapi.MutatingWebhookConfiguration, 20)
	attempts := 0
	client.PrependReactor("update", "mutatingwebhookconfigurations", func(action clienttesting.Action) (bool, runtime.Object, error) {
		attempts++
		if attempts == 1 {
			return true, nil, fmt.Errorf("temporary API failure")
		}
		written <- action.(clienttesting.UpdateAction).GetObject().(*admissionregistrationapi.MutatingWebhookConfiguration).DeepCopy()
		return false, nil, nil
	})
	r := testRegistry(t)
	wrc := &Register{
		clientConfig:      &rest.Config{Host: "https://api.test"},
		registry:          r,
		adapterDefaults:   newAdapterDefaults(r, logr.Discard()),
		mutateInterface:   client.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		validateInterface: client.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		secretInterface:   client.CoreV1().Secrets(config.Namespace),
		timeoutSeconds:    int32(config.WebhookTimeout), inContainer: true, log: logr.Discard(),
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); wrc.RunConfigReconciliation(ctx) }()
	waitWrite := func(policy admissionregistrationapi.FailurePolicyType, timeout int32) {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case cfg := <-written:
				for _, webhook := range cfg.Webhooks {
					if webhook.Name == adapterWebhookName(newRegisteredFake()) && *webhook.FailurePolicy == policy && *webhook.TimeoutSeconds == timeout {
						if cfg.UID != "preserved" {
							t.Fatal("configuration UID changed")
						}
						return
					}
				}
			case <-deadline.C:
				t.Fatal("leader failed to reconcile latest config")
			}
		}
	}
	waitWrite(fail, 8)
	ignore := admissionregistrationapi.Ignore
	timeout := int32(14)
	undo := config.SetDynamicConfigForTest(config.DynamicConfig{WorkloadAdapters: map[string]config.WorkloadAdapterConfig{
		"testwidget": {FailurePolicy: &ignore, TimeoutSeconds: &timeout},
	}})
	defer undo()
	waitWrite(ignore, timeout)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("leader worker did not stop on cancellation")
	}
}

func TestUpsertMutatingWebhookConfiguration_CreateThenUpdatePreservesUID(t *testing.T) {
	client := fake.NewSimpleClientset()
	wrc := &Register{
		mutateInterface: client.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		log:             logr.Discard(),
	}
	name := "test-mwc"

	// Absent object -> created.
	first := &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks:   []admissionregistrationapi.MutatingWebhook{{Name: "wh-a"}},
	}
	if err := wrc.upsertMutatingWebhookConfiguration(t.Context(), first); err != nil {
		t.Fatalf("first upsert (create): %v", err)
	}

	got, err := wrc.mutateInterface.Get(t.Context(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if len(got.Webhooks) != 1 {
		t.Fatalf("webhooks after create = %d, want 1", len(got.Webhooks))
	}
	createdUID := got.UID

	// Existing object -> updated in place; UID must be preserved (no delete window).
	second := &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"k": "v"}},
		Webhooks:   []admissionregistrationapi.MutatingWebhook{{Name: "wh-a"}, {Name: "wh-b"}},
	}
	if err := wrc.upsertMutatingWebhookConfiguration(t.Context(), second); err != nil {
		t.Fatalf("second upsert (update): %v", err)
	}
	got, err = wrc.mutateInterface.Get(t.Context(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if len(got.Webhooks) != 2 {
		t.Fatalf("webhooks after update = %d, want 2", len(got.Webhooks))
	}
	if got.UID != createdUID {
		t.Errorf("UID changed across reconcile: %q -> %q (object must not be recreated)", createdUID, got.UID)
	}
	if got.Labels["k"] != "v" {
		t.Errorf("labels not reconciled: %+v", got.Labels)
	}
}

func TestUpsertMutatingWebhookConfiguration_RetriesOnConflict(t *testing.T) {
	client := fake.NewSimpleClientset(&admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "conflict-mwc"},
		Webhooks:   []admissionregistrationapi.MutatingWebhook{{Name: "old"}},
	})

	// First Update returns a conflict; the upsert must re-Get and retry.
	conflicted := false
	client.PrependReactor("update", "mutatingwebhookconfigurations", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if !conflicted {
			conflicted = true
			return true, nil, k8errors.NewConflict(
				schema.GroupResource{Resource: "mutatingwebhookconfigurations"},
				"conflict-mwc", fmt.Errorf("simulated optimistic concurrency conflict"))
		}
		return false, nil, nil
	})

	wrc := &Register{
		mutateInterface: client.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		log:             logr.Discard(),
	}
	cfg := &admissionregistrationapi.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "conflict-mwc"},
		Webhooks:   []admissionregistrationapi.MutatingWebhook{{Name: "new"}},
	}
	if err := wrc.upsertMutatingWebhookConfiguration(t.Context(), cfg); err != nil {
		t.Fatalf("upsert with transient conflict should succeed: %v", err)
	}
	if !conflicted {
		t.Fatal("conflict reactor was never triggered")
	}
	got, err := wrc.mutateInterface.Get(t.Context(), "conflict-mwc", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after conflict retry: %v", err)
	}
	if len(got.Webhooks) != 1 || got.Webhooks[0].Name != "new" {
		t.Errorf("webhooks = %+v, want reconciled single entry [new]", got.Webhooks)
	}
}

func TestUpsertValidatingWebhookConfiguration_CreatesWhenAbsent(t *testing.T) {
	client := fake.NewSimpleClientset()
	wrc := &Register{
		validateInterface: client.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		log:               logr.Discard(),
	}
	cfg := &admissionregistrationapi.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-vwc"},
		Webhooks:   []admissionregistrationapi.ValidatingWebhook{{Name: "v"}},
	}
	if err := wrc.upsertValidatingWebhookConfiguration(t.Context(), cfg); err != nil {
		t.Fatalf("upsert validating (create): %v", err)
	}
	got, err := wrc.validateInterface.Get(t.Context(), "test-vwc", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if len(got.Webhooks) != 1 {
		t.Fatalf("validating webhooks = %d, want 1", len(got.Webhooks))
	}
}

func TestUpsertWebhookConfigurations_SkipsUnchanged(t *testing.T) {
	for _, validating := range []bool{false, true} {
		for _, tc := range []struct {
			name          string
			changeDesired func(*admissionregistrationapi.MutatingWebhookConfiguration)
			changeLive    func(*admissionregistrationapi.MutatingWebhookConfiguration)
			wantUpdate    bool
			mutatingOnly  bool
		}{
			{name: "identical"},
			{name: "server defaults", changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				entry := &cfg.Webhooks[0]
				policy := admissionregistrationapi.Equivalent
				scope := admissionregistrationapi.AllScopes
				port := int32(443)
				entry.MatchPolicy = &policy
				entry.NamespaceSelector = &metav1.LabelSelector{}
				entry.ObjectSelector = &metav1.LabelSelector{}
				entry.Rules[0].Scope = &scope
				entry.ClientConfig.Service.Port = &port
			}},
			{name: "optional policy and timeout defaults",
				changeDesired: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
					cfg.Webhooks[0].FailurePolicy = nil
					cfg.Webhooks[0].TimeoutSeconds = nil
					cfg.Webhooks[0].ReinvocationPolicy = nil
				},
				changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
					policy := admissionregistrationapi.Fail
					timeout := int32(config.WebhookTimeout)
					reinvoke := admissionregistrationapi.NeverReinvocationPolicy
					cfg.Webhooks[0].FailurePolicy = &policy
					cfg.Webhooks[0].TimeoutSeconds = &timeout
					cfg.Webhooks[0].ReinvocationPolicy = &reinvoke
				}},
			{name: "empty collections and server metadata", changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Labels = map[string]string{}
				cfg.Annotations = map[string]string{}
				cfg.UID = "preserved"
				cfg.ResourceVersion = "42"
				cfg.Webhooks[0].MatchConditions = []admissionregistrationapi.MatchCondition{}
			}},
			{name: "CA drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Webhooks[0].ClientConfig.CABundle = []byte("old-ca")
			}},
			{name: "timeout drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				timeout := int32(20)
				cfg.Webhooks[0].TimeoutSeconds = &timeout
			}},
			{name: "failure policy drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				policy := admissionregistrationapi.Fail
				cfg.Webhooks[0].FailurePolicy = &policy
			}},
			{name: "condition drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Webhooks[0].MatchConditions = []admissionregistrationapi.MatchCondition{{Name: "stale", Expression: "false"}}
			}},
			{name: "nondefault matching", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				policy := admissionregistrationapi.Exact
				cfg.Webhooks[0].MatchPolicy = &policy
			}},
			{name: "selector drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Webhooks[0].NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"stale": "true"}}
			}},
			{name: "object selector drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Webhooks[0].ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"stale": "true"}}
			}},
			{name: "reinvocation drift", wantUpdate: true, mutatingOnly: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				reinvoke := admissionregistrationapi.IfNeededReinvocationPolicy
				cfg.Webhooks[0].ReinvocationPolicy = &reinvoke
			}},
			{name: "scope drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				scope := admissionregistrationapi.NamespacedScope
				cfg.Webhooks[0].Rules[0].Scope = &scope
			}},
			{name: "port drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				port := int32(8443)
				cfg.Webhooks[0].ClientConfig.Service.Port = &port
			}},
			{name: "label drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Labels = map[string]string{"stale": "true"}
			}},
			{name: "annotation drift", wantUpdate: true, changeLive: func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) {
				cfg.Annotations = map[string]string{"stale": "true"}
			}},
		} {
			if validating && tc.mutatingOnly {
				continue
			}
			t.Run(fmt.Sprintf("validating=%t/%s", validating, tc.name), func(t *testing.T) {
				policy := admissionregistrationapi.Ignore
				sideEffects := admissionregistrationapi.SideEffectClassNone
				reinvoke := admissionregistrationapi.NeverReinvocationPolicy
				timeout := int32(config.WebhookTimeout)
				desired := &admissionregistrationapi.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Webhooks: []admissionregistrationapi.MutatingWebhook{{
						Name: "test.varmor.org",
						ClientConfig: admissionregistrationapi.WebhookClientConfig{
							Service:  &admissionregistrationapi.ServiceReference{Namespace: "default", Name: "webhook"},
							CABundle: []byte("current-ca"),
						},
						Rules: []admissionregistrationapi.RuleWithOperations{{
							Operations: []admissionregistrationapi.OperationType{admissionregistrationapi.Create},
							Rule:       podResourceWebhookRule(),
						}},
						FailurePolicy: &policy, SideEffects: &sideEffects, TimeoutSeconds: &timeout,
						ReinvocationPolicy: &reinvoke, AdmissionReviewVersions: []string{"v1"},
					}},
				}
				if tc.changeDesired != nil {
					tc.changeDesired(desired)
				}
				live := desired.DeepCopy()
				if tc.changeLive != nil {
					tc.changeLive(live)
				}
				// Both v1 webhook types share these JSON fields; validating
				// configurations omit the mutating-only reinvocation policy.
				asValidating := func(cfg *admissionregistrationapi.MutatingWebhookConfiguration) *admissionregistrationapi.ValidatingWebhookConfiguration {
					raw, err := json.Marshal(cfg)
					assert.NoError(t, err)
					result := &admissionregistrationapi.ValidatingWebhookConfiguration{}
					assert.NoError(t, json.Unmarshal(raw, result))
					return result
				}
				var initial runtime.Object = live
				if validating {
					initial = asValidating(live)
				}
				client := fake.NewSimpleClientset(initial)
				wrc := &Register{
					mutateInterface:   client.AdmissionregistrationV1().MutatingWebhookConfigurations(),
					validateInterface: client.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
					log:               logr.Discard(),
				}
				before := desired.DeepCopy()
				upsert := func() error {
					if validating {
						return wrc.upsertValidatingWebhookConfiguration(t.Context(), asValidating(desired))
					}
					return wrc.upsertMutatingWebhookConfiguration(t.Context(), desired)
				}
				assert.NoError(t, upsert())
				assert.NoError(t, upsert(), "a second reconciliation must not write again")
				updates := 0
				for _, action := range client.Actions() {
					if action.GetVerb() == "update" {
						updates++
					}
				}
				wantUpdates := 0
				if tc.wantUpdate {
					wantUpdates = 1
				}
				assert.Equal(t, wantUpdates, updates)
				assert.Equal(t, before, desired, "comparison must not default the caller's object")
			})
		}
	}
}

func TestUpsertWebhookConfigurations_ConflictAlreadyConverged(t *testing.T) {
	for _, validating := range []bool{false, true} {
		t.Run(fmt.Sprintf("validating=%t", validating), func(t *testing.T) {
			resource := "mutatingwebhookconfigurations"
			var live runtime.Object = &admissionregistrationapi.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "converged"},
				Webhooks:   []admissionregistrationapi.MutatingWebhook{{Name: "stale"}},
			}
			if validating {
				resource = "validatingwebhookconfigurations"
				live = &admissionregistrationapi.ValidatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "converged"},
					Webhooks:   []admissionregistrationapi.ValidatingWebhook{{Name: "stale"}},
				}
			}
			client := fake.NewSimpleClientset(live)
			updates := 0
			client.PrependReactor("update", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
				updates++
				// Another writer applies the desired state before this write
				// conflicts. The fresh read should avoid a second Update.
				err := client.Tracker().Update(action.GetResource(), action.(clienttesting.UpdateAction).GetObject(), "")
				if err != nil {
					return true, nil, err
				}
				return true, nil, k8errors.NewConflict(schema.GroupResource{Resource: resource}, "converged", fmt.Errorf("concurrent update"))
			})
			wrc := &Register{
				mutateInterface:   client.AdmissionregistrationV1().MutatingWebhookConfigurations(),
				validateInterface: client.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
				log:               logr.Discard(),
			}
			var err error
			if validating {
				err = wrc.upsertValidatingWebhookConfiguration(t.Context(), &admissionregistrationapi.ValidatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "converged"},
					Webhooks:   []admissionregistrationapi.ValidatingWebhook{{Name: "desired"}},
				})
			} else {
				err = wrc.upsertMutatingWebhookConfiguration(t.Context(), &admissionregistrationapi.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "converged"},
					Webhooks:   []admissionregistrationapi.MutatingWebhook{{Name: "desired"}},
				})
			}
			assert.NoError(t, err)
			assert.Equal(t, 1, updates)
		})
	}
}
