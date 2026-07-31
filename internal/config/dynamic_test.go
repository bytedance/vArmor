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
	"testing"

	"github.com/go-logr/logr"
	"gotest.tools/assert"
)

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
	cfg := parseDynamicConfig(raw, logr.Discard())
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

	empty := parseDynamicConfig("", logr.Discard())
	assert.DeepEqual(t, empty, def)

	bad := parseDynamicConfig("microVMDetection: [this is not a map", logr.Discard())
	assert.DeepEqual(t, bad, def)
}
