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

package workloadtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/bytedance/vArmor/pkg/workload"
)

func TestNewRegistry_BuiltinsAndExtras(t *testing.T) {
	base := NewRegistry(t)
	assert.Len(t, base.List(), 4, "built-in adapters only")

	extra := FakeAdapter{
		AdapterName: "widget",
		AdapterGVK:  schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Widget"},
		AdapterGVR:  schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"},
	}
	withExtra := NewRegistry(t, extra)
	assert.Len(t, withExtra.List(), 5)

	got, ok := withExtra.LookupByKind("Widget")
	assert.True(t, ok)
	assert.Equal(t, "widget", got.Name())

	// Each call yields an independent registry; mutating one must not be
	// possible through the other since the registry is immutable post-build.
	assert.False(t, base.IsRegisteredKind("Widget"))
}

func TestFakeAdapter_IdentityAndOptions(t *testing.T) {
	opts := workload.WebhookOptions{TimeoutSeconds: 9}
	f := FakeAdapter{
		AdapterName: "x",
		AdapterGVK:  schema.GroupVersionKind{Group: "g.io", Version: "v1", Kind: "K"},
		AdapterGVR:  schema.GroupVersionResource{Group: "g.io", Version: "v1", Resource: "ks"},
		Options:     opts,
	}

	assert.Equal(t, "x", f.Name())
	assert.Equal(t, "K", f.GVK().Kind)
	assert.Equal(t, "ks", f.GVR().Resource)

	refs, err := f.PodTemplates(nil)
	assert.NoError(t, err)
	assert.Empty(t, refs)
	assert.Equal(t, int32(9), f.DefaultWebhookOptions().TimeoutSeconds)
}
