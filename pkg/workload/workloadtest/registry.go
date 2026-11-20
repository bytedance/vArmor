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

// Package workloadtest provides shared test doubles and builders for the
// pluggable workload Adapter extension point. It is meant to be imported only
// from _test.go files: because no production package imports it, the Go
// toolchain never links it into a shipped binary.
package workloadtest

import (
	"testing"

	"github.com/bytedance/vArmor/pkg/workload"
	"github.com/bytedance/vArmor/pkg/workload/builtin"
)

// NewRegistry builds an isolated registry containing the four built-in
// adapters plus any caller-supplied extras. A construction failure (a nil
// adapter or a duplicate Name/GVK/bare-Kind) fails the calling test rather
// than returning a half-populated registry. Every call returns a fresh
// registry, so tests neither share nor mutate any process-global state.
//
// Pass a package's own fakes as extras to model a manager binary that has
// additional adapters compiled in.
func NewRegistry(t testing.TB, extras ...workload.Adapter) *workload.Registry {
	t.Helper()
	adapters := append([]workload.Adapter{}, builtin.Adapters()...)
	adapters = append(adapters, extras...)
	r, err := workload.NewRegistry(adapters...)
	if err != nil {
		t.Fatalf("workloadtest.NewRegistry: %v", err)
	}
	return r
}
