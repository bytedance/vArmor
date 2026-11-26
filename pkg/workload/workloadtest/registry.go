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
// toolchain never links it into a shipped binary. The lower-level FakeAdapter
// double intentionally lives in the parent workload package instead, since
// that package's own in-package tests construct it; FakeAdapter is therefore
// compiled into the shipped package even though only tests use it.
package workloadtest

import (
	"testing"

	"github.com/bytedance/vArmor/pkg/workload"
)

// NewRegistry builds an isolated registry of caller-supplied custom
// adapters; built-in kinds use hard-coded dispatch and never enter it. Any
// registry construction error fails the calling test. Every call returns a
// fresh registry, so tests share no process-global state.
//
// With no extras the result is an empty registry, modelling a binary
// compiled without custom adapters.
func NewRegistry(t testing.TB, extras ...workload.Adapter) *workload.Registry {
	t.Helper()
	r, err := workload.NewRegistry(extras...)
	if err != nil {
		t.Fatalf("workloadtest.NewRegistry: %v", err)
	}
	return r
}
