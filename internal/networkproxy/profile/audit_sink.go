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

package profile

import (
	als "github.com/bytedance/vArmor/pkg/networkproxy/als"
)

// This file introduces the AuditSinkConfig abstraction that parameterises the
// Envoy gRPC ALS access_log sink used for NetworkProxy violation auditing. It is
// threaded as a parameter through the translation chain (facade -> translator ->
// renderer) so the renderer can embed the per-profile log_name and the agent's
// UDS endpoint without re-plumbing every signature.
//
// NetworkProxy violations always stream over gRPC ALS (Access Log Service) to
// the node-local agent's auditor via a STATIC UDS cluster. The wire-level
// constants of that protocol live in the dependency-free pkg/networkproxy/als
// leaf package so the renderer and the agent's auditor stay byte-compatible
// without the auditor importing any internal/ package.

// AuditSinkConfig parameterises the Envoy gRPC ALS access_log sink used for
// NetworkProxy violation auditing.
type AuditSinkConfig struct {
	// ALSClusterName is the CDS cluster name for the gRPC ALS endpoint.
	// Defaults to als.DefaultALSClusterName when empty.
	ALSClusterName string
	// ALSUDSPath is the UDS pipe path (inside the sidecar) the ALS cluster
	// dials.
	ALSUDSPath string
	// ProfileName is the armor profile name embedded into each log_name as
	// "<class>:<profileName>" so the auditor can attribute events to a
	// profile.
	ProfileName string
	// ALSBufferFlushInterval bounds how long Envoy buffers access-log entries
	// before flushing them to the agent's ALS server (e.g. "1s"). An empty
	// value omits the field so Envoy applies its own default.
	ALSBufferFlushInterval string
	// ALSBufferSizeBytes bounds the sidecar's in-memory access-log buffer so
	// audit load can never back-pressure egress forwarding: once exceeded
	// Envoy flushes (or drops) rather than growing without bound. A zero
	// value omits the field.
	ALSBufferSizeBytes uint32
}

// clusterName returns the effective ALS cluster name, applying the default
// when ALSClusterName is empty.
func (a AuditSinkConfig) clusterName() string {
	if a.ALSClusterName != "" {
		return a.ALSClusterName
	}
	return als.DefaultALSClusterName
}

// denyLogName returns the log_name embedded into the deny access_log entry,
// encoded as "<als.LogNameClassDeny>:<ProfileName>".
func (a AuditSinkConfig) denyLogName() string {
	return als.LogNameClassDeny + ":" + a.ProfileName
}

// auditLogName returns the log_name embedded into the shadow/audit access_log
// entry, encoded as "<als.LogNameClassAudit>:<ProfileName>".
func (a AuditSinkConfig) auditLogName() string {
	return als.LogNameClassAudit + ":" + a.ProfileName
}
