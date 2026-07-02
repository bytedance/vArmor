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

// This file introduces the AuditSinkConfig abstraction that parameterises the
// Envoy gRPC ALS access_log sink used for NetworkProxy violation auditing. It is
// threaded as a parameter through the translation chain (facade -> translator ->
// renderer) so the renderer can embed the per-profile log_name and the agent's
// UDS endpoint without re-plumbing every signature.
//
// NetworkProxy violations always stream over gRPC ALS (Access Log Service) to
// the node-local agent's auditor via a STATIC UDS cluster. The type, constants
// and helper methods follow the shared gRPC ALS protocol so the renderer and the
// agent's auditor stay byte-compatible.

const (
	// DefaultALSClusterName is the CDS cluster name of the gRPC ALS endpoint.
	// It is a fixed, shared convention so the renderer and the agent's
	// auditor stay byte-compatible.
	DefaultALSClusterName = "varmor_audit_als"

	// LogNameClassDeny / LogNameClassAudit are the two log_name classes the
	// renderer embeds (as "<class>:<profileName>") into each gRPC ALS
	// access_log entry. The auditor parses the class to map an event to an
	// action: deny -> DENIED, audit -> AUDIT. This is a shared convention
	// between the renderer and the agent's auditor.
	LogNameClassDeny  = "varmor_np_deny"
	LogNameClassAudit = "varmor_np_audit"

	// ALSFilterChainTagKey is the gRPC ALS custom_tag key whose literal value
	// carries the originating Envoy filter chain name (e.g. "http_chain",
	// "mitm_tls_dns_chain"). The renderer injects it as a literal custom_tag on
	// each L7 access_log entry; the auditor reads it back from
	// AccessLogCommon.custom_tags to attribute the event to its chain. The L4
	// listener-level access_log is shared across the passthrough tls_chain and
	// tcp_default_chain, so no chain tag is emitted there.
	ALSFilterChainTagKey = "filter_chain"
)

// Filter chain names. These are the literal values already used as the
// FilterChain.Name throughout the translator; promoting them to constants
// lets the HCM carry its owning chain name for the gRPC ALS custom_tag
// without re-deriving the string in two places.
const (
	FilterChainNameHTTP       = "http_chain"
	FilterChainNameMITMTLSDNS = "mitm_tls_dns_chain"
	FilterChainNameMITMTLSIP  = "mitm_tls_ip_chain"
	FilterChainNameTLS        = "tls_chain"
	FilterChainNameTCPDefault = "tcp_default_chain"
)

// AuditSinkConfig parameterises the Envoy gRPC ALS access_log sink used for
// NetworkProxy violation auditing.
type AuditSinkConfig struct {
	// ALSClusterName is the CDS cluster name for the gRPC ALS endpoint.
	// Defaults to DefaultALSClusterName when empty.
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
	return DefaultALSClusterName
}

// denyLogName returns the log_name embedded into the deny access_log entry,
// encoded as "<LogNameClassDeny>:<ProfileName>".
func (a AuditSinkConfig) denyLogName() string {
	return LogNameClassDeny + ":" + a.ProfileName
}

// auditLogName returns the log_name embedded into the shadow/audit access_log
// entry, encoded as "<LogNameClassAudit>:<ProfileName>".
func (a AuditSinkConfig) auditLogName() string {
	return LogNameClassAudit + ":" + a.ProfileName
}
