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

// Package als holds the wire-level constants of the gRPC ALS (Access Log
// Service) protocol shared between the NetworkProxy profile renderer (which
// embeds them into the generated Envoy config) and the agent's auditor (which
// parses them back out of incoming access-log entries). It is a dependency-free
// leaf package so that pkg/auditor can consume the protocol contract without
// importing any internal/ package.
//
// A change to any value here is a protocol break: the renderer and the auditor
// must stay byte-compatible.
package als

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

// Filter chain names. These are the literal values used as the FilterChain.Name
// throughout the translator; the auditor reports them back via the
// ALSFilterChainTagKey custom_tag, so they are part of the shared protocol.
const (
	FilterChainNameHTTP       = "http_chain"
	FilterChainNameMITMTLSDNS = "mitm_tls_dns_chain"
	FilterChainNameMITMTLSIP  = "mitm_tls_ip_chain"
	FilterChainNameTLS        = "tls_chain"
	FilterChainNameTCPDefault = "tcp_default_chain"
)
