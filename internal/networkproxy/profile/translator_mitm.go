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

// This file contains everything specific to TLS MITM + API-key injection
// (Phase 4). The design constraints are:
//
//  1. The MITM layer reuses Phase 1's audit/deny/allow qualifier semantics
//     (the 10-row matrix) without introducing new audit logic. Access
//     logging happens at the HCM level via the same CEL expressions as
//     the non-MITM HTTP chain.
//
//  2. API-key injection MUST replace any existing header value (policy
//     declared value wins). This is implemented via Envoy's virtual_host
//     request_headers_to_add with append_action=OVERWRITE_IF_EXISTS_OR_ADD,
//     NOT via a separate header_mutation HTTP filter.
//
//  3. One MITM HCM serves ALL MITM domains. Per-domain discrimination is
//     done by :authority-matched virtual_hosts so that distinct API keys
//     can be injected for distinct upstream services.
//
//  4. MITM must support both DNS-named and plain-IP targets. Because
//     Envoy AND-combines server_names and prefix_ranges within a single
//     filter_chain_match, we emit TWO filter chains sharing the same HCM
//     shape:
//       - DNS chain:  filter_chain_match {server_names=[...], transport_protocol=tls}
//       - IP  chain:  filter_chain_match {prefix_ranges=[...], transport_protocol=tls}
//     This is the minimum chain count required to cover both dimensions
//     without sacrificing matching specificity.
//
//  5. Port is intentionally NOT restricted -- any port may carry TLS
//     (e.g., k8s apiserver on 6443). Envoy's tls_inspector listener
//     filter decides whether bytes look like a TLS ClientHello based on
//     content, not port.
//
//  6. The controller resolves SecretRef into literal header values BEFORE
//     calling the translator. The translator never touches the kube-apiserver.

import (
	"fmt"
	"net"
	"sort"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

// ============================================================================
// Public input type
// ============================================================================

// MITMInput carries all MITM-related inputs that the controller has already
// resolved (Secret reads, wildcard/IP split). The translator never performs
// any external lookups, keeping it a pure function.
type MITMInput struct {
	// Domains lists the targets for which TLS should be terminated.
	// Entries may be DNS names (including "*.example.com" wildcards) or
	// IP literals (IPv4/IPv6, with or without a CIDR suffix). An entry
	// is classified as "IP" if it parses as a valid IP/CIDR.
	Domains []string

	// HeadersByDomain maps each MITMConfig.Domains entry to its already
	// resolved list of header injections. The controller reads SecretRef
	// values before calling the translator; the translator receives only
	// literal (Name, Value) pairs.
	//
	// Map keys are the literal strings from MITMConfig.Domains, matching
	// HeaderMutation.Domain exactly (no wildcard expansion).
	HeadersByDomain map[string][]HeaderToAdd

	// LeafCertPath / LeafKeyPath are the in-sidecar file paths where the
	// policy's unified Secret projects the MITM leaf certificate and key.
	// If empty, defaults from internal/config are applied.
	LeafCertPath string
	LeafKeyPath  string
}

// Enabled reports whether a valid, non-empty MITM configuration was supplied.
func (m *MITMInput) Enabled() bool {
	return m != nil && len(m.Domains) > 0
}

// ============================================================================
// Rule classification (shared between MITM and non-MITM paths)
// ============================================================================

// egressClassification is the intermediate result of partitioning egress
// rules into deny/allow/shadow buckets. Produced by classifyEgress and
// consumed by both the Phase 1 chain builders and the MITM chain builders
// so the 10-row audit matrix lives in exactly one place.
type egressClassification struct {
	defaultDeny bool

	denyEgressRules  []varmor.NetworkProxyEgressRule
	allowEgressRules []varmor.NetworkProxyEgressRule

	denyHTTPRules  []varmor.NetworkProxyHTTPRule
	allowHTTPRules []varmor.NetworkProxyHTTPRule

	auditCfg AuditConfig
}

func classifyEgress(egress *varmor.NetworkProxyEgress) egressClassification {
	defaultDeny := strings.EqualFold(egress.DefaultAction, "deny")

	var (
		denyEgressRules        []varmor.NetworkProxyEgressRule
		allowEgressRules       []varmor.NetworkProxyEgressRule
		denyHTTPRules          []varmor.NetworkProxyHTTPRule
		allowHTTPRules         []varmor.NetworkProxyHTTPRule
		auditShadowEgressRules []varmor.NetworkProxyEgressRule
		auditShadowHTTPRules   []varmor.NetworkProxyHTTPRule
	)
	anyAuditQualifier := false

	for _, r := range egress.Rules {
		action, audit := classifyRule(r.Qualifiers, defaultDeny)
		if audit && hasQualifier(r.Qualifiers, "audit") {
			anyAuditQualifier = true
		}
		switch action {
		case ruleActionDeny:
			denyEgressRules = append(denyEgressRules, r)
		case ruleActionAllow:
			allowEgressRules = append(allowEgressRules, r)
		}
		if defaultDeny {
			if action == ruleActionAllow && audit {
				auditShadowEgressRules = append(auditShadowEgressRules, r)
			}
		} else if hasQualifier(r.Qualifiers, "audit") {
			auditShadowEgressRules = append(auditShadowEgressRules, r)
		}
	}

	for _, r := range egress.HTTPRules {
		action, audit := classifyRule(r.Qualifiers, defaultDeny)
		if audit && hasQualifier(r.Qualifiers, "audit") {
			anyAuditQualifier = true
		}
		switch action {
		case ruleActionDeny:
			denyHTTPRules = append(denyHTTPRules, r)
		case ruleActionAllow:
			allowHTTPRules = append(allowHTTPRules, r)
		}
		if defaultDeny {
			if action == ruleActionAllow && audit {
				auditShadowHTTPRules = append(auditShadowHTTPRules, r)
			}
		} else if hasQualifier(r.Qualifiers, "audit") {
			auditShadowHTTPRules = append(auditShadowHTTPRules, r)
		}
	}

	accessLogEnabled := defaultDeny || anyAuditQualifier

	return egressClassification{
		defaultDeny:      defaultDeny,
		denyEgressRules:  denyEgressRules,
		allowEgressRules: allowEgressRules,
		denyHTTPRules:    denyHTTPRules,
		allowHTTPRules:   allowHTTPRules,
		auditCfg: AuditConfig{
			AccessLogEnabled:       accessLogEnabled,
			DefaultDeny:            defaultDeny,
			AuditShadowEgressRules: auditShadowEgressRules,
			AuditShadowHTTPRules:   auditShadowHTTPRules,
		},
	}
}

// ============================================================================
// MITM chain builders
// ============================================================================

// splitMITMDomains partitions Domains into DNS names (including wildcards)
// and IP/CIDR literals. Any entry that parses as a net.IP or CIDR is
// classified as IP; everything else is DNS.
func splitMITMDomains(domains []string) (dnsNames, ipPrefixes []string) {
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		// CIDR first so "10.0.0.0/8" isn't mistaken for a DNS name.
		if _, _, err := net.ParseCIDR(d); err == nil {
			ipPrefixes = append(ipPrefixes, d)
			continue
		}
		if ip := net.ParseIP(d); ip != nil {
			ipPrefixes = append(ipPrefixes, d)
			continue
		}
		dnsNames = append(dnsNames, d)
	}
	return
}

// buildMITMChains emits up to two filter chains: one matching by SNI
// (DNS / wildcard entries) and one matching by destination IP CIDR. Both
// chains share the same downstream TLS context, HCM shape and header
// injection plan -- they differ only in their filter_chain_match.
func buildMITMChains(cls egressClassification, mitm *MITMInput) []FilterChain {
	dnsNames, ipPrefixes := splitMITMDomains(mitm.Domains)

	certPath := mitm.LeafCertPath
	if certPath == "" {
		certPath = varmorconfig.MITMLeafCertPath
	}
	keyPath := mitm.LeafKeyPath
	if keyPath == "" {
		keyPath = varmorconfig.MITMLeafKeyPath
	}
	tlsCtx := &DownstreamTLSContext{CertPath: certPath, KeyPath: keyPath}

	hcmFilter := buildMITMHCMFilter(cls, mitm)

	var chains []FilterChain
	if len(dnsNames) > 0 {
		chains = append(chains, FilterChain{
			Name: "mitm_tls_dns_chain",
			FilterChainMatch: &FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       dnsNames,
			},
			TransportSocket: tlsCtx,
			Filters:         []NetworkFilter{hcmFilter},
		})
	}
	if len(ipPrefixes) > 0 {
		chains = append(chains, FilterChain{
			Name: "mitm_tls_ip_chain",
			FilterChainMatch: &FilterChainMatch{
				TransportProtocol: "tls",
				PrefixRanges:      ipPrefixes,
			},
			TransportSocket: tlsCtx,
			Filters:         []NetworkFilter{hcmFilter},
		})
	}
	return chains
}

// buildMITMHCMFilter constructs the HTTP Connection Manager that runs
// after TLS termination in the MITM chain. It reuses the exact same HTTP
// RBAC filter ordering as the non-MITM HTTP chain (shadow then deny then
// allow then router) so that the 10-row audit semantic matrix applies
// uniformly to plaintext HTTP, MITM'd HTTPS by DNS, and MITM'd HTTPS by IP.
func buildMITMHCMFilter(cls egressClassification, mitm *MITMInput) NetworkFilter {
	var httpFilters []HTTPFilter

	// Shadow RBAC must precede enforcement RBAC: a denied request short-
	// circuits subsequent filters, so shadow metadata would otherwise
	// never be emitted.
	auditShadowRBAC := buildHTTPRBACForHTTP(RBACActionAllow, cls.auditCfg.AuditShadowEgressRules, cls.auditCfg.AuditShadowHTTPRules)
	hasHTTPShadow := auditShadowRBAC != nil
	if hasHTTPShadow {
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{ShadowRules: auditShadowRBAC},
		})
	}

	// Deny HTTP RBAC (applies regardless of defaultAction).
	if denyRBAC := buildHTTPRBACForHTTP(RBACActionDeny, cls.denyEgressRules, cls.denyHTTPRules); denyRBAC != nil {
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{Rules: denyRBAC},
		})
	}

	// Allow HTTP RBAC (only for deny-default).
	if cls.defaultDeny {
		allowRBAC := buildHTTPRBACForHTTP(RBACActionAllow, cls.allowEgressRules, cls.allowHTTPRules)
		if allowRBAC == nil {
			allowRBAC = &RBACRules{Action: RBACActionAllow, Policies: map[string]*RBACPolicy{}}
		}
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{Rules: allowRBAC},
		})
	}

	// Router -- terminal HTTP filter, forwards to the original_dst cluster.
	httpFilters = append(httpFilters, HTTPFilter{
		Name:        "envoy.filters.http.router",
		TypedConfig: nil,
	})

	hcmCEL := computeHCMCEL(cls.auditCfg.DefaultDeny, hasHTTPShadow)

	return NetworkFilter{
		Name: "envoy.filters.network.http_connection_manager",
		TypedConfig: &HTTPConnManagerConfig{
			StatPrefix:       "mitm_outbound",
			HTTPFilters:      httpFilters,
			AccessLogEnabled: cls.auditCfg.AccessLogEnabled,
			AccessLogCEL:     hcmCEL,
			RouteConfig: &RouteConfig{
				Name:         "mitm_route",
				VirtualHosts: buildMITMVirtualHosts(mitm),
			},
		},
	}
}

// buildMITMVirtualHosts produces one virtual_host per MITMConfig.Domains
// entry, plus a catch-all "*" virtual_host as a safety net. Each
// MITM-owned virtual_host carries its per-domain request_headers_to_add
// (OVERWRITE_IF_EXISTS_OR_ADD) so that client-supplied credentials for
// the same header are unconditionally replaced.
//
// Virtual host domains field accepts:
//   - "example.com"           literal host (no port)
//   - "example.com:*"         any port
//   - "1.2.3.4" / "1.2.3.4:*" IP-target hosts
//   - "*.example.com"         wildcard subdomain (Envoy native support)
//
// For each entry we emit both "<domain>" and "<domain>:*" so that
// requests with and without explicit ports hit the same virtual_host.
// For CIDR entries (e.g., "10.0.0.0/24") we skip virtual_host domain
// emission -- :authority cannot carry a CIDR -- and instead merge their
// header rules into the catch-all virtual_host so every request
// intercepted by the IP chain with this CIDR still receives injection.
func buildMITMVirtualHosts(mitm *MITMInput) []VirtualHost {
	var vhosts []VirtualHost

	// Deterministic ordering for test stability.
	sorted := make([]string, len(mitm.Domains))
	copy(sorted, mitm.Domains)
	sort.Strings(sorted)

	// Collect per-domain header rules that cannot be attached to a
	// specific :authority (CIDR entries) so they can fall into the
	// catch-all virtual_host.
	var catchAllHeaders []HeaderToAdd

	for i, d := range sorted {
		headers := mitm.HeadersByDomain[d]

		// CIDR entries: no :authority form, so headers (if any) fall to
		// the catch-all virtual_host.
		if _, _, err := net.ParseCIDR(d); err == nil {
			catchAllHeaders = append(catchAllHeaders, headers...)
			continue
		}

		domains := []string{d}
		// Append ":*" unless the user already wrote an explicit port or
		// the entry is a wildcard form that Envoy parses specially.
		if !strings.Contains(d, ":") && !strings.HasPrefix(d, "*.") {
			domains = append(domains, d+":*")
		}

		vhosts = append(vhosts, VirtualHost{
			Name:                fmt.Sprintf("mitm_vh_%d", i),
			Domains:             domains,
			RequestHeadersToAdd: headers,
			Routes: []Route{{
				Match:  RouteMatch{Prefix: "/"},
				Action: RouteAction{Cluster: mitmUpstreamClusterName},
			}},
		})
	}

	vhosts = append(vhosts, VirtualHost{
		Name:                "mitm_vh_default",
		Domains:             []string{"*"},
		RequestHeadersToAdd: catchAllHeaders,
		Routes: []Route{{
			Match:  RouteMatch{Prefix: "/"},
			Action: RouteAction{Cluster: mitmUpstreamClusterName},
		}},
	})
	return vhosts
}
