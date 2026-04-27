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
//  3. Each MITM chain gets its OWN HCM with VirtualHosts scoped to the
//     domains that can enter that chain. DNS chain VHs only contain DNS
//     domains; IP chain VHs only contain IP/CIDR domains. This prevents
//     unreachable VirtualHosts (e.g., IP VHs in a DNS-only chain).
//
//  4. MITM must support both DNS-named and plain-IP targets. Because
//     Envoy AND-combines server_names and prefix_ranges within a single
//     filter_chain_match, we emit TWO filter chains with SEPARATE HCMs:
//       - DNS chain:  filter_chain_match {server_names=[...], transport_protocol=tls}
//       - IP  chain:  filter_chain_match {prefix_ranges=[...], transport_protocol=tls}
//     Each HCM carries only the VirtualHosts and RBAC rules relevant to
//     its chain type. This is the minimum chain count required to cover
//     both dimensions without sacrificing matching specificity.
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

// Validate checks that MITMInput contains only supported domain forms.
// In particular, CIDR entries wider than a single host (/32 for IPv4,
// /128 for IPv6) are rejected because they would silently break all TLS
// connections in the range: Envoy terminates TLS but no VirtualHost
// matches the decrypted :authority, resulting in a 404 for every request.
func (m *MITMInput) Validate() error {
	if m == nil {
		return nil
	}
	for _, d := range m.Domains {
		if _, ipNet, err := net.ParseCIDR(d); err == nil {
			ones, bits := ipNet.Mask.Size()
			if !((bits == 32 && ones == 32) || (bits == 128 && ones == 128)) {
				return fmt.Errorf(
					"mitm.domains: CIDR %q has prefix length /%d which is wider than a single host; "+
						"only /32 (IPv4) or /128 (IPv6) CIDRs are allowed for TLS MITM — "+
						"use individual IPs or DNS names instead", d, ones)
			}
		}
	}
	return nil
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

// filterHTTPRulesForDomains returns a copy of httpRules where each rule's
// Match.Hosts is filtered to only contain hosts that are present in the
// given domain set. Rules whose host list becomes empty after filtering
// are dropped entirely. This ensures each MITM chain's RBAC only
// references hosts that can actually reach that chain.
//
// The domainSet should contain the raw domain strings (e.g., "httpbin.org",
// "1.1.1.1", "8.8.4.4/32"). For IP/CIDR domains, we also strip the CIDR
// suffix when matching against httpRule hosts (which don't have /32).
func filterHTTPRulesForDomains(rules []varmor.NetworkProxyHTTPRule, domains []string) []varmor.NetworkProxyHTTPRule {
	// Build a lookup set from domains. For CIDR /32 entries like
	// "8.8.4.4/32", also add the bare IP "8.8.4.4" since httpRule
	// hosts use bare IPs.
	domainSet := make(map[string]bool, len(domains)*2)
	for _, d := range domains {
		domainSet[d] = true
		// For /32 or /128 CIDRs, also register the bare IP
		if ip, ipNet, err := net.ParseCIDR(d); err == nil {
			ones, bits := ipNet.Mask.Size()
			if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
				domainSet[ip.String()] = true
			}
		}
	}

	var filtered []varmor.NetworkProxyHTTPRule
	for _, r := range rules {
		if len(r.Match.Hosts) == 0 {
			// No host constraint: rule applies everywhere, keep it
			filtered = append(filtered, r)
			continue
		}
		var keepHosts []string
		for _, h := range r.Match.Hosts {
			if domainSet[h] {
				keepHosts = append(keepHosts, h)
			}
		}
		if len(keepHosts) == 0 {
			continue // All hosts filtered out, skip this rule
		}
		// Deep copy the rule with filtered hosts
		rCopy := r
		rCopy.Match.Hosts = keepHosts
		filtered = append(filtered, rCopy)
	}
	return filtered
}
// filterEgressRulesForDomains returns a copy of egressRules where each rule's
// IP or CIDR is checked against the given domain set. Rules whose IP/CIDR is
// not present in the domain set are dropped. This ensures each MITM chain's
// RBAC only references L4 destinations that can actually reach that chain.
//
// Matching logic:
//   - Bare IP rule ("1.1.1.1") matches domain "1.1.1.1" or "1.1.1.1/32"
//   - CIDR rule ("8.8.8.8/32") matches domain "8.8.8.8/32" or bare "8.8.8.8"
//   - Rules with no IP/CIDR are kept (they apply everywhere)
func filterEgressRulesForDomains(rules []varmor.NetworkProxyEgressRule, domains []string) []varmor.NetworkProxyEgressRule {
	domainSet := make(map[string]bool, len(domains)*2)
	for _, d := range domains {
		domainSet[d] = true
		// For bare IPs, also add /32 (or /128) so CIDR rules can match
		if ip := net.ParseIP(d); ip != nil {
			if ip.To4() != nil {
				domainSet[d+"/32"] = true
			} else {
				domainSet[d+"/128"] = true
			}
		}
		// For /32 or /128 CIDRs, also register the bare IP
		if ip, ipNet, err := net.ParseCIDR(d); err == nil {
			ones, bits := ipNet.Mask.Size()
			if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
				domainSet[ip.String()] = true
			}
		}
	}

	var filtered []varmor.NetworkProxyEgressRule
	for _, r := range rules {
		if r.IP == "" && r.CIDR == "" {
			// No IP/CIDR constraint: rule applies everywhere, keep it
			filtered = append(filtered, r)
			continue
		}
		key := r.IP
		if key == "" {
			key = r.CIDR
		}
		if domainSet[key] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// buildMITMChains emits up to two filter chains: one matching by SNI
// (DNS / wildcard entries) and one matching by destination IP CIDR.
// Each chain gets its OWN HCM with VirtualHosts and RBAC rules scoped
// to the domains that can actually enter that chain. A DNS chain only
// carries DNS-type VHs/RBAC; an IP chain only carries IP-type VHs/RBAC.
// Sharing a single HCM between both chains would produce unreachable
// VirtualHosts and RBAC rules (e.g., IP VHs in a DNS chain that only
// matches by server_names).
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

	var chains []FilterChain
	if len(dnsNames) > 0 {
		dnsHCM := buildMITMHCMFilter(cls, dnsNames, mitm.HeadersByDomain)
		chains = append(chains, FilterChain{
			Name: "mitm_tls_dns_chain",
			FilterChainMatch: &FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       dnsNames,
			},
			TransportSocket: tlsCtx,
			Filters:         []NetworkFilter{dnsHCM},
		})
	}
	if len(ipPrefixes) > 0 {
		ipHCM := buildMITMHCMFilter(cls, ipPrefixes, mitm.HeadersByDomain)
		chains = append(chains, FilterChain{
			Name: "mitm_tls_ip_chain",
			FilterChainMatch: &FilterChainMatch{
				TransportProtocol: "tls",
				PrefixRanges:      ipPrefixes,
			},
			TransportSocket: tlsCtx,
			Filters:         []NetworkFilter{ipHCM},
		})
	}
	return chains
}

// buildMITMHCMFilter constructs the HTTP Connection Manager that runs
// after TLS termination in the MITM chain. It reuses the exact same HTTP
// RBAC filter ordering as the non-MITM HTTP chain (shadow then deny then
// allow then router) so that the 10-row audit semantic matrix applies
// uniformly to plaintext HTTP, MITM'd HTTPS by DNS, and MITM'd HTTPS by IP.
func buildMITMHCMFilter(cls egressClassification, domains []string, headersByDomain map[string][]HeaderToAdd) NetworkFilter {
	// Filter both HTTP rules and L4 egress rules to only contain entries
	// reachable via this chain. Without this, an egress rule for a CIDR
	// not in mitm.domains (e.g., 10.0.0.0/24) would leak into the MITM
	// chain's RBAC, allowing traffic that should only be handled by the
	// passthrough tls_chain.
	chainAllowHTTPRules := filterHTTPRulesForDomains(cls.allowHTTPRules, domains)
	chainDenyHTTPRules := filterHTTPRulesForDomains(cls.denyHTTPRules, domains)
	chainAuditShadowHTTPRules := filterHTTPRulesForDomains(cls.auditCfg.AuditShadowHTTPRules, domains)
	chainAllowEgressRules := filterEgressRulesForDomains(cls.allowEgressRules, domains)
	chainDenyEgressRules := filterEgressRulesForDomains(cls.denyEgressRules, domains)
	chainAuditShadowEgressRules := filterEgressRulesForDomains(cls.auditCfg.AuditShadowEgressRules, domains)

	var httpFilters []HTTPFilter

	// Shadow RBAC must precede enforcement RBAC: a denied request short-
	// circuits subsequent filters, so shadow metadata would otherwise
	// never be emitted.
	auditShadowRBAC := buildHTTPRBACForHTTP(RBACActionAllow, chainAuditShadowEgressRules, chainAuditShadowHTTPRules)
	hasHTTPShadow := auditShadowRBAC != nil
	if hasHTTPShadow {
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{ShadowRules: auditShadowRBAC},
		})
	}

	// Deny HTTP RBAC (applies regardless of defaultAction).
	if denyRBAC := buildHTTPRBACForHTTP(RBACActionDeny, chainDenyEgressRules, chainDenyHTTPRules); denyRBAC != nil {
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{Rules: denyRBAC},
		})
	}

	// Allow HTTP RBAC (only for deny-default).
	if cls.defaultDeny {
		allowRBAC := buildHTTPRBACForHTTP(RBACActionAllow, chainAllowEgressRules, chainAllowHTTPRules)
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

	hcmDenyCEL, hcmShadowCEL := computeHCMCELs(cls.auditCfg.DefaultDeny, hasHTTPShadow)

	return NetworkFilter{
		Name: "envoy.filters.network.http_connection_manager",
		TypedConfig: &HTTPConnManagerConfig{
			StatPrefix:       "mitm_outbound",
			HTTPFilters:      httpFilters,
			AccessLogEnabled:   cls.auditCfg.AccessLogEnabled,
			AccessLogDenyCEL:   hcmDenyCEL,
			AccessLogShadowCEL: hcmShadowCEL,
			RouteConfig: &RouteConfig{
				Name:         "mitm_route",
				VirtualHosts: buildMITMVirtualHosts(domains, headersByDomain),
			},
		},
	}
}

// buildMITMVirtualHosts produces one virtual_host per MITMConfig.Domains
// entry. There is deliberately NO catch-all ("*") virtual_host: this is
// the anti-domain-fronting defence. If a request enters the MITM chain
// via SNI but its decrypted :authority header does not match any MITM
// domain, Envoy's HCM finds no matching VirtualHost and returns 404
// before the Router executes — so no header injection occurs and the
// request is never forwarded to the upstream.
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
// emission — :authority cannot carry a CIDR, and traffic intercepted
// by the IP chain will have the real upstream IP as :authority, so we
// emit a VirtualHost matching that IP directly.
func buildMITMVirtualHosts(domains []string, headersByDomain map[string][]HeaderToAdd) []VirtualHost {
	var vhosts []VirtualHost

	// Deterministic ordering for test stability.
	sorted := make([]string, len(domains))
	copy(sorted, domains)
	sort.Strings(sorted)

	for i, d := range sorted {
		headers := headersByDomain[d]

		// CIDR entries: expand to per-IP virtual_host. :authority will
		// be the literal IP, so we match on it. For a /32 or /128 the
		// VH domain is just the IP; for wider CIDRs we cannot predict
		// the exact :authority, so we skip VH creation (the request
		// will get 404 — the user should use individual IPs or DNS
		// names for header injection targets).
		if _, ipNet, err := net.ParseCIDR(d); err == nil {
			ones, bits := ipNet.Mask.Size()
			if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
				// Single-host CIDR (/32 or /128): emit a VH matching the IP
				ip := ipNet.IP.String()
				vhosts = append(vhosts, VirtualHost{
					Name:                fmt.Sprintf("mitm_vh_%d", i),
					Domains:             []string{ip, ip + ":*"},
					RequestHeadersToAdd: headers,
					Routes: []Route{{
						Match:  RouteMatch{Prefix: "/"},
						Action: RouteAction{Cluster: mitmUpstreamClusterName, Timeout: "0s"},
					}},
				})
			}
			// For wider CIDRs, no VH is emitted. The IP chain's
			// filter_chain_match.prefix_ranges still intercepts the
			// traffic, but without a matching VH the HCM returns 404.
			// This is the safe default: CIDR ranges should be used
			// for deny/audit RBAC, not for header injection.
			continue
		}

		// Bare IP (without CIDR notation): emit VH matching the IP.
		if ip := net.ParseIP(d); ip != nil {
			vhosts = append(vhosts, VirtualHost{
				Name:                fmt.Sprintf("mitm_vh_%d", i),
				Domains:             []string{d, d + ":*"},
				RequestHeadersToAdd: headers,
				Routes: []Route{{
					Match:  RouteMatch{Prefix: "/"},
					Action: RouteAction{Cluster: mitmUpstreamClusterName, Timeout: "0s"},
				}},
			})
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
				Action: RouteAction{Cluster: mitmUpstreamClusterName, Timeout: "0s"},
			}},
		})
	}

	return vhosts
}

// ============================================================================
// Dead-rule filtering for tls_chain
// ============================================================================
//
// When MITM is enabled, Envoy's most-specific-match algorithm ensures that
// TLS traffic to MITM domains NEVER reaches tls_chain:
//   - DNS domains/wildcards: mitm_tls_dns_chain's server_names match is
//     more specific than tls_chain's bare transport_protocol="tls".
//   - IP /32 and bare IPs: mitm_tls_ip_chain's prefix_ranges match is
//     a higher-priority layer than transport_protocol.
//
// Consequently, any RBAC rules for these targets in tls_chain are dead code.
// The functions below filter them out to keep the generated config clean.

// buildMITMDomainSet constructs a lookup set from MITM domains for dead-rule
// filtering. It normalises bare IPs and /32 CIDRs so that both forms can be
// looked up uniformly.
//
// Returns:
//   - dnsSet:  exact DNS names and wildcard patterns (e.g., "api.openai.com", "*.openai.com")
//   - ipSet:   normalised IPs (e.g., "1.1.1.1", "8.8.8.8") — bare IP and /32 both map here
func buildMITMDomainSet(domains []string) (dnsSet map[string]bool, ipSet map[string]bool) {
	dnsSet = make(map[string]bool)
	ipSet = make(map[string]bool)
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		// /32 or /128 CIDR → register the bare IP
		if ip, ipNet, err := net.ParseCIDR(d); err == nil {
			ones, bits := ipNet.Mask.Size()
			if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
				ipSet[ip.String()] = true
			}
			continue
		}
		// Bare IP literal
		if ip := net.ParseIP(d); ip != nil {
			ipSet[ip.String()] = true
			continue
		}
		// DNS name (exact or wildcard)
		dnsSet[d] = true
	}
	return
}

// filterEgressRulesForTLSChain removes egress rules whose IP or /32 CIDR
// target is covered by a MITM domain. These rules would be dead in tls_chain
// because mitm_tls_ip_chain's prefix_ranges steals all TLS traffic to that IP.
//
// Rules with no IP/CIDR, or with a CIDR wider than /32, are kept.
func filterEgressRulesForTLSChain(rules []varmor.NetworkProxyEgressRule, ipSet map[string]bool) []varmor.NetworkProxyEgressRule {
	if len(ipSet) == 0 {
		return rules
	}
	var kept []varmor.NetworkProxyEgressRule
	for _, r := range rules {
		if r.IP != "" {
			if ipSet[r.IP] {
				continue // dead rule: MITM IP chain steals this traffic
			}
		}
		if r.CIDR != "" {
			if ip, ipNet, err := net.ParseCIDR(r.CIDR); err == nil {
				ones, bits := ipNet.Mask.Size()
				if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
					if ipSet[ip.String()] {
						continue // dead rule: /32 CIDR matches MITM IP
					}
				}
			}
		}
		kept = append(kept, r)
	}
	return kept
}

// filterHTTPRulesForTLSChain removes HTTP rules whose hosts are entirely
// covered by MITM domains. In tls_chain, HTTP rules become SNI-based RBAC
// (via httpRuleToSNIPermissions). When ALL hosts of a rule are MITM targets,
// the corresponding SNI traffic is handled by MITM chains, making the
// tls_chain rule dead.
//
// If a rule has a mix of MITM and non-MITM hosts, only the MITM hosts are
// removed; the rule is kept with the remaining hosts. If the rule has no
// hosts (applies globally), it is kept as-is.
func filterHTTPRulesForTLSChain(rules []varmor.NetworkProxyHTTPRule, dnsSet map[string]bool, ipSet map[string]bool) []varmor.NetworkProxyHTTPRule {
	if len(dnsSet) == 0 && len(ipSet) == 0 {
		return rules
	}
	var kept []varmor.NetworkProxyHTTPRule
	for _, r := range rules {
		if len(r.Match.Hosts) == 0 {
			// No host constraint: applies globally, keep it
			kept = append(kept, r)
			continue
		}
		var keepHosts []string
		for _, h := range r.Match.Hosts {
			// Check if this host is a MITM target
			if dnsSet[h] {
				continue // exact DNS or wildcard DNS match
			}
			// Check if host is an IP that matches MITM IP set
			if ip := net.ParseIP(h); ip != nil {
				if ipSet[ip.String()] {
					continue
				}
			}
			keepHosts = append(keepHosts, h)
		}
		if len(keepHosts) == 0 {
			continue // all hosts are MITM targets, entire rule is dead
		}
		rCopy := r
		rCopy.Match.Hosts = keepHosts
		kept = append(kept, rCopy)
	}
	return kept
}
