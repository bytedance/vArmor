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

package networkproxy

import (
	"fmt"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

// ============================================================================
// Envoy xDS structure types (simplified for YAML generation)
// ============================================================================

// FilterChain represents one Envoy filter chain.
type FilterChain struct {
	Name             string
	FilterChainMatch *FilterChainMatch
	Filters          []NetworkFilter
}

// FilterChainMatch defines the match criteria for a filter chain.
type FilterChainMatch struct {
	TransportProtocol    string
	ApplicationProtocols []string
}

// NetworkFilter represents a network-level filter in a chain.
type NetworkFilter struct {
	Name        string
	TypedConfig interface{}
}

// TCPProxyConfig represents tcp_proxy filter configuration.
type TCPProxyConfig struct {
	StatPrefix string
	Cluster    string
	// Note: tcp_proxy access_log is no longer rendered in v4 (all-CEL architecture).
	// All audit logging is handled at listener-level and HCM-level via CEL.
}

// ============================================================================
// RBAC types
// ============================================================================

type RBACAction string

const (
	RBACActionAllow RBACAction = "ALLOW"
	RBACActionDeny  RBACAction = "DENY"
	RBACActionLog   RBACAction = "LOG"
)

type RBACConfig struct {
	StatPrefix  string
	Rules       *RBACRules `json:"rules,omitempty"`
	ShadowRules *RBACRules `json:"shadow_rules,omitempty"`
}

type RBACRules struct {
	Action   RBACAction
	Policies map[string]*RBACPolicy
}

type RBACPolicy struct {
	Permissions []Permission
	Principals  []Principal
}

type Permission struct {
	AndRules []PermissionRule
}

type PermissionRule struct {
	Type  string
	Value interface{}
}

type Principal struct {
	Any bool
}

type HTTPFilter struct {
	Name        string
	TypedConfig interface{}
}

type HTTPConnManagerConfig struct {
	StatPrefix       string
	HTTPFilters      []HTTPFilter
	RouteConfig      *RouteConfig
	AccessLogEnabled bool
	// AccessLogCEL is the pre-computed CEL expression for HCM access_log filtering.
	// Empty string means no access_log should be rendered.
	// Possible values:
	//   - celHCMDenyOrShadow: deny-default with shadow rules
	//   - celHCMDeny: deny-default without shadow rules
	//   - celHCMShadow: allow-default with shadow rules
	//   - "": allow-default without shadow rules (no access_log)
	AccessLogCEL string
}

type RouteConfig struct {
	Name         string
	VirtualHosts []VirtualHost
}

type VirtualHost struct {
	Name    string
	Domains []string
	Routes  []Route
}

type Route struct {
	Match  RouteMatch
	Action RouteAction
}

type RouteMatch struct {
	Prefix string
}

type RouteAction struct {
	Cluster string
}

// ============================================================================
// Constants
// ============================================================================

const (
	clusterName = "original_dst"
	listenPort  = 15001
)

// ============================================================================
// Qualifier helpers
// ============================================================================

func hasQualifier(qualifiers []string, q string) bool {
	for _, v := range qualifiers {
		if v == q {
			return true
		}
	}
	return false
}

// ruleAction represents the effective action of a rule.
type ruleAction string

const (
	ruleActionAllow ruleAction = "allow"
	ruleActionDeny  ruleAction = "deny"
)

// classifyRule determines the effective action and audit flag for a rule
// based on its qualifiers and the default action.
//
// Rules:
//   - Explicit "allow" → allow, explicit "deny" → deny, neither → follows defaultAction
//   - defaultAction=deny: ALL deny actions are auto-audited. allow is NOT audited unless "audit" present.
//   - defaultAction=allow: deny is NOT audited unless "audit" present. "audit" alone = allow+audit.
func classifyRule(qualifiers []string, defaultDeny bool) (action ruleAction, audit bool) {
	hasAllow := hasQualifier(qualifiers, "allow")
	hasDeny := hasQualifier(qualifiers, "deny")
	hasAudit := hasQualifier(qualifiers, "audit")

	if hasAllow {
		action = ruleActionAllow
	} else if hasDeny {
		action = ruleActionDeny
	} else if defaultDeny {
		action = ruleActionDeny
	} else {
		action = ruleActionAllow
	}

	if hasAudit {
		audit = true
	} else if defaultDeny && action == ruleActionDeny {
		audit = true // all denies auto-audited in deny-default
	}
	return
}

// ============================================================================
// Domain matching helpers
// ============================================================================

func isWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

func wildcardToSuffix(domain string) string {
	return domain[1:] // "*.openai.com" -> ".openai.com"
}

// ============================================================================
// AuditConfig carries audit-related information to chain builders.
// ============================================================================

// AuditConfig holds audit configuration computed during rule classification.
type AuditConfig struct {
	// AccessLogEnabled indicates whether access_log should be rendered.
	// True when defaultAction=deny (always) or when any rule has audit qualifier.
	AccessLogEnabled bool
	// DefaultDeny determines the access_log filter strategy.
	DefaultDeny bool
	// AuditShadowEgressRules are egress rules that need shadow_rules for audit metadata.
	// For deny-default: only allow+audit rules (deny is auto-captured by CEL deny detection).
	// For allow-default: all rules with explicit "audit" qualifier.
	AuditShadowEgressRules []varmor.NetworkProxyEgressRule
	// AuditShadowHTTPRules are HTTP rules that need shadow_rules for audit metadata.
	AuditShadowHTTPRules []varmor.NetworkProxyHTTPRule
}

// HasShadowRules returns true if there are any shadow rules to generate.
func (a *AuditConfig) HasShadowRules() bool {
	return len(a.AuditShadowEgressRules) > 0 || len(a.AuditShadowHTTPRules) > 0
}

// HasShadowEgressRules returns true if there are shadow egress rules.
func (a *AuditConfig) HasShadowEgressRules() bool {
	return len(a.AuditShadowEgressRules) > 0
}

// HasShadowHTTPRules returns true if there are shadow HTTP rules.
func (a *AuditConfig) HasShadowHTTPRules() bool {
	return len(a.AuditShadowHTTPRules) > 0
}

// ============================================================================
// CEL Expression Selection
// ============================================================================

// computeListenerCEL returns the CEL expression for listener-level access_log.
// Returns empty string if no listener access_log is needed.
func computeListenerCEL(defaultDeny bool, hasShadowEgressRules bool) string {
	if defaultDeny && hasShadowEgressRules {
		return celListenerDenyOrShadow
	} else if defaultDeny {
		return celListenerDeny
	} else if hasShadowEgressRules {
		return celListenerShadow
	}
	return ""
}

// computeHCMCEL returns the CEL expression for HCM-level access_log.
// Returns empty string if no HCM access_log is needed.
func computeHCMCEL(defaultDeny bool, hasShadowRules bool) string {
	if defaultDeny && hasShadowRules {
		return celHCMDenyOrShadow
	} else if defaultDeny {
		return celHCMDeny
	} else if hasShadowRules {
		return celHCMShadow
	}
	return ""
}

// ============================================================================
// Core Translator
// ============================================================================

type TranslateResult struct {
	LDS string
	CDS string
}

// TranslateEgressRules converts varmor.NetworkProxyEgress CRD rules into Envoy xDS configuration.
func TranslateEgressRules(egress *varmor.NetworkProxyEgress, version int64, proxyPort uint16) (*TranslateResult, error) {
	if egress == nil {
		return nil, fmt.Errorf("network proxy egress rules is nil")
	}

	defaultDeny := strings.ToLower(egress.DefaultAction) == "deny"

	// Classify rules into buckets
	var (
		denyEgressRules  []varmor.NetworkProxyEgressRule
		allowEgressRules []varmor.NetworkProxyEgressRule

		denyHTTPRules  []varmor.NetworkProxyHTTPRule
		allowHTTPRules []varmor.NetworkProxyHTTPRule

		// Shadow rules for audit: computed differently based on defaultAction
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

		// Shadow rules computation differs by defaultAction:
		// deny-default: only allow+audit needs shadow (deny is auto-captured by CEL deny detection)
		// allow-default: all rules with explicit "audit" qualifier need shadow
		if defaultDeny {
			if action == ruleActionAllow && audit {
				auditShadowEgressRules = append(auditShadowEgressRules, r)
			}
		} else {
			if hasQualifier(r.Qualifiers, "audit") {
				auditShadowEgressRules = append(auditShadowEgressRules, r)
			}
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

		// Shadow rules computation
		if defaultDeny {
			if action == ruleActionAllow && audit {
				auditShadowHTTPRules = append(auditShadowHTTPRules, r)
			}
		} else {
			if hasQualifier(r.Qualifiers, "audit") {
				auditShadowHTTPRules = append(auditShadowHTTPRules, r)
			}
		}
	}

	// Compute accessLogEnabled:
	// - defaultAction=deny: always (to capture auto-audited denies)
	// - defaultAction=allow: only if any rule has explicit "audit" qualifier
	accessLogEnabled := defaultDeny || anyAuditQualifier

	auditCfg := AuditConfig{
		AccessLogEnabled:       accessLogEnabled,
		DefaultDeny:            defaultDeny,
		AuditShadowEgressRules: auditShadowEgressRules,
		AuditShadowHTTPRules:   auditShadowHTTPRules,
	}

	// Build 3 filter chains
	tlsChain := buildTLSChain(defaultDeny, denyEgressRules, allowEgressRules, denyHTTPRules, allowHTTPRules, auditCfg)
	httpChain := buildHTTPChain(defaultDeny, denyEgressRules, allowEgressRules, denyHTTPRules, allowHTTPRules, auditCfg)
	tcpChain := buildTCPDefaultChain(defaultDeny, denyEgressRules, allowEgressRules, auditCfg)

	// Compute listener-level CEL expression.
	// The listener CEL checks connection.termination_details (set by Network RBAC)
	// and/or network RBAC shadow metadata.
	//
	// Note: hasShadowEgressRules is used (not HasShadowRules) because the listener
	// uses envoy.filters.network.rbac namespace. HTTP shadow rules are handled at HCM level.
	// However, for TLS chain, HTTP rules generate SNI-based network RBAC shadow rules too,
	// so we check both egress and HTTP shadow rules for the TLS chain.
	hasShadowForListener := auditCfg.HasShadowRules()
	listenerCEL := computeListenerCEL(defaultDeny, hasShadowForListener)

	lds := renderListenerYAML(tlsChain, httpChain, tcpChain, version, proxyPort, accessLogEnabled, listenerCEL)
	cds := renderClustersYAML(version)

	return &TranslateResult{
		LDS: lds,
		CDS: cds,
	}, nil
}

// ============================================================================
// Chain 1: TLS
// ============================================================================

func buildTLSChain(defaultDeny bool,
	denyEgressRules, allowEgressRules []varmor.NetworkProxyEgressRule,
	denyHTTPRules, allowHTTPRules []varmor.NetworkProxyHTTPRule,
	auditCfg AuditConfig,
) FilterChain {
	chain := FilterChain{
		Name: "tls_chain",
		FilterChainMatch: &FilterChainMatch{
			TransportProtocol: "tls",
		},
	}

	// Shadow RBAC must be placed before enforcement RBAC in the network filter chain.
	// If enforcement RBAC denies a connection, subsequent network filters won't execute,
	// so shadow metadata would never be written. Same reasoning as the HTTP chain.
	auditShadowRBAC := buildNetworkRBACForTLS(RBACActionAllow, auditCfg.AuditShadowEgressRules, auditCfg.AuditShadowHTTPRules)
	if auditShadowRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix:  "tls_audit_rbac",
				ShadowRules: auditShadowRBAC,
			},
		})
	}

	// Deny RBAC
	denyRBAC := buildNetworkRBACForTLS(RBACActionDeny, denyEgressRules, denyHTTPRules)
	if denyRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix: "tls_deny_rbac",
				Rules:      denyRBAC,
			},
		})
	}

	// Allow RBAC (only when defaultAction=deny)
	if defaultDeny {
		allowRBAC := buildNetworkRBACForTLS(RBACActionAllow, allowEgressRules, allowHTTPRules)
		if allowRBAC != nil {
			chain.Filters = append(chain.Filters, NetworkFilter{
				Name: "envoy.filters.network.rbac",
				TypedConfig: &RBACConfig{
					StatPrefix: "tls_allow_rbac",
					Rules:      allowRBAC,
				},
			})
		}
	}

	// tcp_proxy → original_dst cluster (no access_log — handled at listener level)
	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.tcp_proxy",
		TypedConfig: &TCPProxyConfig{
			StatPrefix: "tls_passthrough",
			Cluster:    clusterName,
		},
	})

	return chain
}

func buildNetworkRBACForTLS(action RBACAction, egressRules []varmor.NetworkProxyEgressRule, httpRules []varmor.NetworkProxyHTTPRule) *RBACRules {
	policies := make(map[string]*RBACPolicy)
	idx := 0

	for _, r := range egressRules {
		perms := egressRuleToNetworkPermissions(r)
		if len(perms) == 0 {
			continue
		}
		policies[fmt.Sprintf("egress_%d", idx)] = &RBACPolicy{
			Permissions: perms,
			Principals:  []Principal{{Any: true}},
		}
		idx++
	}

	for _, r := range httpRules {
		perms := httpRuleToSNIPermissions(r)
		if len(perms) == 0 {
			continue
		}
		policies[fmt.Sprintf("http_%d", idx)] = &RBACPolicy{
			Permissions: perms,
			Principals:  []Principal{{Any: true}},
		}
		idx++
	}

	if len(policies) == 0 {
		return nil
	}

	return &RBACRules{
		Action:   action,
		Policies: policies,
	}
}

// ============================================================================
// Chain 2: HTTP
// ============================================================================

func buildHTTPChain(defaultDeny bool,
	denyEgressRules, allowEgressRules []varmor.NetworkProxyEgressRule,
	denyHTTPRules, allowHTTPRules []varmor.NetworkProxyHTTPRule,
	auditCfg AuditConfig,
) FilterChain {
	chain := FilterChain{
		Name: "http_chain",
		FilterChainMatch: &FilterChainMatch{
			ApplicationProtocols: []string{"http/1.0", "http/1.1", "h2c"},
		},
	}

	var httpFilters []HTTPFilter

	// Shadow RBAC must be placed before enforcement RBAC in the HTTP filter chain.
	// If enforcement denies a request (returns 403), subsequent filters won't execute,
	// so shadow metadata would never be written.
	auditShadowRBAC := buildHTTPRBACForHTTP(RBACActionAllow, auditCfg.AuditShadowEgressRules, auditCfg.AuditShadowHTTPRules)
	hasHTTPShadow := auditShadowRBAC != nil
	if auditShadowRBAC != nil {
		httpFilters = append(httpFilters, HTTPFilter{
			Name: "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{
				ShadowRules: auditShadowRBAC,
			},
		})
	}

	// Deny HTTP RBAC
	denyRBAC := buildHTTPRBACForHTTP(RBACActionDeny, denyEgressRules, denyHTTPRules)
	if denyRBAC != nil {
		httpFilters = append(httpFilters, HTTPFilter{
			Name: "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{
				Rules: denyRBAC,
			},
		})
	}

	// Allow HTTP RBAC (only when defaultAction=deny)
	if defaultDeny {
		allowRBAC := buildHTTPRBACForHTTP(RBACActionAllow, allowEgressRules, allowHTTPRules)
		if allowRBAC != nil {
			httpFilters = append(httpFilters, HTTPFilter{
				Name:        "envoy.filters.http.rbac",
				TypedConfig: &RBACConfig{Rules: allowRBAC},
			})
		}
	}

	// Router (terminal filter)
	httpFilters = append(httpFilters, HTTPFilter{
		Name:        "envoy.filters.http.router",
		TypedConfig: nil,
	})

	// Compute HCM CEL expression
	hcmCEL := computeHCMCEL(auditCfg.DefaultDeny, hasHTTPShadow)

	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.http_connection_manager",
		TypedConfig: &HTTPConnManagerConfig{
			StatPrefix:       "http_outbound",
			HTTPFilters:      httpFilters,
			AccessLogEnabled: auditCfg.AccessLogEnabled,
			AccessLogCEL:     hcmCEL,
			RouteConfig: &RouteConfig{
				Name: "local_route",
				VirtualHosts: []VirtualHost{{
					Name:    "allow_any",
					Domains: []string{"*"},
					Routes: []Route{{
						Match:  RouteMatch{Prefix: "/"},
						Action: RouteAction{Cluster: clusterName},
					}},
				}},
			},
		},
	})

	return chain
}

func buildHTTPRBACForHTTP(action RBACAction, egressRules []varmor.NetworkProxyEgressRule, httpRules []varmor.NetworkProxyHTTPRule) *RBACRules {
	policies := make(map[string]*RBACPolicy)
	idx := 0

	for _, r := range egressRules {
		perms := egressRuleToHTTPPermissions(r)
		if len(perms) == 0 {
			continue
		}
		policies[fmt.Sprintf("egress_%d", idx)] = &RBACPolicy{
			Permissions: perms,
			Principals:  []Principal{{Any: true}},
		}
		idx++
	}

	for _, r := range httpRules {
		perms := httpRuleToHTTPPermissions(r)
		if len(perms) == 0 {
			continue
		}
		policies[fmt.Sprintf("http_%d", idx)] = &RBACPolicy{
			Permissions: perms,
			Principals:  []Principal{{Any: true}},
		}
		idx++
	}

	if len(policies) == 0 {
		return nil
	}

	return &RBACRules{
		Action:   action,
		Policies: policies,
	}
}

// ============================================================================
// Chain 3: TCP Default
// ============================================================================

func buildTCPDefaultChain(defaultDeny bool,
	denyEgressRules, allowEgressRules []varmor.NetworkProxyEgressRule,
	auditCfg AuditConfig,
) FilterChain {
	chain := FilterChain{
		Name:             "tcp_default_chain",
		FilterChainMatch: nil,
	}

	// Shadow RBAC must be placed before enforcement RBAC in the network filter chain.
	// Same reasoning as TLS chain and HTTP chain: denied connections terminate
	// before subsequent filters run, so shadow metadata must be written first.
	auditShadowRBAC := buildNetworkRBACForTCP(RBACActionAllow, auditCfg.AuditShadowEgressRules)
	if auditShadowRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix:  "tcp_audit_rbac",
				ShadowRules: auditShadowRBAC,
			},
		})
	}

	// Deny RBAC
	denyRBAC := buildNetworkRBACForTCP(RBACActionDeny, denyEgressRules)
	if denyRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix: "tcp_deny_rbac",
				Rules:      denyRBAC,
			},
		})
	}

	// Allow RBAC (only when defaultAction=deny)
	if defaultDeny {
		allowRBAC := buildNetworkRBACForTCP(RBACActionAllow, allowEgressRules)
		if allowRBAC != nil {
			chain.Filters = append(chain.Filters, NetworkFilter{
				Name: "envoy.filters.network.rbac",
				TypedConfig: &RBACConfig{
					StatPrefix: "tcp_allow_rbac",
					Rules:      allowRBAC,
				},
			})
		}
	}

	// tcp_proxy → original_dst cluster (no access_log — handled at listener level)
	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.tcp_proxy",
		TypedConfig: &TCPProxyConfig{
			StatPrefix: "tcp_passthrough",
			Cluster:    clusterName,
		},
	})

	return chain
}

func buildNetworkRBACForTCP(action RBACAction, egressRules []varmor.NetworkProxyEgressRule) *RBACRules {
	policies := make(map[string]*RBACPolicy)
	idx := 0

	for _, r := range egressRules {
		perms := egressRuleToNetworkPermissions(r)
		if len(perms) == 0 {
			continue
		}
		policies[fmt.Sprintf("egress_%d", idx)] = &RBACPolicy{
			Permissions: perms,
			Principals:  []Principal{{Any: true}},
		}
		idx++
	}

	if len(policies) == 0 {
		return nil
	}

	return &RBACRules{
		Action:   action,
		Policies: policies,
	}
}

// ============================================================================
// Permission builders
// ============================================================================

func egressRuleToNetworkPermissions(r varmor.NetworkProxyEgressRule) []Permission {
	var rules []PermissionRule

	if r.IP != "" {
		rules = append(rules, PermissionRule{
			Type:  "destination_ip",
			Value: r.IP,
		})
	}

	if r.CIDR != "" {
		rules = append(rules, PermissionRule{
			Type:  "destination_ip",
			Value: r.CIDR,
		})
	}

	rules = append(rules, portToPermissionRules(r.Ports)...)

	if len(rules) == 0 {
		return nil
	}

	if r.IP == "" && r.CIDR == "" && len(r.Ports) > 0 {
		var perms []Permission
		for _, pr := range rules {
			perms = append(perms, Permission{AndRules: []PermissionRule{pr}})
		}
		return perms
	}

	return []Permission{{AndRules: rules}}
}

func egressRuleToHTTPPermissions(r varmor.NetworkProxyEgressRule) []Permission {
	return egressRuleToNetworkPermissions(r)
}

func httpRuleToSNIPermissions(r varmor.NetworkProxyHTTPRule) []Permission {
	if len(r.Match.Hosts) == 0 {
		return nil
	}

	var sniRules []PermissionRule
	for _, host := range r.Match.Hosts {
		if isWildcardDomain(host) {
			sniRules = append(sniRules, PermissionRule{
				Type:  "requested_server_name",
				Value: map[string]string{"suffix": wildcardToSuffix(host)},
			})
		} else {
			sniRules = append(sniRules, PermissionRule{
				Type:  "requested_server_name",
				Value: map[string]string{"exact": host},
			})
		}
	}

	portRules := portToPermissionRules(r.Match.Ports)

	if len(portRules) == 0 {
		var perms []Permission
		for _, sr := range sniRules {
			perms = append(perms, Permission{AndRules: []PermissionRule{sr}})
		}
		return perms
	}

	var perms []Permission
	for _, sr := range sniRules {
		for _, pr := range portRules {
			perms = append(perms, Permission{AndRules: []PermissionRule{sr, pr}})
		}
	}
	return perms
}

func httpRuleToHTTPPermissions(r varmor.NetworkProxyHTTPRule) []Permission {
	var hostRules []PermissionRule
	for _, host := range r.Match.Hosts {
		if isWildcardDomain(host) {
			hostRules = append(hostRules, PermissionRule{
				Type: "header",
				Value: map[string]string{
					"name":         ":authority",
					"suffix_match": wildcardToSuffix(host),
				},
			})
		} else {
			hostRules = append(hostRules, PermissionRule{
				Type: "header",
				Value: map[string]string{
					"name":        ":authority",
					"exact_match": host,
				},
			})
		}
	}

	portRules := portToPermissionRules(r.Match.Ports)

	var methodRules []PermissionRule
	for _, method := range r.Match.Methods {
		methodRules = append(methodRules, PermissionRule{
			Type: "header",
			Value: map[string]string{
				"name":        ":method",
				"exact_match": strings.ToUpper(method),
			},
		})
	}

	var pathRules []PermissionRule
	for _, path := range r.Match.Paths {
		if path.Exact != "" {
			pathRules = append(pathRules, PermissionRule{
				Type:  "url_path",
				Value: map[string]string{"exact": path.Exact},
			})
		} else if path.Prefix != "" {
			pathRules = append(pathRules, PermissionRule{
				Type:  "url_path",
				Value: map[string]string{"prefix": path.Prefix},
			})
		}
	}

	dimensions := [][]PermissionRule{}
	if len(hostRules) > 0 {
		dimensions = append(dimensions, hostRules)
	}
	if len(portRules) > 0 {
		dimensions = append(dimensions, portRules)
	}
	if len(methodRules) > 0 {
		dimensions = append(dimensions, methodRules)
	}
	if len(pathRules) > 0 {
		dimensions = append(dimensions, pathRules)
	}

	if len(dimensions) == 0 {
		return nil
	}

	combos := crossProduct(dimensions)
	var perms []Permission
	for _, combo := range combos {
		perms = append(perms, Permission{AndRules: combo})
	}
	return perms
}

func crossProduct(dimensions [][]PermissionRule) [][]PermissionRule {
	if len(dimensions) == 0 {
		return nil
	}

	result := [][]PermissionRule{{}}
	for _, dim := range dimensions {
		var newResult [][]PermissionRule
		for _, existing := range result {
			for _, rule := range dim {
				combo := make([]PermissionRule, len(existing), len(existing)+1)
				copy(combo, existing)
				combo = append(combo, rule)
				newResult = append(newResult, combo)
			}
		}
		result = newResult
	}
	return result
}

func portToPermissionRules(ports []varmor.Port) []PermissionRule {
	var rules []PermissionRule
	for _, p := range ports {
		if p.EndPort > 0 && p.EndPort != p.Port {
			rules = append(rules, PermissionRule{
				Type: "destination_port_range",
				Value: map[string]uint16{
					"start": p.Port,
					"end":   p.EndPort + 1,
				},
			})
		} else {
			rules = append(rules, PermissionRule{
				Type:  "destination_port",
				Value: p.Port,
			})
		}
	}
	return rules
}
