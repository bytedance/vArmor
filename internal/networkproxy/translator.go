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
	// TransportProtocol: "tls" for TLS traffic. Empty for non-transport-level match.
	TransportProtocol string
	// ApplicationProtocols: set by http_inspector. e.g., ["http/1.0", "http/1.1", "h2c"]
	ApplicationProtocols []string
}

// NetworkFilter represents a network-level filter in a chain.
type NetworkFilter struct {
	Name        string
	TypedConfig interface{} // *RBACConfig, *HTTPConnManagerConfig, or *TCPProxyConfig
}

// TCPProxyConfig represents tcp_proxy filter configuration.
type TCPProxyConfig struct {
	StatPrefix string
	Cluster    string
}

// ============================================================================
// RBAC types (for network.rbac and http.rbac)
// ============================================================================

// RBACAction is the action for an RBAC filter.
type RBACAction string

const (
	RBACActionAllow RBACAction = "ALLOW"
	RBACActionDeny  RBACAction = "DENY"
	RBACActionLog   RBACAction = "LOG"
)

// RBACConfig represents a network.rbac or http.rbac filter config.
type RBACConfig struct {
	StatPrefix  string     // only used by network.rbac, ignored for http.rbac
	Rules       *RBACRules `json:"rules,omitempty"`
	ShadowRules *RBACRules `json:"shadow_rules,omitempty"`
}

// RBACRules contains the action and a set of policies.
type RBACRules struct {
	Action   RBACAction
	Policies map[string]*RBACPolicy
}

// RBACPolicy represents a single RBAC policy with permissions and principals.
type RBACPolicy struct {
	Permissions []Permission
	Principals  []Principal
}

// Permission defines what the policy matches on.
type Permission struct {
	AndRules []PermissionRule // AND semantics within one permission
}

// PermissionRule is a single atomic permission matcher.
type PermissionRule struct {
	Type  string      // "any", "destination_ip", "destination_port", "destination_port_range", "requested_server_name", "header", "url_path"
	Value interface{} // string, uint16, map[string]string, map[string]uint16
}

// Principal defines who (source) the policy applies to.
type Principal struct {
	Any bool
}

// HTTPFilter represents an HTTP-level filter inside http_connection_manager.
type HTTPFilter struct {
	Name        string
	TypedConfig interface{} // *RBACConfig or nil (for router)
}

// HTTPConnManagerConfig represents the http_connection_manager typed_config.
type HTTPConnManagerConfig struct {
	StatPrefix  string
	HTTPFilters []HTTPFilter
	RouteConfig *RouteConfig
}

// RouteConfig for inline route configuration.
type RouteConfig struct {
	Name         string
	VirtualHosts []VirtualHost
}

// VirtualHost defines virtual host routing.
type VirtualHost struct {
	Name    string
	Domains []string
	Routes  []Route
}

// Route defines a single route entry.
type Route struct {
	Match  RouteMatch
	Action RouteAction
}

// RouteMatch defines route matching criteria.
type RouteMatch struct {
	Prefix string
}

// RouteAction defines the route action.
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

func isAllowRule(qualifiers []string) bool {
	return hasQualifier(qualifiers, "allow")
}

func isDenyRule(qualifiers []string) bool {
	return hasQualifier(qualifiers, "deny")
}

func isAuditOnly(qualifiers []string) bool {
	return hasQualifier(qualifiers, "audit") && !hasQualifier(qualifiers, "allow") && !hasQualifier(qualifiers, "deny")
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
// Core Translator
// ============================================================================

// TranslateResult contains the generated Envoy xDS configuration.
// LDS and CDS are in file-based xDS format, ready to be written to ConfigMap.
type TranslateResult struct {
	LDS string // Listener Discovery Service YAML (lds.yaml)
	CDS string // Cluster Discovery Service YAML (cds.yaml)
}

// TranslateEgressRules converts NetworkProxyEgress CRD rules into Envoy xDS configuration.
// Output is in file-based xDS format (version_info + resources[]),
// directly usable as ConfigMap data for Envoy sidecar.
func TranslateEgressRules(egress *varmor.NetworkProxyEgress, version int64, proxyPort uint16) (*TranslateResult, error) {
	if egress == nil {
		return nil, fmt.Errorf("network proxy egress rules is nil")
	}

	// Classify rules by action
	var (
		denyEgressRules  []varmor.NetworkProxyEgressRule
		allowEgressRules []varmor.NetworkProxyEgressRule
		auditEgressRules []varmor.NetworkProxyEgressRule

		denyHTTPRules  []varmor.NetworkProxyHTTPRule
		allowHTTPRules []varmor.NetworkProxyHTTPRule
		auditHTTPRules []varmor.NetworkProxyHTTPRule
	)

	for _, r := range egress.Rules {
		switch {
		case isAuditOnly(r.Qualifiers):
			auditEgressRules = append(auditEgressRules, r)
		case isDenyRule(r.Qualifiers):
			denyEgressRules = append(denyEgressRules, r)
		case isAllowRule(r.Qualifiers):
			allowEgressRules = append(allowEgressRules, r)
		}
	}

	for _, r := range egress.HTTPRules {
		switch {
		case isAuditOnly(r.Qualifiers):
			auditHTTPRules = append(auditHTTPRules, r)
		case isDenyRule(r.Qualifiers):
			denyHTTPRules = append(denyHTTPRules, r)
		case isAllowRule(r.Qualifiers):
			allowHTTPRules = append(allowHTTPRules, r)
		}
	}

	defaultDeny := strings.ToLower(egress.DefaultAction) == "deny"

	// Build 3 filter chains
	tlsChain := buildTLSChain(defaultDeny, denyEgressRules, allowEgressRules, auditEgressRules, denyHTTPRules, allowHTTPRules, auditHTTPRules)
	httpChain := buildHTTPChain(defaultDeny, denyEgressRules, allowEgressRules, auditEgressRules, denyHTTPRules, allowHTTPRules, auditHTTPRules)
	tcpChain := buildTCPDefaultChain(defaultDeny, denyEgressRules, allowEgressRules, auditEgressRules)

	lds := renderListenerYAML(tlsChain, httpChain, tcpChain, version, proxyPort)
	cds := renderClustersYAML(version)

	return &TranslateResult{
		LDS: lds,
		CDS: cds,
	}, nil
}

// ============================================================================
// Chain 1: TLS (tls_inspector detected → transport_protocol: "tls")
// network.rbac: EgressRules → destination_ip/port, HTTPRules → requested_server_name (SNI)
// NOTE: Methods/Paths are NOT applicable in TLS chain (encrypted, no HTTP parsing)
// ============================================================================

func buildTLSChain(defaultDeny bool,
	denyEgressRules, allowEgressRules, auditEgressRules []varmor.NetworkProxyEgressRule,
	denyHTTPRules, allowHTTPRules, auditHTTPRules []varmor.NetworkProxyHTTPRule,
) FilterChain {
	chain := FilterChain{
		Name: "tls_chain",
		FilterChainMatch: &FilterChainMatch{
			TransportProtocol: "tls",
		},
	}

	// Deny RBAC
	denyRBAC := buildNetworkRBACForTLS(RBACActionDeny, denyEgressRules, denyHTTPRules)
	auditDenyRBAC := buildNetworkRBACForTLS(RBACActionDeny, auditEgressRules, auditHTTPRules)
	if denyRBAC != nil || auditDenyRBAC != nil {
		cfg := &RBACConfig{StatPrefix: "tls_deny_rbac"}
		if denyRBAC != nil {
			cfg.Rules = denyRBAC
		}
		if auditDenyRBAC != nil {
			cfg.ShadowRules = auditDenyRBAC
		}
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name:        "envoy.filters.network.rbac",
			TypedConfig: cfg,
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

	// tcp_proxy → original_dst cluster
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
// Chain 2: HTTP (http_inspector detected → application_protocols match)
//
// KEY: Use application_protocols: ["http/1.0", "http/1.1", "h2c"] instead of
// transport_protocol: "raw_buffer". The http_inspector sets application_protocols
// when it detects HTTP. Using raw_buffer would match ALL non-TLS traffic
// (both HTTP and pure TCP), making the TCP default chain unreachable.
//
// http_connection_manager → http.rbac
// Supports full L7 matching: Host header + Port + Method + Path
// ============================================================================

func buildHTTPChain(defaultDeny bool,
	denyEgressRules, allowEgressRules, auditEgressRules []varmor.NetworkProxyEgressRule,
	denyHTTPRules, allowHTTPRules, auditHTTPRules []varmor.NetworkProxyHTTPRule,
) FilterChain {
	chain := FilterChain{
		Name: "http_chain",
		FilterChainMatch: &FilterChainMatch{
			// http_inspector sets application_protocols when HTTP is detected.
			// This ensures only confirmed HTTP traffic enters this chain.
			// Pure TCP traffic (non-HTTP, non-TLS) falls to default_filter_chain.
			ApplicationProtocols: []string{"http/1.0", "http/1.1", "h2c"},
		},
	}

	var httpFilters []HTTPFilter

	// Deny HTTP RBAC
	denyRBAC := buildHTTPRBACForHTTP(RBACActionDeny, denyEgressRules, denyHTTPRules)
	auditDenyRBAC := buildHTTPRBACForHTTP(RBACActionDeny, auditEgressRules, auditHTTPRules)
	if denyRBAC != nil || auditDenyRBAC != nil {
		cfg := &RBACConfig{}
		if denyRBAC != nil {
			cfg.Rules = denyRBAC
		}
		if auditDenyRBAC != nil {
			cfg.ShadowRules = auditDenyRBAC
		}
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: cfg,
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

	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.http_connection_manager",
		TypedConfig: &HTTPConnManagerConfig{
			StatPrefix:  "http_outbound",
			HTTPFilters: httpFilters,
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
// Chain 3: TCP Default (fallback for non-TLS, non-HTTP traffic)
// network.rbac: Only EgressRules (IP/CIDR/Port). HTTPRules dead here.
// ============================================================================

func buildTCPDefaultChain(defaultDeny bool,
	denyEgressRules, allowEgressRules, auditEgressRules []varmor.NetworkProxyEgressRule,
) FilterChain {
	chain := FilterChain{
		Name:             "tcp_default_chain",
		FilterChainMatch: nil, // default filter chain
	}

	// Deny RBAC
	denyRBAC := buildNetworkRBACForTCP(RBACActionDeny, denyEgressRules)
	auditDenyRBAC := buildNetworkRBACForTCP(RBACActionDeny, auditEgressRules)
	if denyRBAC != nil || auditDenyRBAC != nil {
		cfg := &RBACConfig{StatPrefix: "tcp_deny_rbac"}
		if denyRBAC != nil {
			cfg.Rules = denyRBAC
		}
		if auditDenyRBAC != nil {
			cfg.ShadowRules = auditDenyRBAC
		}
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name:        "envoy.filters.network.rbac",
			TypedConfig: cfg,
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

	// tcp_proxy → original_dst cluster
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
// Permission builders: CRD Rule → RBAC permissions
// ============================================================================

// egressRuleToNetworkPermissions converts an EgressRule to network.rbac permissions.
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

	// If only ports specified (no IP/CIDR), each port is a separate permission (OR)
	if r.IP == "" && r.CIDR == "" && len(r.Ports) > 0 {
		var perms []Permission
		for _, pr := range rules {
			perms = append(perms, Permission{AndRules: []PermissionRule{pr}})
		}
		return perms
	}

	// AND all rules together into one permission
	return []Permission{{AndRules: rules}}
}

// egressRuleToHTTPPermissions converts an EgressRule to http.rbac permissions.
func egressRuleToHTTPPermissions(r varmor.NetworkProxyEgressRule) []Permission {
	return egressRuleToNetworkPermissions(r)
}

// httpRuleToSNIPermissions converts an HTTPRule to network.rbac SNI permissions (TLS chain).
// NOTE: Methods/Paths are NOT used here - TLS chain can only see SNI + IP/Port.
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

	// Cross product: (host AND port)
	var perms []Permission
	for _, sr := range sniRules {
		for _, pr := range portRules {
			perms = append(perms, Permission{AndRules: []PermissionRule{sr, pr}})
		}
	}
	return perms
}

// httpRuleToHTTPPermissions converts an HTTPRule to http.rbac permissions (HTTP chain).
// Supports full L7 matching: Host (:authority header) + varmor.Port + Method (:method header) + Path (url_path).
//
// Combination semantics:
//   - Within each dimension (hosts, ports, methods, paths): OR
//   - Across dimensions: AND (cross product)
//   - Example: hosts=[a.com, b.com] + methods=[GET, POST]
//     → (a.com AND GET) OR (a.com AND POST) OR (b.com AND GET) OR (b.com AND POST)
//
// If only methods/paths are specified (no hosts), they still generate valid permissions.
func httpRuleToHTTPPermissions(r varmor.NetworkProxyHTTPRule) []Permission {
	// Collect atomic rules per dimension
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

	// Build cross product of all non-empty dimensions
	// Each combination produces one Permission with AND semantics
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

	// Compute cross product
	combos := crossProduct(dimensions)
	var perms []Permission
	for _, combo := range combos {
		perms = append(perms, Permission{AndRules: combo})
	}
	return perms
}

// crossProduct computes the cartesian product of multiple slices of PermissionRules.
// Each element in the result is a combination with one rule from each dimension (AND).
// Multiple result elements represent OR semantics.
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

// portToPermissionRules converts varmor.Port slice to PermissionRules.
func portToPermissionRules(ports []varmor.Port) []PermissionRule {
	var rules []PermissionRule
	for _, p := range ports {
		if p.EndPort > 0 && p.EndPort != p.Port {
			rules = append(rules, PermissionRule{
				Type: "destination_port_range",
				Value: map[string]uint16{
					"start": p.Port,
					"end":   p.EndPort + 1, // Envoy port range is [start, end)
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
