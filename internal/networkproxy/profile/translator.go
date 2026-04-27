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
	// TransportSocket configures the listener-side TLS termination for a
	// chain. When set, Envoy will decrypt incoming TLS using the provided
	// leaf certificate; the HCM then operates on plaintext HTTP. This is
	// how the MITM chains perform TLS interception.
	TransportSocket *DownstreamTLSContext
}

// DownstreamTLSContext is a minimal representation of Envoy's
// envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext.
//
// The translator only produces file-backed tls_certificates because the
// controller writes the leaf cert/key into the policy's unified Secret
// and projects them into the sidecar at fixed paths; Envoy's
// watched_directory picks up rotations in place.
type DownstreamTLSContext struct {
	CertPath string
	KeyPath  string
}

// FilterChainMatch defines the match criteria for a filter chain.
type FilterChainMatch struct {
	TransportProtocol    string
	ApplicationProtocols []string
	// ServerNames is the SNI match list, used by MITM TLS chains to
	// intercept only connections whose TLS ClientHello SNI appears in
	// MITMConfig.Domains. Literal entries and single-label wildcards
	// (e.g., "*.openai.com") are supported by Envoy natively.
	ServerNames []string
	// PrefixRanges is the destination-IP CIDR match list, used by MITM
	// IP chains to intercept plain-IP TLS connections (no SNI) whose
	// destination appears in MITMConfig.Domains as an IP literal.
	PrefixRanges []string
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

	// UpstreamConnectMode controls when tcp_proxy establishes the upstream connection.
	// Default (empty/"IMMEDIATE"): connect upstream immediately in onNewConnection().
	// "ON_DOWNSTREAM_DATA": wait for downstream data before connecting upstream,
	// allowing preceding network filters (e.g. RBAC) to evaluate in onData() first.
	// Requires Envoy >= 1.34. See https://github.com/envoyproxy/envoy/issues/9023.
	UpstreamConnectMode string
	// MaxEarlyDataBytes is required when UpstreamConnectMode is ON_DOWNSTREAM_DATA.
	// It specifies the maximum number of bytes to buffer from downstream before
	// the upstream connection is established.
	MaxEarlyDataBytes int
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
	// AccessLogDenyCEL is the CEL expression for deny detection in HCM access_log.
	// Empty when defaultAction != deny.
	AccessLogDenyCEL string
	// AccessLogShadowCEL is the CEL expression for shadow/audit detection in HCM access_log.
	// Empty when no shadow rules exist.
	AccessLogShadowCEL string
}

type RouteConfig struct {
	Name         string
	VirtualHosts []VirtualHost
}

type VirtualHost struct {
	Name    string
	Domains []string
	Routes  []Route
	// RequestHeadersToAdd carries the MITM-layer header injection plan.
	// Every entry uses append_action=OVERWRITE_IF_EXISTS_OR_ADD so that
	// client-supplied values for the same header are unconditionally
	// replaced by the policy-declared value (this is the required
	// semantics for API-key injection).
	RequestHeadersToAdd []HeaderToAdd
}

// HeaderToAdd is one resolved header injection entry. The controller
// pre-resolves SecretRef into a literal Value before calling the
// translator, so the translator itself never touches the kube-apiserver.
type HeaderToAdd struct {
	Name  string
	Value string
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
	Timeout string // "0s" to disable route timeout; empty = Envoy default (15s)
}

// ============================================================================
// Constants
// ============================================================================

const (
	// clusterName is the passthrough ORIGINAL_DST cluster used by Phase 1
	// TLS passthrough / plain HTTP / catch-all TCP chains. Envoy forwards
	// bytes unmodified to the socket's SO_ORIGINAL_DST target.
	clusterName = "original_dst"
	// mitmUpstreamClusterName is the TLS-capable ORIGINAL_DST cluster used
	// exclusively by MITM HCM routes. It carries an UpstreamTlsContext so
	// that Envoy re-encrypts traffic to the upstream after HTTP inspection.
	// SNI is derived automatically from the request's :authority header
	// (auto_sni + auto_san_validation on the route action).
	mitmUpstreamClusterName = "mitm_upstream"
	listenPort              = 15001
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

// regexEscapeHost escapes regex metacharacters in a hostname or IP so it
// can be safely embedded in a RE2 safe_regex pattern. The only metachar
// that appears in valid DNS names and IPv4 literals is '.'.
func regexEscapeHost(host string) string {
	return strings.ReplaceAll(host, ".", "\\.")
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

// computeListenerCELs returns the deny and shadow CEL expressions for listener-level access_log.
// Each is returned separately so the renderer can emit them as independent access_log entries,
// avoiding the CEL || short-circuit failure when connection.termination_details is null.
func computeListenerCELs(defaultDeny bool, hasShadowEgressRules bool) (denyCEL, shadowCEL string) {
	if defaultDeny {
		denyCEL = celListenerDeny
	}
	if hasShadowEgressRules {
		shadowCEL = celListenerShadow
	}
	return
}

// computeHCMCELs returns the deny and shadow CEL expressions for HCM-level access_log.
// Each is returned separately so the renderer can emit them as independent access_log entries,
// avoiding the CEL || short-circuit failure.
func computeHCMCELs(defaultDeny bool, hasShadowRules bool) (denyCEL, shadowCEL string) {
	if defaultDeny {
		denyCEL = celHCMDeny
	}
	if hasShadowRules {
		shadowCEL = celHCMShadow
	}
	return
}

// ============================================================================
// Core Translator
// ============================================================================

type TranslateResult struct {
	LDS string
	CDS string
}

// TranslateEgressRules converts varmor.NetworkProxyEgress CRD rules into
// Envoy xDS configuration.
//
// The optional mitm argument enables TLS MITM + HTTP header injection.
// When mitm is nil or MITMInput.Enabled() reports false, the emitted
// listener is identical to the pre-Phase-4 output (three filter chains:
// TLS passthrough, HTTP, TCP default). When enabled, one or two MITM
// filter chains are prepended so Envoy's most-specific-match precedence
// intercepts targeted TLS while other TLS falls through unchanged.
func TranslateEgressRules(egress *varmor.NetworkProxyEgress, version int64, proxyPort uint16, mitm *MITMInput) (*TranslateResult, error) {
	if egress == nil {
		return nil, fmt.Errorf("network proxy egress rules is nil")
	}

	// Rule classification (deny/allow/shadow buckets + audit config).
	// Factored into classifyEgress so the 10-row audit matrix lives in
	// exactly one place.
	cls := classifyEgress(egress)

	// Phase 1 chains (TLS passthrough, HTTP, TCP default).
	//
	// When MITM is enabled, filter out dead rules from tls_chain inputs.
	// MITM chains (mitm_tls_dns_chain / mitm_tls_ip_chain) use more-specific
	// filter_chain_match criteria (server_names / prefix_ranges) that steal
	// TLS traffic from tls_chain for targeted domains/IPs. Any RBAC rules
	// for those targets in tls_chain would never execute.
	tlsDenyEgress := cls.denyEgressRules
	tlsAllowEgress := cls.allowEgressRules
	tlsDenyHTTP := cls.denyHTTPRules
	tlsAllowHTTP := cls.allowHTTPRules
	tlsAuditCfg := cls.auditCfg
	if mitm.Enabled() {
		dnsSet, ipSet := buildMITMDomainSet(mitm.Domains)
		tlsDenyEgress = filterEgressRulesForTLSChain(cls.denyEgressRules, ipSet)
		tlsAllowEgress = filterEgressRulesForTLSChain(cls.allowEgressRules, ipSet)
		tlsDenyHTTP = filterHTTPRulesForTLSChain(cls.denyHTTPRules, dnsSet, ipSet)
		tlsAllowHTTP = filterHTTPRulesForTLSChain(cls.allowHTTPRules, dnsSet, ipSet)
		tlsAuditCfg = AuditConfig{
			AccessLogEnabled:       cls.auditCfg.AccessLogEnabled,
			DefaultDeny:            cls.auditCfg.DefaultDeny,
			AuditShadowEgressRules: filterEgressRulesForTLSChain(cls.auditCfg.AuditShadowEgressRules, ipSet),
			AuditShadowHTTPRules:   filterHTTPRulesForTLSChain(cls.auditCfg.AuditShadowHTTPRules, dnsSet, ipSet),
		}
	}
	tlsChain := buildTLSChain(cls.defaultDeny,
		tlsDenyEgress, tlsAllowEgress,
		tlsDenyHTTP, tlsAllowHTTP,
		tlsAuditCfg)
	httpChain := buildHTTPChain(cls.defaultDeny,
		cls.denyEgressRules, cls.allowEgressRules,
		cls.denyHTTPRules, cls.allowHTTPRules,
		cls.auditCfg)
	tcpChain := buildTCPDefaultChain(cls.defaultDeny,
		cls.denyEgressRules, cls.allowEgressRules,
		cls.auditCfg)

	// Validate MITM config before building chains.
	if err := mitm.Validate(); err != nil {
		return nil, err
	}

	// Optional MITM chains -- prepended to the filter-chain list when
	// a non-empty MITMInput is supplied.
	var mitmChains []FilterChain
	if mitm.Enabled() {
		mitmChains = buildMITMChains(cls, mitm)
	}

	// Listener-level CEL (Network RBAC deny detection + shadow metadata).
	// Uses HasShadowRules (both egress and HTTP) because HTTP rules can
	// generate SNI-based network RBAC shadow rules on the TLS chain.
	listenerDenyCEL, listenerShadowCEL := computeListenerCELs(cls.defaultDeny, cls.auditCfg.HasShadowRules())

	lds := renderListenerYAML(mitmChains, tlsChain, httpChain, tcpChain,
		version, proxyPort,
		cls.auditCfg.AccessLogEnabled, listenerDenyCEL, listenerShadowCEL)
	cds := renderClustersYAML(version, mitm.Enabled())

	return &TranslateResult{LDS: lds, CDS: cds}, nil
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

	// Compute RBAC rule payloads.
	auditShadowRBAC := buildNetworkRBACForTLS(RBACActionAllow, auditCfg.AuditShadowEgressRules, auditCfg.AuditShadowHTTPRules)
	denyRBAC := buildNetworkRBACForTLS(RBACActionDeny, denyEgressRules, denyHTTPRules)
	var allowRBAC *RBACRules
	if defaultDeny {
		allowRBAC = buildNetworkRBACForTLS(RBACActionAllow, allowEgressRules, allowHTTPRules)
		if allowRBAC == nil {
			// No allow rules for TLS -> deny all TLS (ALLOW with empty policies = deny all)
			allowRBAC = &RBACRules{
				Action:   RBACActionAllow,
				Policies: map[string]*RBACPolicy{},
			}
		}
	}

	// Merge shadow_rules into enforcement RBAC filter instances.
	//
	// Envoy <= v1.33 silently skips all but the first
	// envoy.filters.network.rbac instance in a filter chain, so we must
	// minimise the number of RBAC filter instances.
	//
	// Strategy:
	//   deny+allow -> shadow on deny filter (first); allow stays separate
	//   deny only  -> shadow on deny filter
	//   allow only -> shadow on allow filter
	//   shadow only -> permissive rules + shadow_rules in one filter
	//   nothing    -> no RBAC filter
	//
	// Within a single filter instance Envoy always evaluates shadow_rules
	// before rules, so audit metadata is written even when rules denies.
	if denyRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix:  "tls_deny_rbac",
				Rules:       denyRBAC,
				ShadowRules: auditShadowRBAC, // may be nil
			},
		})
		if allowRBAC != nil {
			chain.Filters = append(chain.Filters, NetworkFilter{
				Name: "envoy.filters.network.rbac",
				TypedConfig: &RBACConfig{
					StatPrefix: "tls_allow_rbac",
					Rules:      allowRBAC,
				},
			})
		}
	} else if allowRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix:  "tls_allow_rbac",
				Rules:       allowRBAC,
				ShadowRules: auditShadowRBAC, // may be nil
			},
		})
	} else if auditShadowRBAC != nil {
		// Shadow-only: no enforcement rules at all.
		// Create a permissive RBAC (ALLOW + allow_all policy) so the filter
		// executes and writes shadow metadata without blocking any traffic.
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix: "tls_audit_rbac",
				Rules: &RBACRules{
					Action: RBACActionAllow,
					Policies: map[string]*RBACPolicy{
						"allow_all": {
							Permissions: []Permission{{AndRules: []PermissionRule{{Type: "any", Value: true}}}},
							Principals:  []Principal{{Any: true}},
						},
					},
				},
				ShadowRules: auditShadowRBAC,
			},
		})
	}

	// tcp_proxy -> original_dst cluster (no access_log -- handled at listener level)
	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.tcp_proxy",
		TypedConfig: &TCPProxyConfig{
			StatPrefix:          "tls_passthrough",
			Cluster:             clusterName,
			UpstreamConnectMode: "ON_DOWNSTREAM_DATA",
			MaxEarlyDataBytes:   8192,
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
		if allowRBAC == nil {
			// No allow rules for HTTP → deny all HTTP (ALLOW with empty policies = deny all)
			allowRBAC = &RBACRules{
				Action:   RBACActionAllow,
				Policies: map[string]*RBACPolicy{},
			}
		}
		httpFilters = append(httpFilters, HTTPFilter{
			Name:        "envoy.filters.http.rbac",
			TypedConfig: &RBACConfig{Rules: allowRBAC},
		})
	}

	// Router (terminal filter)
	httpFilters = append(httpFilters, HTTPFilter{
		Name:        "envoy.filters.http.router",
		TypedConfig: nil,
	})

	// Compute HCM CEL expression
	hcmDenyCEL, hcmShadowCEL := computeHCMCELs(auditCfg.DefaultDeny, hasHTTPShadow)

	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.http_connection_manager",
		TypedConfig: &HTTPConnManagerConfig{
			StatPrefix:         "http_outbound",
			HTTPFilters:        httpFilters,
			AccessLogEnabled:   auditCfg.AccessLogEnabled,
			AccessLogDenyCEL:   hcmDenyCEL,
			AccessLogShadowCEL: hcmShadowCEL,
			RouteConfig: &RouteConfig{
				Name: "local_route",
				VirtualHosts: []VirtualHost{{
					Name:    "allow_any",
					Domains: []string{"*"},
					Routes: []Route{{
						Match:  RouteMatch{Prefix: "/"},
						Action: RouteAction{Cluster: clusterName, Timeout: "0s"},
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

	// Compute RBAC rule payloads.
	auditShadowRBAC := buildNetworkRBACForTCP(RBACActionAllow, auditCfg.AuditShadowEgressRules)
	denyRBAC := buildNetworkRBACForTCP(RBACActionDeny, denyEgressRules)
	var allowRBAC *RBACRules
	if defaultDeny {
		allowRBAC = buildNetworkRBACForTCP(RBACActionAllow, allowEgressRules)
		if allowRBAC == nil {
			// No L4 allow rules -> deny all raw TCP (ALLOW with empty policies = deny all)
			allowRBAC = &RBACRules{
				Action:   RBACActionAllow,
				Policies: map[string]*RBACPolicy{},
			}
		}
	}

	// Merge shadow_rules into enforcement RBAC filter instances.
	// Same strategy as buildTLSChain -- see comments there.
	if denyRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix:  "tcp_deny_rbac",
				Rules:       denyRBAC,
				ShadowRules: auditShadowRBAC, // may be nil
			},
		})
		if allowRBAC != nil {
			chain.Filters = append(chain.Filters, NetworkFilter{
				Name: "envoy.filters.network.rbac",
				TypedConfig: &RBACConfig{
					StatPrefix: "tcp_allow_rbac",
					Rules:      allowRBAC,
				},
			})
		}
	} else if allowRBAC != nil {
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix:  "tcp_allow_rbac",
				Rules:       allowRBAC,
				ShadowRules: auditShadowRBAC, // may be nil
			},
		})
	} else if auditShadowRBAC != nil {
		// Shadow-only: permissive rules + shadow_rules in one filter.
		chain.Filters = append(chain.Filters, NetworkFilter{
			Name: "envoy.filters.network.rbac",
			TypedConfig: &RBACConfig{
				StatPrefix: "tcp_audit_rbac",
				Rules: &RBACRules{
					Action: RBACActionAllow,
					Policies: map[string]*RBACPolicy{
						"allow_all": {
							Permissions: []Permission{{AndRules: []PermissionRule{{Type: "any", Value: true}}}},
							Principals:  []Principal{{Any: true}},
						},
					},
				},
				ShadowRules: auditShadowRBAC,
			},
		})
	}

	// tcp_proxy -> original_dst cluster (no access_log -- handled at listener level)
	chain.Filters = append(chain.Filters, NetworkFilter{
		Name: "envoy.filters.network.tcp_proxy",
		TypedConfig: &TCPProxyConfig{
			StatPrefix:          "tcp_passthrough",
			Cluster:             clusterName,
			UpstreamConnectMode: "ON_DOWNSTREAM_DATA",
			MaxEarlyDataBytes:   8192,
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
	// Build IP/CIDR rules as one dimension
	var ipRules []PermissionRule
	if r.IP != "" {
		ipRules = append(ipRules, PermissionRule{
			Type:  "destination_ip",
			Value: r.IP,
		})
	}
	if r.CIDR != "" {
		ipRules = append(ipRules, PermissionRule{
			Type:  "destination_ip",
			Value: r.CIDR,
		})
	}

	// Build port rules as another dimension
	portRules := portToPermissionRules(r.Ports)

	// Use cross-product to generate correct OR semantics across dimensions.
	// E.g., IP=10.0.0.1 + ports=[443, 80] produces:
	//   (IP AND port443) OR (IP AND port80)
	// NOT: IP AND port443 AND port80 (impossible to match)
	var dimensions [][]PermissionRule
	if len(ipRules) > 0 {
		dimensions = append(dimensions, ipRules)
	}
	if len(portRules) > 0 {
		dimensions = append(dimensions, portRules)
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
	// ── Phase 1: Build method & path dimensions (unchanged) ──────────
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

	// ── Phase 2: Build host × port dimension ────────────────────────
	//
	// Strategy: when both hosts and exact ports are present, we BIND them
	// instead of using a Cartesian crossProduct. The binding bakes the
	// port number into the :authority matcher for non-default ports,
	// producing zero dead rules and zero regex.
	//
	// When ports contain ranges or hosts exist without ports, we fall
	// back to or_rules (exact host) or safe_regex (wildcard host) so
	// the matcher handles any port value.

	hosts := r.Match.Hosts
	ports := r.Match.Ports

	allExactPorts := true
	for _, p := range ports {
		if p.EndPort > 0 && p.EndPort != p.Port {
			allExactPorts = false
			break
		}
	}

	var hostPortDim [][]PermissionRule // each entry is one OR-branch of and_rules

	if len(hosts) > 0 && len(ports) > 0 && allExactPorts {
		// ── Binding path: bake port into :authority matcher ──────
		for _, host := range hosts {
			for _, p := range ports {
				portRule := PermissionRule{
					Type:  "destination_port",
					Value: p.Port,
				}

				hostRule := authorityMatcherForHostPort(host, p.Port)
				hostPortDim = append(hostPortDim, []PermissionRule{hostRule, portRule})
			}
		}
	} else if len(hosts) > 0 {
		// ── Fallback path: hosts with no ports / port ranges ────
		// Use or_rules (exact host) or safe_regex (wildcard) so the
		// matcher is port-agnostic, then cross with port dimension.
		hostRules := portAgnosticHostRules(hosts)
		portRules := portToPermissionRules(ports)

		if len(portRules) == 0 {
			// No ports: each hostRule becomes its own branch
			for _, hr := range hostRules {
				hostPortDim = append(hostPortDim, []PermissionRule{hr})
			}
		} else {
			// Cross hostRules × portRules manually
			for _, hr := range hostRules {
				for _, pr := range portRules {
					hostPortDim = append(hostPortDim, []PermissionRule{hr, pr})
				}
			}
		}
	} else {
		// ── No hosts: port-only ─────────────────────────────────
		portRules := portToPermissionRules(ports)
		for _, pr := range portRules {
			hostPortDim = append(hostPortDim, []PermissionRule{pr})
		}
	}

	// ── Phase 3: Cross host-port branches with method & path ────────
	otherDimensions := [][]PermissionRule{}
	if len(methodRules) > 0 {
		otherDimensions = append(otherDimensions, methodRules)
	}
	if len(pathRules) > 0 {
		otherDimensions = append(otherDimensions, pathRules)
	}

	if len(hostPortDim) == 0 && len(otherDimensions) == 0 {
		return nil
	}

	if len(hostPortDim) == 0 {
		// Only method/path, no host/port
		combos := crossProduct(otherDimensions)
		var perms []Permission
		for _, combo := range combos {
			perms = append(perms, Permission{AndRules: combo})
		}
		return perms
	}

	if len(otherDimensions) == 0 {
		// Only host-port, no method/path
		var perms []Permission
		for _, hp := range hostPortDim {
			perms = append(perms, Permission{AndRules: hp})
		}
		return perms
	}

	// Cross each host-port branch with all method/path combos
	otherCombos := crossProduct(otherDimensions)
	var perms []Permission
	for _, hp := range hostPortDim {
		for _, oc := range otherCombos {
			combo := make([]PermissionRule, 0, len(hp)+len(oc))
			combo = append(combo, hp...)
			combo = append(combo, oc...)
			perms = append(perms, Permission{AndRules: combo})
		}
	}
	return perms
}

// isDefaultHTTPPort returns true for ports where HTTP specs do NOT
// require the port to appear in the Host/:authority header (80, 443).
func isDefaultHTTPPort(port uint16) bool {
	return port == 80 || port == 443
}

// authorityMatcherForHostPort returns a single PermissionRule that matches
// the :authority header for the given (host, port) combination.
//
// For default ports (80, 443): :authority = "host" (no port suffix).
// For non-default ports:       :authority = "host:port".
//
// This eliminates dead rules by binding the port into the matcher value.
func authorityMatcherForHostPort(host string, port uint16) PermissionRule {
	if isWildcardDomain(host) {
		suffix := wildcardToSuffix(host) // "*.openai.com" -> ".openai.com"
		if isDefaultHTTPPort(port) {
			return PermissionRule{
				Type: "header",
				Value: map[string]string{
					"name":         ":authority",
					"suffix_match": suffix,
				},
			}
		}
		// Non-default port: suffix includes ":port"
		// e.g., ".openai.com:6443" matches "api.openai.com:6443"
		return PermissionRule{
			Type: "header",
			Value: map[string]string{
				"name":         ":authority",
				"suffix_match": fmt.Sprintf("%s:%d", suffix, port),
			},
		}
	}

	// Exact host
	if isDefaultHTTPPort(port) {
		return PermissionRule{
			Type: "header",
			Value: map[string]string{
				"name":        ":authority",
				"exact_match": host,
			},
		}
	}
	// Non-default port: bake "host:port" into exact_match
	return PermissionRule{
		Type: "header",
		Value: map[string]string{
			"name":        ":authority",
			"exact_match": fmt.Sprintf("%s:%d", host, port),
		},
	}
}

// portAgnosticHostRules generates :authority matchers that work regardless
// of port value. Used when ports are ranges or unspecified.
//
// For exact hosts: or_rules(exact_match:"host", prefix_match:"host:") --
//
//	matches both "host" (default port) and "host:NNN" (any port).
//
// For wildcard hosts: safe_regex -- only way to handle unknown port suffix.
func portAgnosticHostRules(hosts []string) []PermissionRule {
	var rules []PermissionRule
	for _, host := range hosts {
		if isWildcardDomain(host) {
			suffix := wildcardToSuffix(host)
			escapedSuffix := regexEscapeHost(suffix)
			rules = append(rules, PermissionRule{
				Type: "header",
				Value: map[string]string{
					"name":             ":authority",
					"safe_regex_match": "^[^:]*" + escapedSuffix + "(:\\d+)?$",
				},
			})
		} else {
			// or_rules wrapping exact + prefix, treated as atomic unit
			rules = append(rules, PermissionRule{
				Type: "or_rules",
				Value: []PermissionRule{
					{
						Type: "header",
						Value: map[string]string{
							"name":        ":authority",
							"exact_match": host,
						},
					},
					{
						Type: "header",
						Value: map[string]string{
							"name":         ":authority",
							"prefix_match": host + ":",
						},
					},
				},
			})
		}
	}
	return rules
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
