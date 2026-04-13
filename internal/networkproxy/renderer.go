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
	"net"
	"sort"
	"strings"
)

// ============================================================================
// YAML Renderer: converts internal translator structures to Envoy xDS YAML
// ============================================================================

// --- CEL Expression Constants ---
//
// All access_log filtering uses CEL (Common Expression Language) exclusively.
// This eliminates response_flag_filter (UAEX), metadata_filter, and or_filter,
// providing a single, consistent mechanism across all layers.
//
// Background: Envoy's RBAC filters do NOT set the UAEX response flag.
// UAEX is only set by ext_authz. Network RBAC sets CONNECTION_TERMINATION_DETAILS,
// and HTTP RBAC sets RESPONSE_CODE_DETAILS. We use CEL to inspect these attributes.
//
// Listener-level (connection-level, covers TLS + TCP chains):
//   Deny detection:  connection.termination_details.matches("rbac_access_denied.*")
//   Shadow detection: 'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters.network.rbac']
//
// HCM-level (HTTP chain):
//   Deny detection:  response.code_details.matches("rbac_access_denied.*")
//   Shadow detection: 'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters.http.rbac']
//
// CEL error handling: ExpressionFilter treats expression evaluation errors as false,
// which is safe — when an attribute or metadata namespace doesn't exist, the
// expression simply returns false (no log emitted).

const (
	// Listener-level CEL: detect Network RBAC denial
	celListenerDeny = `connection.termination_details.matches("rbac_access_denied.*")`
	// Listener-level CEL: detect shadow_rules match (network RBAC audit)
	celListenerShadow = `'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters.network.rbac']`
	// Listener-level CEL: deny OR shadow (deny-default with shadow rules)
	celListenerDenyOrShadow = `connection.termination_details.matches("rbac_access_denied.*") || 'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters.network.rbac']`

	// HCM-level CEL: detect HTTP RBAC denial
	celHCMDeny = `response.code_details.matches("rbac_access_denied.*")`
	// HCM-level CEL: detect shadow_rules match (HTTP RBAC audit)
	celHCMShadow = `'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters.http.rbac']`
	// HCM-level CEL: deny OR shadow (deny-default with shadow rules)
	celHCMDenyOrShadow = `response.code_details.matches("rbac_access_denied.*") || 'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters.http.rbac']`
)

// yamlCEL wraps a CEL expression for safe embedding in YAML.
// Uses double-quoted YAML string, escaping internal double quotes and backslashes.
func yamlCEL(expr string) string {
	escaped := strings.ReplaceAll(expr, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func renderListenerYAML(tlsChain, httpChain FilterChain, tcpChain FilterChain, version int64, proxyPort uint16, listenerAccessLogEnabled bool, listenerCEL string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`version_info: "%d"
resources:
- "@type": type.googleapis.com/envoy.config.listener.v3.Listener
  name: varmor_outbound
  address:
    socket_address:
      address: 0.0.0.0
      port_value: %d

  # --- Listener Filters (connection-level, executed before filter chain matching) ---
  listener_filters:
  - name: envoy.filters.listener.original_dst
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
  - name: envoy.filters.listener.tls_inspector
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
  - name: envoy.filters.listener.http_inspector
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.listener.http_inspector.v3.HttpInspector
`, version, proxyPort))

	// Listener-level access_log: captures connection-level events across ALL filter chains
	// (TLS chain + TCP default chain). Uses CEL to detect Network RBAC deny events
	// and/or shadow_rules metadata matches.
	//
	// The listener-level CEL expression is pre-computed by the translator based on:
	//   - deny-default + shadow: celListenerDenyOrShadow
	//   - deny-default only:     celListenerDeny
	//   - allow-default + shadow: celListenerShadow
	//   - allow-default only:     (no listener access_log)
	//
	// HTTP chain events are handled separately at the HCM level, so there is no
	// namespace conflict between envoy.filters.network.rbac and envoy.filters.http.rbac.
	if listenerAccessLogEnabled && listenerCEL != "" {
		sb.WriteString("\n  access_log:\n")
		sb.WriteString("  - name: envoy.access_loggers.stdout\n")
		sb.WriteString("    filter:\n")
		sb.WriteString("      extension_filter:\n")
		sb.WriteString("        name: envoy.access_loggers.extension_filters.cel\n")
		sb.WriteString("        typed_config:\n")
		sb.WriteString("          \"@type\": type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter\n")
		sb.WriteString(fmt.Sprintf("          expression: %s\n", yamlCEL(listenerCEL)))
		sb.WriteString("    typed_config:\n")
		sb.WriteString("      \"@type\": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog\n")
		sb.WriteString("      log_format:\n")
		sb.WriteString("        text_format_source:\n")
		sb.WriteString("          inline_string: \"[%START_TIME%][L4] dst=%DOWNSTREAM_LOCAL_ADDRESS% sni=%REQUESTED_SERVER_NAME% duration=%DURATION%ms reason=%CONNECTION_TERMINATION_DETAILS%\\n\"\n")
	}

	sb.WriteString("\n  filter_chains:\n")

	// Chain 1: TLS
	sb.WriteString(renderFilterChainYAML(&tlsChain, 2))

	// Chain 2: HTTP
	sb.WriteString(renderFilterChainYAML(&httpChain, 2))

	// Chain 3: TCP default (as default_filter_chain)
	sb.WriteString("\n  default_filter_chain:\n")
	sb.WriteString(renderDefaultFilterChainBodyYAML(&tcpChain, 4))

	return sb.String()
}

func renderFilterChainYAML(chain *FilterChain, indent int) string {
	var sb strings.Builder
	prefix := strings.Repeat(" ", indent)

	sb.WriteString(fmt.Sprintf("%s# ---- %s ----\n", prefix, chain.Name))

	if chain.FilterChainMatch != nil {
		sb.WriteString(fmt.Sprintf("%s- filter_chain_match:\n", prefix))

		if chain.FilterChainMatch.TransportProtocol != "" {
			sb.WriteString(fmt.Sprintf("%s    transport_protocol: \"%s\"\n", prefix, chain.FilterChainMatch.TransportProtocol))
		}

		if len(chain.FilterChainMatch.ApplicationProtocols) > 0 {
			sb.WriteString(fmt.Sprintf("%s    application_protocols: [", prefix))
			for i, p := range chain.FilterChainMatch.ApplicationProtocols {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(fmt.Sprintf("\"%s\"", p))
			}
			sb.WriteString("]\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s- ", prefix))
	}

	sb.WriteString(fmt.Sprintf("%s  filters:\n", prefix))
	for _, f := range chain.Filters {
		sb.WriteString(renderNetworkFilterYAML(&f, indent+2))
	}

	return sb.String()
}

func renderDefaultFilterChainBodyYAML(chain *FilterChain, indent int) string {
	var sb strings.Builder
	prefix := strings.Repeat(" ", indent)

	sb.WriteString(fmt.Sprintf("%s# ---- %s (fallback for non-TLS, non-HTTP) ----\n", prefix, chain.Name))
	sb.WriteString(fmt.Sprintf("%sfilters:\n", prefix))
	for _, f := range chain.Filters {
		sb.WriteString(renderNetworkFilterYAML(&f, indent))
	}

	return sb.String()
}

func renderNetworkFilterYAML(f *NetworkFilter, indent int) string {
	switch f.Name {
	case "envoy.filters.network.rbac":
		return renderNetworkRBACFilterYAML(f, indent)
	case "envoy.filters.network.tcp_proxy":
		return renderTCPProxyFilterYAML(f, indent)
	case "envoy.filters.network.http_connection_manager":
		return renderHTTPConnManagerYAML(f, indent)
	default:
		return ""
	}
}

func renderTCPProxyFilterYAML(f *NetworkFilter, indent int) string {
	prefix := strings.Repeat(" ", indent)
	cfg := f.TypedConfig.(*TCPProxyConfig)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s- name: envoy.filters.network.tcp_proxy\n", prefix))
	sb.WriteString(fmt.Sprintf("%s  typed_config:\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    \"@type\": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    stat_prefix: %s\n", prefix, cfg.StatPrefix))
	sb.WriteString(fmt.Sprintf("%s    cluster: %s\n", prefix, cfg.Cluster))

	// tcp_proxy access_log is NO LONGER rendered.
	//
	// In the all-CEL architecture (v4), ALL audit logging is handled by:
	//   - Listener-level access_log (CEL on connection.termination_details / network shadow metadata)
	//     → Covers TLS and TCP chain deny + shadow events
	//   - HCM-level access_log (CEL on response.code_details / HTTP shadow metadata)
	//     → Covers HTTP chain deny + shadow events
	//
	// tcp_proxy only sees ALLOWED traffic (denied traffic never reaches it), and
	// shadow_rules metadata from network RBAC is visible at the listener level.
	// Therefore, tcp_proxy access_log is redundant and removed entirely.

	return sb.String()
}

func renderNetworkRBACFilterYAML(f *NetworkFilter, indent int) string {
	prefix := strings.Repeat(" ", indent)
	cfg := f.TypedConfig.(*RBACConfig)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s- name: envoy.filters.network.rbac\n", prefix))
	sb.WriteString(fmt.Sprintf("%s  typed_config:\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    \"@type\": type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    stat_prefix: %s\n", prefix, cfg.StatPrefix))

	if cfg.Rules != nil {
		sb.WriteString(fmt.Sprintf("%s    rules:\n", prefix))
		sb.WriteString(renderRBACRulesYAML(cfg.Rules, indent+6, "network"))
	}

	if cfg.ShadowRules != nil {
		sb.WriteString(fmt.Sprintf("%s    shadow_rules:\n", prefix))
		sb.WriteString(renderRBACRulesYAML(cfg.ShadowRules, indent+6, "network"))
	}

	return sb.String()
}

func renderHTTPConnManagerYAML(f *NetworkFilter, indent int) string {
	prefix := strings.Repeat(" ", indent)
	cfg := f.TypedConfig.(*HTTPConnManagerConfig)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s- name: envoy.filters.network.http_connection_manager\n", prefix))
	sb.WriteString(fmt.Sprintf("%s  typed_config:\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    stat_prefix: %s\n", prefix, cfg.StatPrefix))
	sb.WriteString(fmt.Sprintf("%s    internal_address_config: {}\n", prefix))

	// HCM access_log filter: uses a single CEL expression for ALL scenarios.
	//
	// The CEL expression is pre-computed by the translator based on:
	//   - deny-default + shadow: celHCMDenyOrShadow
	//   - deny-default only:     celHCMDeny
	//   - allow-default + shadow: celHCMShadow
	//   - allow-default only:     (no access_log)
	//
	// This replaces the previous mix of response_flag_filter, metadata_filter,
	// and or_filter with a single, unified CEL expression.
	if cfg.AccessLogEnabled && cfg.AccessLogCEL != "" {
		sb.WriteString(fmt.Sprintf("%s    access_log:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s    - name: envoy.access_loggers.stdout\n", prefix))
		sb.WriteString(fmt.Sprintf("%s      filter:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s        extension_filter:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s          name: envoy.access_loggers.extension_filters.cel\n", prefix))
		sb.WriteString(fmt.Sprintf("%s          typed_config:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s            \"@type\": type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter\n", prefix))
		sb.WriteString(fmt.Sprintf("%s            expression: %s\n", prefix, yamlCEL(cfg.AccessLogCEL)))
		sb.WriteString(fmt.Sprintf("%s      typed_config:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s        \"@type\": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog\n", prefix))
		sb.WriteString(fmt.Sprintf("%s        log_format:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s          text_format_source:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s            inline_string: \"[%%START_TIME%%][L7] method=%%REQ(:METHOD)%% uri=%%REQ(:AUTHORITY)%%%%REQ(:PATH)%% code=%%RESPONSE_CODE%% dst=%%DOWNSTREAM_LOCAL_ADDRESS%% duration=%%DURATION%%ms reason=%%RESPONSE_CODE_DETAILS%%\\n\"\n", prefix))
	}

	// Route config
	if cfg.RouteConfig != nil {
		sb.WriteString(fmt.Sprintf("%s    route_config:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s      name: %s\n", prefix, cfg.RouteConfig.Name))
		sb.WriteString(fmt.Sprintf("%s      virtual_hosts:\n", prefix))
		for _, vh := range cfg.RouteConfig.VirtualHosts {
			sb.WriteString(fmt.Sprintf("%s      - name: %s\n", prefix, vh.Name))
			sb.WriteString(fmt.Sprintf("%s        domains:\n", prefix))
			for _, d := range vh.Domains {
				sb.WriteString(fmt.Sprintf("%s        - \"%s\"\n", prefix, d))
			}
			sb.WriteString(fmt.Sprintf("%s        routes:\n", prefix))
			for _, r := range vh.Routes {
				sb.WriteString(fmt.Sprintf("%s        - match:\n", prefix))
				sb.WriteString(fmt.Sprintf("%s            prefix: \"%s\"\n", prefix, r.Match.Prefix))
				sb.WriteString(fmt.Sprintf("%s          route:\n", prefix))
				sb.WriteString(fmt.Sprintf("%s            cluster: %s\n", prefix, r.Action.Cluster))
			}
		}
	}

	// HTTP filters
	sb.WriteString(fmt.Sprintf("%s    http_filters:\n", prefix))
	for _, hf := range cfg.HTTPFilters {
		sb.WriteString(renderHTTPFilterYAML(&hf, indent+6))
	}

	return sb.String()
}

func renderHTTPFilterYAML(hf *HTTPFilter, indent int) string {
	prefix := strings.Repeat(" ", indent)

	switch hf.Name {
	case "envoy.filters.http.rbac":
		return renderHTTPRBACFilterYAML(hf, indent)
	case "envoy.filters.http.router":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%s- name: envoy.filters.http.router\n", prefix))
		sb.WriteString(fmt.Sprintf("%s  typed_config:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s    \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\n", prefix))
		return sb.String()
	default:
		return ""
	}
}

func renderHTTPRBACFilterYAML(hf *HTTPFilter, indent int) string {
	prefix := strings.Repeat(" ", indent)
	cfg := hf.TypedConfig.(*RBACConfig)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s- name: envoy.filters.http.rbac\n", prefix))
	sb.WriteString(fmt.Sprintf("%s  typed_config:\n", prefix))
	sb.WriteString(fmt.Sprintf("%s    \"@type\": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC\n", prefix))

	if cfg.Rules != nil {
		sb.WriteString(fmt.Sprintf("%s    rules:\n", prefix))
		sb.WriteString(renderRBACRulesYAML(cfg.Rules, indent+6, "http"))
	}

	if cfg.ShadowRules != nil {
		sb.WriteString(fmt.Sprintf("%s    shadow_rules:\n", prefix))
		sb.WriteString(renderRBACRulesYAML(cfg.ShadowRules, indent+6, "http"))
	}

	return sb.String()
}

func renderRBACRulesYAML(rules *RBACRules, indent int, rbacType string) string {
	prefix := strings.Repeat(" ", indent)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%saction: %s\n", prefix, rules.Action))

	// Empty policies map → render as "policies: {}" (ALLOW with no policies = deny all)
	if len(rules.Policies) == 0 {
		sb.WriteString(fmt.Sprintf("%spolicies: {}\n", prefix))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("%spolicies:\n", prefix))

	names := make([]string, 0, len(rules.Policies))
	for name := range rules.Policies {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		policy := rules.Policies[name]
		sb.WriteString(fmt.Sprintf("%s  \"%s\":\n", prefix, name))
		sb.WriteString(fmt.Sprintf("%s    permissions:\n", prefix))

		for _, perm := range policy.Permissions {
			if len(perm.AndRules) == 1 {
				sb.WriteString(renderPermissionRuleYAML(perm.AndRules[0], indent+4, rbacType))
			} else {
				sb.WriteString(fmt.Sprintf("%s    - and_rules:\n", prefix))
				sb.WriteString(fmt.Sprintf("%s        rules:\n", prefix))
				for _, r := range perm.AndRules {
					sb.WriteString(renderPermissionRuleYAML(r, indent+8, rbacType))
				}
			}
		}

		sb.WriteString(fmt.Sprintf("%s    principals:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s    - any: true\n", prefix))
	}

	return sb.String()
}

func renderPermissionRuleYAML(rule PermissionRule, indent int, rbacType string) string {
	prefix := strings.Repeat(" ", indent)
	var sb strings.Builder

	switch rule.Type {
	case "any":
		sb.WriteString(fmt.Sprintf("%s- any: true\n", prefix))

	case "destination_ip":
		ipStr := rule.Value.(string)
		ip, cidrNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s- destination_ip:\n", prefix))
			sb.WriteString(fmt.Sprintf("%s    address_prefix: %s\n", prefix, ipStr))
			sb.WriteString(fmt.Sprintf("%s    prefix_len: 32\n", prefix))
		} else {
			ones, _ := cidrNet.Mask.Size()
			sb.WriteString(fmt.Sprintf("%s- destination_ip:\n", prefix))
			sb.WriteString(fmt.Sprintf("%s    address_prefix: %s\n", prefix, ip.Mask(cidrNet.Mask).String()))
			sb.WriteString(fmt.Sprintf("%s    prefix_len: %d\n", prefix, ones))
		}

	case "destination_port":
		port := rule.Value.(uint16)
		sb.WriteString(fmt.Sprintf("%s- destination_port: %d\n", prefix, port))

	case "destination_port_range":
		rangeVal := rule.Value.(map[string]uint16)
		sb.WriteString(fmt.Sprintf("%s- destination_port_range:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s    start: %d\n", prefix, rangeVal["start"]))
		sb.WriteString(fmt.Sprintf("%s    end: %d\n", prefix, rangeVal["end"]))

	case "requested_server_name":
		sniVal := rule.Value.(map[string]string)
		if exact, ok := sniVal["exact"]; ok {
			sb.WriteString(fmt.Sprintf("%s- requested_server_name:\n", prefix))
			sb.WriteString(fmt.Sprintf("%s    exact: \"%s\"\n", prefix, exact))
		} else if suffix, ok := sniVal["suffix"]; ok {
			sb.WriteString(fmt.Sprintf("%s- requested_server_name:\n", prefix))
			sb.WriteString(fmt.Sprintf("%s    suffix: \"%s\"\n", prefix, suffix))
		}

	case "header":
		headerVal := rule.Value.(map[string]string)
		name := headerVal["name"]
		sb.WriteString(fmt.Sprintf("%s- header:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s    name: \"%s\"\n", prefix, name))
		if exact, ok := headerVal["exact_match"]; ok {
			sb.WriteString(fmt.Sprintf("%s    string_match:\n", prefix))
			sb.WriteString(fmt.Sprintf("%s      exact: \"%s\"\n", prefix, exact))
		} else if suffix, ok := headerVal["suffix_match"]; ok {
			sb.WriteString(fmt.Sprintf("%s    string_match:\n", prefix))
			sb.WriteString(fmt.Sprintf("%s      suffix: \"%s\"\n", prefix, suffix))
		}

	case "url_path":
		pathVal := rule.Value.(map[string]string)
		sb.WriteString(fmt.Sprintf("%s- url_path:\n", prefix))
		sb.WriteString(fmt.Sprintf("%s    path:\n", prefix))
		if exact, ok := pathVal["exact"]; ok {
			sb.WriteString(fmt.Sprintf("%s      exact: \"%s\"\n", prefix, exact))
		} else if pfx, ok := pathVal["prefix"]; ok {
			sb.WriteString(fmt.Sprintf("%s      prefix: \"%s\"\n", prefix, pfx))
		}
	}

	return sb.String()
}

func renderClustersYAML(version int64) string {
	return fmt.Sprintf(`version_info: "%d"
resources:
- "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
  name: original_dst
  type: ORIGINAL_DST
  lb_policy: CLUSTER_PROVIDED
  connect_timeout: 10s
`, version)
}

func renderAllowAllListenerYAML(version int64, proxyPort uint16) string {
	return fmt.Sprintf(`version_info: "%d"
resources:
- "@type": type.googleapis.com/envoy.config.listener.v3.Listener
  name: varmor_outbound
  address:
    socket_address:
      address: 0.0.0.0
      port_value: %d
  listener_filters:
  - name: envoy.filters.listener.original_dst
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
  default_filter_chain:
    name: 
    filters:
    - name: envoy.filters.network.tcp_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
        stat_prefix: passthrough
        cluster: original_dst
`, version, proxyPort)
}

func renderDenyAllListenerYAML(version int64, proxyPort uint16) string {
	return fmt.Sprintf(`version_info: "%d"
resources:
- "@type": type.googleapis.com/envoy.config.listener.v3.Listener
  name: varmor_outbound
  address:
    socket_address:
      address: 0.0.0.0
      port_value: %d
  listener_filters:
  - name: envoy.filters.listener.original_dst
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
  default_filter_chain:
    name: deny_all
    filters:
    - name: envoy.filters.network.rbac
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC
        stat_prefix: deny_all_rbac
        rules:
          action: DENY
          policies:
            "deny-all":
              permissions:
              - any: true
              principals:
              - any: true
    - name: envoy.filters.network.tcp_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
        stat_prefix: deny_all
        cluster: original_dst
`, version, proxyPort)
}
