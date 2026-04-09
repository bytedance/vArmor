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
//
// Output format: file-based xDS (version_info + resources[])
// - LDS: version_info + Listener resource  → write to ConfigMap lds.yaml
// - CDS: version_info + Cluster resource   → write to ConfigMap cds.yaml
// ============================================================================

func renderListenerYAML(tlsChain, httpChain FilterChain, tcpChain FilterChain, version int64, proxyPort uint16) string {
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

  filter_chains:
`, version, proxyPort))

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

// renderRBACRulesYAML renders RBAC rules content (action + policies).
//
// Indentation model (relative to `indent` parameter):
//
//	action: DENY                       ← indent
//	policies:                          ← indent
//	  "policy_name":                   ← indent+2
//	    permissions:                   ← indent+4
//	    - destination_ip:              ← indent+4  (list item aligned with key)
//	        address_prefix: ...        ← indent+8
//	    - and_rules:                   ← indent+4
//	        rules:                     ← indent+8
//	        - destination_ip: ...      ← indent+8  (list item aligned with key)
//	    principals:                    ← indent+4
//	    - any: true                    ← indent+4
func renderRBACRulesYAML(rules *RBACRules, indent int, rbacType string) string {
	prefix := strings.Repeat(" ", indent)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%saction: %s\n", prefix, rules.Action))
	sb.WriteString(fmt.Sprintf("%spolicies:\n", prefix))

	// Sort policy names for deterministic output
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
				// Single rule: list item aligned with "permissions:" key
				sb.WriteString(renderPermissionRuleYAML(perm.AndRules[0], indent+4, rbacType))
			} else {
				// Multiple rules: and_rules wrapper, list item aligned with "permissions:" key
				sb.WriteString(fmt.Sprintf("%s    - and_rules:\n", prefix))
				sb.WriteString(fmt.Sprintf("%s        rules:\n", prefix))
				for _, r := range perm.AndRules {
					// Inner list items aligned with "rules:" key
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
