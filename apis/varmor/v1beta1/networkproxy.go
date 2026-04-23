/*
Copyright The vArmor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

// SecretKeyRef is a reference to a specific key within a Kubernetes Secret.
// The referenced Secret must exist in the same namespace as the target workload.
type SecretKeyRef struct {
	// name is the name of the Kubernetes Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// key is the key within the Secret's data map.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// HeaderAction describes a single HTTP header to inject into requests
// forwarded through the MITM proxy.
//
// Exactly one of value or secretRef must be specified:
//   - value: a literal header value (suitable for non-sensitive headers)
//   - secretRef: a reference to a Kubernetes Secret key containing the header
//     value (suitable for API keys and other credentials)
//
// When multiple HeaderAction entries share the same name on the same domain,
// or when the upstream request already carries the header, vArmor injects
// with overwrite if exists or add semantics — the injected value replaces any
// existing value for that header.
//
// The header value is injected as-is. vArmor does NOT prepend "Bearer " or
// any other authentication scheme prefix — the value (or Secret content)
// must contain the complete header value ready for injection.
//
// Examples:
//
//	# Literal value (non-sensitive)
//	- name: "X-Request-Source"
//	  value: "varmor-agent"
//
//	# Secret reference (sensitive)
//	# If the Secret data contains "Bearer sk-xxx", the injected header is:
//	#   Authorization: Bearer sk-xxx
//	- name: "Authorization"
//	  secretRef:
//	    name: "openai-credentials"
//	    key: "api-key"
type HeaderAction struct {
	// name is the HTTP header name (e.g., "Authorization", "x-api-key").
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// value is a literal header value. Use this for non-sensitive values.
	// Mutually exclusive with secretRef.
	// +optional
	Value string `json:"value,omitempty"`
	// secretRef references a Kubernetes Secret key containing the header value.
	// Use this for sensitive values such as API keys or tokens. The referenced
	// Secret must be pre-created by the user in the same namespace as the
	// target workload. The controller reads the Secret value at reconcile time
	// and inlines it into the Envoy xDS configuration.
	// Mutually exclusive with value.
	// +optional
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`
}

// HeaderMutation describes per-domain HTTP header injection rules.
// When the MITM proxy terminates TLS for the specified domain, these
// headers are added to every request before forwarding to the upstream.
type HeaderMutation struct {
	// domain specifies which MITM domain this mutation applies to.
	// Must literally equal one of the entries in MITMConfig.Domains
	// (no wildcard expansion is performed on either side).
	// +kubebuilder:validation:MinLength=1
	Domain string `json:"domain"`
	// headers is the list of headers to inject for this domain.
	// +kubebuilder:validation:MinItems=1
	Headers []HeaderAction `json:"headers"`
}

// MITMConfig describes TLS Man-in-the-Middle configuration for inspecting
// encrypted HTTPS traffic at the HTTP level. When configured, the sidecar
// proxy terminates TLS for the specified domains using an auto-generated
// CA certificate, inspects and optionally modifies the plaintext HTTP,
// then re-encrypts traffic to the upstream server.
//
// vArmor automatically generates a self-signed CA (ECDSA P-256, 10-year
// validity) per policy. The controller appends this CA to an embedded
// Mozilla trust bundle and publishes the concatenated bundle, together
// with the xDS configuration and leaf certificate material, in the
// policy's unified Secret. Application containers consume the bundle via
// a projected Secret volume (exposed through SSL_CERT_FILE,
// REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS and CURL_CA_BUNDLE) so that
// both the public internet PKI and the MITM CA are trusted. The CA
// private key is never projected into the application container.
//
// Domains are written verbatim into the leaf certificate's SAN list,
// including wildcard entries such as "*.openai.com". Wildcard matching
// follows RFC 6125: a wildcard matches exactly one DNS label, and does
// not match the bare parent domain. Users who need both must list both
// explicitly in Domains.
type MITMConfig struct {
	// domains specifies which TLS connections should be terminated
	// for L7 inspection. Only connections to these domains will
	// be decrypted; all other TLS traffic passes through unmodified.
	// +kubebuilder:validation:MinItems=1
	Domains []string `json:"domains"`
	// headerMutations specifies per-domain HTTP header injection rules.
	// Each entry's domain must be present in the domains list above
	// (literal equality; no wildcard expansion is performed).
	//
	// This is typically used for injecting API keys or authentication tokens
	// into requests destined for specific upstream services, enabling
	// centralized credential management at the proxy layer.
	// +optional
	HeaderMutations []HeaderMutation `json:"headerMutations,omitempty"`
}

type NetworkProxyConfig struct {
	// mitm configures TLS Man-in-the-Middle for inspecting encrypted
	// HTTPS traffic at the HTTP level.
	// +optional
	MITM *MITMConfig `json:"mitm,omitempty"`
	// proxyUID specifies the UID used by the proxy sidecar process at runtime.
	// This UID must be different from the UID of the target application, as iptables
	// rules rely on this UID for traffic distinction.
	// This field cannot be modified after the policy is created.
	// Default: 1337
	// +optional
	ProxyUID *int64 `json:"proxyUID,omitempty"`
	// proxyPort specifies the listening port on which the proxy sidecar process listens.
	// When the listening port of the target application conflicts with it, a different port
	// can be specified.
	// This field cannot be modified after the policy is created.
	// Default: 15001
	// +optional
	ProxyPort *uint16 `json:"proxyPort,omitempty"`
	// proxyAdminPort specifies the listening port on which the proxy sidecar process handles
	// admin requests. When the listening port of the target application conflicts with it,
	// a different port can be specified.
	// This field cannot be modified after the policy is created.
	// Default: 15000
	// +optional
	ProxyAdminPort *uint16 `json:"proxyAdminPort,omitempty"`
}

// NetworkProxyEgressRule describes a single L4 egress access control rule
// enforced by the Network enforcer (sidecar proxy).
// It matches connections based on destination IP, CIDR, and port only.
type NetworkProxyEgressRule struct {
	// qualifiers determine the behavior of the rule.
	// Available values: allow, deny, audit (allow and deny are mutually exclusive).
	Qualifiers []string `json:"qualifiers"`
	// description is a human-readable description of the rule's purpose.
	// +optional
	Description string `json:"description,omitempty"`
	// ip specifies a single destination IP address.
	// Mutually exclusive with cidr.
	// +optional
	IP string `json:"ip,omitempty"`
	// cidr specifies a destination IP range.
	// Mutually exclusive with ip.
	// +optional
	CIDR string `json:"cidr,omitempty"`
	// ports restricts the rule to specific destination ports (OR relationship).
	// If empty, matches all ports.
	// +optional
	Ports []Port `json:"ports,omitempty"`
}

// HTTPPathMatch describes how to match an HTTP request path.
type HTTPPathMatch struct {
	// exact specifies an exact path string to match.
	// +optional
	Exact string `json:"exact,omitempty"`
	// prefix specifies a path prefix to match.
	// +optional
	Prefix string `json:"prefix,omitempty"`
}

// HTTPMatch describes match criteria for HTTP/HTTPS traffic.
type HTTPMatch struct {
	// hosts specifies the target service domains to match.
	//
	// Matching mechanism varies by traffic type:
	//   - HTTPS: matched via TLS SNI (Server Name Indication), no decryption needed
	//   - HTTP:  matched via Host header
	//   - HTTPS + MITM: matched via Host header after TLS termination
	//
	// Supports exact match ("api.openai.com") and wildcard ("*.openai.com").
	// Multiple values are OR'd.
	// +optional
	Hosts []string `json:"hosts,omitempty"`
	// ports restricts the rule to specific destination ports.
	// +optional
	Ports []Port `json:"ports,omitempty"`
	// paths specifies HTTP request path matching.
	//
	// Note: path matching requires visibility into plaintext HTTP.
	//   - For plain HTTP: works directly
	//   - For HTTPS: requires MITM configuration
	//   - If HTTPS without MITM: paths are IGNORED (only hosts matching applies)
	// +optional
	Paths []HTTPPathMatch `json:"paths,omitempty"`
	// methods specifies HTTP methods to match (e.g., GET, POST).
	//
	// Same visibility requirements as paths.
	// +optional
	Methods []string `json:"methods,omitempty"`
}

// NetworkProxyHTTPRule describes an application-level egress access control
// rule for HTTP/HTTPS traffic. It controls which web services (by domain,
// path, method) the container can access.
type NetworkProxyHTTPRule struct {
	Qualifiers []string `json:"qualifiers"`
	// +optional
	Description string    `json:"description,omitempty"`
	Match       HTTPMatch `json:"match"`
}

// NetworkProxyEgress describes the complete egress access control policy
// enforced by the NetworkProxy enforcer's sidecar proxy.
type NetworkProxyEgress struct {
	// defaultAction specifies the default action for connections that do not
	// match any rule.
	//
	// Available values:
	//   - "deny":  connections not matching any allow rule are rejected (whitelist mode).
	//   - "allow": connections not matching any deny rule are permitted (blacklist mode).
	//
	// When both allow and deny rules coexist, deny rules are evaluated first
	// (deny takes precedence), then allow rules are evaluated. Connections
	// matching neither are subject to defaultAction.
	DefaultAction string `json:"defaultAction"`
	// rules specifies L4 (connection-level) egress access control rules.
	// Rules support matching by domain (TLS SNI), IP, CIDR, and port.
	//
	// Rules within this list are evaluated based on their qualifiers:
	//   - Deny rules (qualifiers contain "deny") are evaluated first as a group.
	//   - Allow rules (qualifiers contain "allow") are evaluated second as a group.
	//   - Within each group, rules are in a logical OR relationship.
	// +optional
	Rules []NetworkProxyEgressRule `json:"rules,omitempty"`
	// httpRules specifies L7 (HTTP request-level) egress access control rules.
	// These rules can inspect HTTP method, host, path, and other request attributes.
	//
	// For HTTPS traffic, httpRules require TLS MITM to be configured via the
	// mitm field. For plain HTTP traffic, httpRules apply directly.
	// +optional
	HTTPRules []NetworkProxyHTTPRule `json:"httpRules,omitempty"`
}

// NetworkProxyRules describes the complete set of network access control rules
// enforced by the NetworkProxy	enforcer via a sidecar proxy.
//
// Unlike BPF network rules which operate at the kernel level (socket/connect
// syscalls), NetworkProxyRawRules operate at the application protocol level with
// capabilities including:
//   - TLS SNI-based domain matching (without decryption)
//   - HTTP-level request matching (with MITM for HTTPS)
//   - Connection auditing and logging
//
// When both BPF network rules and NetworkProxyRawRules are active, BPF rules
// execute first at the kernel level. Only connections allowed by BPF reach
// the sidecar proxy for NetworkProxyRawRules evaluation.
type NetworkProxyRules struct {
	// egress specifies the egress (outbound) access control rules.
	// +optional
	Egress *NetworkProxyEgress `json:"egress,omitempty"`
}
