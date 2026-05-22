package profile

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// =============================================================================
// TestYamlEscapeScalar: exhaustive coverage for all dangerous character classes
// =============================================================================

func TestYamlEscapeScalar(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// --- Fast path: no allocation needed ---
		{name: "no special chars", input: "Bearer sk-1234abcd", expected: "Bearer sk-1234abcd"},
		{name: "empty string", input: "", expected: ""},

		// --- Core injection characters ---
		{name: "backslash", input: `value\with\slashes`, expected: `value\\with\\slashes`},
		{name: "double quote", input: "value\"with\"quotes", expected: `value\"with\"quotes`},
		{name: "backslash and quote combined", input: "val\\\"mixed", expected: `val\\\"mixed`},

		// --- C0 control characters ---
		{name: "newline LF", input: "value\ninjected_key: malicious", expected: `value\u000Ainjected_key: malicious`},
		{name: "carriage return CR", input: "value\rinjection", expected: `value\u000Dinjection`},
		{name: "CRLF combined", input: "value\r\ninjection", expected: `value\u000D\u000Ainjection`},
		{name: "tab U+0009", input: "value\twith\ttabs", expected: `value\u0009with\u0009tabs`},
		{name: "null byte U+0000", input: "value\x00truncate", expected: `value\u0000truncate`},
		{name: "SOH U+0001", input: "start\x01end", expected: `start\u0001end`},
		{name: "form feed U+000C", input: "before\x0cafter", expected: `before\u000Cafter`},
		{name: "escape U+001B", input: "esc\x1b[31m", expected: `esc\u001B[31m`},
		{name: "unit separator U+001F boundary", input: "before\x1fafter", expected: `before\u001Fafter`},

		// --- DEL ---
		{name: "DEL U+007F", input: "value\x7fend", expected: `value\u007Fend`},

		// --- YAML 1.1 line break characters ---
		{name: "NEL U+0085", input: "value\u0085end", expected: `value\u0085end`},
		{name: "Line Separator U+2028", input: "value\u2028end", expected: `value\u2028end`},
		{name: "Paragraph Separator U+2029", input: "value\u2029end", expected: `value\u2029end`},

		// --- Legitimate characters MUST pass through unchanged ---
		{name: "normal domain", input: "api.openai.com", expected: "api.openai.com"},
		{name: "wildcard domain", input: "*.openai.com", expected: "*.openai.com"},
		{name: "domain with port", input: "api.example.com:443", expected: "api.example.com:443"},
		{name: "IPv6 address", input: "2001:db8::1", expected: "2001:db8::1"},
		{name: "IPv6 with brackets", input: "[2001:db8::1]:443", expected: "[2001:db8::1]:443"},
		{name: "URI path with query", input: "/api/v1/users?name=foo&id=123", expected: "/api/v1/users?name=foo&id=123"},
		{name: "URL-encoded path", input: "/api/v1/search%20query", expected: "/api/v1/search%20query"},
		{name: "Bearer token with space", input: "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig", expected: "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"},
		{name: "Base64 chars (+/=)", input: "dGVzdA==+abc/def", expected: "dGVzdA==+abc/def"},
		{name: "tilde and at sign", input: "user@host~backup", expected: "user@host~backup"},
		{name: "space U+0020 is safe", input: "hello world", expected: "hello world"},
		{name: "all safe special chars", input: " !#$%&'()*+,-./:;<=>?@[]^_`{|}~", expected: " !#$%&'()*+,-./:;<=>?@[]^_`{|}~"},
		{name: "hyphen underscore in domain", input: "my-service_v2.internal.svc.cluster.local", expected: "my-service_v2.internal.svc.cluster.local"},

		// --- Combined attack patterns ---
		{name: "classic YAML injection quote+LF", input: "evil\"\ninjected_key: value", expected: `evil\"\u000Ainjected_key: value`},
		{name: "backslash before quote + LF", input: "evil\\\"\nkey: val", expected: `evil\\\"\u000Akey: val`},
		{name: "LS injection U+2028", input: "evil\u2028injected: true", expected: `evil\u2028injected: true`},
		{name: "multiple dangerous chars sequence", input: "\x01\x02\x1f\x7f\u0085", expected: `\u0001\u0002\u001F\u007F\u0085`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := yamlEscapeScalar(tt.input)
			if got != tt.expected {
				t.Errorf("yamlEscapeScalar(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// TestNeedsYAMLEscape: fast-path detection
// =============================================================================

func TestNeedsYAMLEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Safe strings - should return false (no escaping needed)
		{name: "normal ASCII", input: "normal-string", expected: false},
		{name: "domain", input: "api.openai.com", expected: false},
		{name: "wildcard domain with port", input: "*.example.com:443", expected: false},
		{name: "IPv6", input: "2001:db8::1", expected: false},
		{name: "space is safe", input: "hello world", expected: false},
		{name: "empty string", input: "", expected: false},
		{name: "printable ASCII no slash no quote", input: "ABCxyz0123!@#$%^&*()", expected: false},
		{name: "URI path", input: "/api/v1/users?q=test&page=1", expected: false},

		// Unsafe strings - should return true
		{name: "has double quote", input: "has\"quote", expected: true},
		{name: "has backslash", input: `has\slash`, expected: true},
		{name: "has newline", input: "has\nnewline", expected: true},
		{name: "has CR", input: "has\rreturn", expected: true},
		{name: "has tab", input: "has\ttab", expected: true},
		{name: "has null", input: "has\x00null", expected: true},
		{name: "has DEL", input: "has\x7fdel", expected: true},
		{name: "has NEL U+0085", input: "has\u0085nel", expected: true},
		{name: "has LS U+2028", input: "has\u2028ls", expected: true},
		{name: "has PS U+2029", input: "has\u2029ps", expected: true},
		{name: "has SOH U+0001", input: "has\x01soh", expected: true},
		{name: "has US U+001F", input: "has\x1fus", expected: true},
		{name: "has ESC U+001B", input: "has\x1besc", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needsYAMLEscape(tt.input)
			if got != tt.expected {
				t.Errorf("needsYAMLEscape(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// TestYamlEscapeScalar_YAMLRoundTrip: verify YAML transparency
// Escaped output, when embedded in a double-quoted YAML scalar and parsed,
// MUST produce the original input value (Envoy receives the correct string).
// =============================================================================

func TestYamlEscapeScalar_YAMLRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "normal string", input: "Bearer sk-1234abcd"},
		{name: "with backslash", input: `path\to\file`},
		{name: "with double quote", input: "say \"hello\""},
		{name: "with newline", input: "line1\nline2"},
		{name: "with tab", input: "col1\tcol2"},
		{name: "with null byte", input: "before\x00after"},
		{name: "with DEL", input: "before\x7fafter"},
		{name: "with NEL", input: "before\u0085after"},
		{name: "with LS U+2028", input: "before\u2028after"},
		{name: "with PS U+2029", input: "before\u2029after"},
		{name: "with CRLF", input: "line1\r\nline2"},
		{name: "combined attack", input: "evil\"\nkey: value"},
		{name: "wildcard domain", input: "*.openai.com"},
		{name: "IPv6", input: "2001:db8::1"},
		{name: "URI path", input: "/api/v1/users?q=hello&page=1"},
		{name: "header with Base64", input: "Basic dXNlcjpwYXNz+/=="},
		{name: "backslash before newline", input: "path\\\nvalue"},
		{name: "multiple escapes", input: "a\"b\\c\nd\te"},
		{name: "SOH and ESC", input: "x\x01y\x1bz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escaped := yamlEscapeScalar(tt.input)

			// Construct a YAML document: key: "escaped_value"
			yamlDoc := "key: \"" + escaped + "\"\n"

			// Parse it
			var result map[string]string
			err := yaml.Unmarshal([]byte(yamlDoc), &result)
			if err != nil {
				t.Fatalf("YAML parse failed for input %q (escaped=%q): %v\nyamlDoc: %s",
					tt.input, escaped, err, yamlDoc)
			}

			// The parsed value MUST equal the original input
			got := result["key"]
			if got != tt.input {
				t.Errorf("YAML round-trip failed:\n  input:   %q\n  escaped: %q\n  parsed:  %q\n  yaml:    %s",
					tt.input, escaped, got, yamlDoc)
			}
		})
	}
}
