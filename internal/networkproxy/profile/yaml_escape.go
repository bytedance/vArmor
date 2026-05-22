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
)

// yamlEscapeScalar escapes a string for safe embedding inside a double-quoted
// YAML scalar. This prevents YAML injection attacks where a user-controlled
// string could break out of the quoted scalar and inject arbitrary YAML keys
// or values.
//
// Escaped characters:
//   - Backslash        -> \\\\ (must be first to avoid double-escaping)
//   - Double-quote     -> \\" (break out of quoted scalar)
//   - C0 control chars -> \\uXXXX (U+0000 to U+001F)
//   - DEL (U+007F)     -> \\u007F
//   - NEL (U+0085)     -> \\u0085 (YAML 1.1 line break)
//   - LS  (U+2028)     -> \\u2028 (YAML 1.1 line break)
//   - PS  (U+2029)     -> \\u2029 (YAML 1.1 line break)
//
// This function MUST be used for ALL user-controlled strings interpolated
// into double-quoted YAML scalars in the renderer.
func yamlEscapeScalar(v string) string {
	if !needsYAMLEscape(v) {
		return v
	}
	var sb strings.Builder
	sb.Grow(len(v) * 2)
	for _, c := range v {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '"':
			sb.WriteString(`\"`)
		case c < 0x20: // C0 control characters
			sb.WriteString(fmt.Sprintf(`\u%04X`, c))
		case c == 0x7F: // DEL
			sb.WriteString(`\u007F`)
		case c == 0x85: // NEL
			sb.WriteString(`\u0085`)
		case c == 0x2028: // Line Separator
			sb.WriteString(`\u2028`)
		case c == 0x2029: // Paragraph Separator
			sb.WriteString(`\u2029`)
		default:
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// needsYAMLEscape is a fast-path check to avoid allocation when no escaping
// is needed (the common case for well-formed inputs).
//
// NOTE: The character set checked here must stay in sync with
// containsYAMLUnsafeChars in internal/policy/validate.go so that the webhook
// rejects exactly the same characters the renderer would escape.
func needsYAMLEscape(v string) bool {
	for _, c := range v {
		if c == '\\' || c == '"' || c < 0x20 || c == 0x7F ||
			c == 0x85 || c == 0x2028 || c == 0x2029 {
			return true
		}
	}
	return false
}
