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

package webhooks

import (
	"fmt"
	"strings"

	"github.com/go-openapi/jsonpointer"
)

// templateAtPointer verifies the adapter references a real object, including
// templates in arrays. Patches operate on the original JSON to preserve fields.
func templateAtPointer(root map[string]interface{}, path string) (map[string]interface{}, error) {
	// RFC 6901 permits quotes, backslashes and line breaks inside reference
	// tokens, but this pointer is later spliced verbatim into a
	// string-rendered JSON Patch path, so the dangerous characters must be
	// rejected here before they can reach the shared renderer.
	if path != "" && strings.ContainsAny(path, "\"\\\n\r") {
		return nil, fmt.Errorf("invalid template pointer %q", path)
	}
	// jsonpointer.New enforces the leading "/" (the empty pointer addresses
	// the root document for a Pod), and Get performs the RFC 6901 token
	// unescaping, map lookup and array-index bounds checks.
	ptr, err := jsonpointer.New(path)
	if err != nil {
		return nil, fmt.Errorf("invalid template pointer %q: %w", path, err)
	}
	current, _, err := ptr.Get(root)
	if err != nil {
		return nil, fmt.Errorf("template pointer %q: %w", path, err)
	}
	template, ok := current.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("template pointer %q is not an object", path)
	}
	return template, nil
}
