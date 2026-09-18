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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func TestHTTPMethodCasePermissions(t *testing.T) {
	methods := []string{"GET", "get", "Get", "MiXeD", "X-Custom!"}
	rule := varmor.NetworkProxyHTTPRule{Match: varmor.HTTPMatch{Methods: append([]string(nil), methods...)}}
	permissions := httpRuleToHTTPPermissions(rule)
	require.Len(t, permissions, len(methods))
	for i, permission := range permissions {
		require.Len(t, permission.AndRules, 1)
		actual := decodeHostCasePermission(t, permission.AndRules[0]).GetHeader()
		require.NotNil(t, actual)
		require.Equal(t, ":method", actual.Name)
		require.Equal(t, methods[i], actual.GetStringMatch().GetExact())
		require.False(t, actual.GetStringMatch().GetIgnoreCase())
		if methods[i] != strings.ToUpper(methods[i]) {
			require.NotEqual(t, strings.ToUpper(methods[i]), actual.GetStringMatch().GetExact())
		}
	}
	require.Equal(t, methods, rule.Match.Methods, "translation must not rewrite policy methods")
}
