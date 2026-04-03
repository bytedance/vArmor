// Copyright 2021-2023 vArmor Authors
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

package nri

import (
	"fmt"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, namespace string, target varmor.Target, isClusterScope bool) *varmor.NriContent {
	if enhanceProtect == nil {
		return nil
	}

	nriContent := &varmor.NriContent{}

	var builtinRules []string
	var rawRules string

	// 1. Generate builtin rules
	if len(enhanceProtect.RejectContainerRules) > 0 {
		builtinRules = append(builtinRules, "package nri.authz")
		builtinRules = append(builtinRules, "import data.varmor.nri.builtin")

		// Determine the rule name and mode based on AllowViolations
		action := "deny"
		if enhanceProtect.AllowViolations {
			action = "audit_allow"
		}

		ruleTemplate := `
%s[d] {
	builtin.%s
	d := {
		"id": "%s",
		"message": "%s"
	}
}`

		for _, ruleID := range enhanceProtect.RejectContainerRules {
			switch ruleID {
			case "disallow-privileged-container":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "is_privileged_container", "NRI-001", "Privileged containers are strictly forbidden"))
			case "disallow-dangerous-capabilities":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "has_dangerous_capabilities", "NRI-002", "Containers with dangerous capabilities are forbidden"))
			case "disallow-host-root-mount":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "mounts_host_root", "NRI-003", "Mounting host root directory is forbidden"))
			case "disallow-host-network":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "uses_host_network", "NRI-004", "Using host network is forbidden"))
			case "disallow-host-pid":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "uses_host_pid", "NRI-005", "Using host PID namespace is forbidden"))
			case "disallow-latest-tag":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "has_latest_tag", "NRI-101", "Using ':latest' tag is forbidden"))
			case "disallow-cpu-limits-missing":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "missing_cpu_limits", "NRI-103", "Missing CPU limits"))
			case "disallow-memory-limits-missing":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "missing_memory_limits", "NRI-104", "Missing memory limits"))
			case "disallow-root-container":
				builtinRules = append(builtinRules, fmt.Sprintf(ruleTemplate, action, "runs_as_root", "NRI-201", "Running as root is forbidden"))
			}
		}
	}

	if len(builtinRules) > 0 {
		nriContent.BuiltinRules = strings.Join(builtinRules, "\n\n")
	}

	// 2. Handle raw rules
	if enhanceProtect.NriRawRules != "" {
		rawRules = enhanceProtect.NriRawRules
		nriContent.Rules = rawRules
	}

	if enhanceProtect.NriOptions != nil {
		nriContent.Timeout = enhanceProtect.NriOptions.Timeout
		nriContent.FailurePolicy = enhanceProtect.NriOptions.FailurePolicy
	}

	nriContent.AuditViolations = enhanceProtect.AuditViolations
	nriContent.AllowViolations = enhanceProtect.AllowViolations

	// 3. Save matching information
	nriContent.Namespace = namespace
	nriContent.Target = target
	nriContent.IsClusterScope = isClusterScope

	return nriContent
}
