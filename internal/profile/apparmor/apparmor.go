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

package apparmor

import (
	"fmt"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func GenerateAlwaysAllowProfile(profileName string) string {
	return fmt.Sprintf(alwaysAllowTemplate, profileName, "")
}

func GenerateRuntimeDefaultProfile(profileName string) string {
	return fmt.Sprintf(runtimeDefaultTemplate, profileName, profileName, profileName, "")
}

func GenerateBehaviorModelingProfile(profileName string) string {
	return fmt.Sprintf(behaviorModelingTemplate, profileName)
}

func addSpacePrefixToCustomRules(customRules string) string {
	lines := strings.Split(customRules, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			lines[i] = "  " + line
		}
	}
	return strings.Join(lines, "\n")
}

func GenerateEnhanceProtectProfile(enhanceProtect *varmor.EnhanceProtect, profileName string) string {
	var baseRules string
	qualifier := "  "

	if enhanceProtect.AuditViolations {
		qualifier += "audit "
	}

	if !enhanceProtect.AllowViolations {
		qualifier += "deny "
	}

	// Hardening Rules
	if len(enhanceProtect.HardeningRules) > 0 {
		baseRules += "  # Hardening Rules\n"
		for _, rule := range enhanceProtect.HardeningRules {
			baseRules += generateHardeningRules(rule, qualifier)
		}
	}

	// Attack Protection Rules
	if len(enhanceProtect.AttackProtectionRules) > 0 {
		baseRules += "\n  # Attack Protection Rules\n"
		for _, attackProtectionRule := range enhanceProtect.AttackProtectionRules {
			// Process the global custom rules
			if len(attackProtectionRule.Targets) == 0 {
				for _, rule := range attackProtectionRule.Rules {
					baseRules += generateAttackProtectionRules(rule, qualifier, enhanceProtect.AllowViolations)
				}
			}
		}
	}

	// Vulnerability Mitigation Rules
	if len(enhanceProtect.VulMitigationRules) > 0 {
		baseRules += "\n  # Vulnerability Mitigation Rules\n"
		for _, rule := range enhanceProtect.VulMitigationRules {
			baseRules += generateVulMitigationRules(rule, qualifier)
		}
	}

	// Custom Rules
	if len(enhanceProtect.AppArmorRawRules) > 0 {
		baseRules += "\n  # Custom Rules\n"
		for _, rule := range enhanceProtect.AppArmorRawRules {
			// Process the global custom rules
			if len(rule.Targets) == 0 {
				baseRules += addSpacePrefixToCustomRules(rule.Rules)
			}
		}
	}

	// Generate attack protection rules and custom rules for restricting specific target executables
	baseRules = generateEnhanceProtectRulesForTargets(enhanceProtect, profileName, baseRules, qualifier)

	// Generate the final profile
	if enhanceProtect.Privileged {
		// Create profile for privileged container based on the AlwaysAllow template
		p := fmt.Sprintf(alwaysAllowTemplate, profileName, baseRules)
		p = strings.ReplaceAll(p, "  QUALIFIER ", qualifier)
		return p
	} else {
		// Create profile for unprivileged container based on the RuntimeDefault template
		templ := runtimeDefaultTemplateForEnhanceProtectMode
		if enhanceProtect.AllowViolations {
			// Note:
			//		'x' must be preceded by exec qualifier 'i', 'p', 'c', or 'u' if there is no deny qualifier
			templ = strings.ReplaceAll(templ, "wklx,", "wklix,")
		}

		p := fmt.Sprintf(templ, profileName, profileName, profileName, baseRules)
		p = strings.ReplaceAll(p, "  QUALIFIER ", qualifier)
		return p
	}
}

func GenerateDefenseInDepthProfile(appArmorRawRules []varmor.AppArmorRawRules, profile, profileName string) string {
	// Generate custom rules
	customRules := ""
	if len(appArmorRawRules) > 0 {
		customRules += "\n  # Custom Rules\n"
		for _, rule := range appArmorRawRules {
			if len(rule.Targets) == 0 {
				// Process the global custom rules
				customRules += addSpacePrefixToCustomRules(rule.Rules)
			}
		}
		// Generate custom rules for restricting specific target executables
		customRules = generateDefenseInDepthCustomRulesForTargets(appArmorRawRules, customRules, profileName)
	}

	// Generate the final profile
	lastIndex := strings.LastIndex(profile, "}")
	if lastIndex != -1 {
		return profile[:lastIndex] + customRules + profile[lastIndex:]
	}

	return profile
}
