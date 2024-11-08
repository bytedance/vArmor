// Copyright 2022 vArmor Authors
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
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

func buildExecRules(appArmor *varmor.AppArmor) string {
	ruleSet := "\n  # ---- EXEC ----\n"

	rules := make([]string, 0, len(appArmor.Executions))

	for _, exec := range appArmor.Executions {
		rule := fmt.Sprintf("  %s ix,\n", exec)
		rules = append(rules, rule)
	}

	sort.Strings(rules)
	ruleSet += strings.Join(rules, "")

	return ruleSet
}

func buildFileRules(appArmor *varmor.AppArmor) string {
	ruleSet := "\n  # ---- FILE ----\n"

	rules := make([]string, 0, len(appArmor.Files))

	for _, file := range appArmor.Files {
		if varmorutils.InStringArray("a", file.Permissions) && varmorutils.InStringArray("w", file.Permissions) {
			perm := make([]string, 0, len(file.Permissions))
			for _, p := range file.Permissions {
				if p != "a" {
					perm = append(perm, p)
				}
			}
			file.Permissions = perm
		}
		sort.Strings(file.Permissions)

		var rule string
		if file.Owner {
			rule = fmt.Sprintf("  owner %s %s,\n", file.Path, strings.Join(file.Permissions, ""))
		} else {
			rule = fmt.Sprintf("  %s %s,\n", file.Path, strings.Join(file.Permissions, ""))
		}
		rules = append(rules, rule)
	}

	sort.Strings(rules)
	ruleSet += strings.Join(rules, "")

	return ruleSet
}

func buildCapabilityRules(appArmor *varmor.AppArmor) string {
	ruleSet := "\n  # ---- CAPABILITY ----\n"

	rules := make([]string, 0, len(appArmor.Capabilities))

	for _, cap := range appArmor.Capabilities {
		rule := fmt.Sprintf("  capability %s,\n", cap)
		rules = append(rules, rule)
	}

	sort.Strings(rules)
	ruleSet += strings.Join(rules, "")

	return ruleSet
}

func buildNetworkRules(appArmor *varmor.AppArmor, debug bool) string {
	ruleSet := "\n  # ---- NETWORK ----\n"

	if debug && len(appArmor.Networks) > 0 {
		rules := make([]string, 0, len(appArmor.Networks))
		for _, net := range appArmor.Networks {
			var rule string
			if net.SockType != "" {
				rule = fmt.Sprintf("  network %s %s,\n", net.Family, net.SockType)
			} else if net.Protocol != "" {
				rule = fmt.Sprintf("  network %s %s,\n", net.Family, net.Protocol)
			} else {
				rule = fmt.Sprintf("  network %s,\n", net.Family)
			}
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		ruleSet += strings.Join(rules, "")
	} else {
		ruleSet += "  network,\n"
	}

	return ruleSet
}

func buildPtraceRules(appArmor *varmor.AppArmor, profileName string, debug bool) string {
	ruleSet := "\n  # ---- PTRACE ----\n"

	// From docker-default profile, See:
	//   https://github.com/moby/moby/blob/master/profiles/apparmor/template.go
	//   https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go
	ruleSet += "  ## suppress ptrace denials when using 'docker ps' or using 'ps' inside a container\n"
	ruleSet += fmt.Sprintf("  ptrace (trace,read,tracedby,readby) peer=%s,\n", profileName)

	// From audit logs
	if debug && len(appArmor.Ptraces) > 0 {
		ruleSet += "  ## only for debug\n"

		rules := make([]string, 0, len(appArmor.Ptraces))
		for _, ptrace := range appArmor.Ptraces {
			rule := fmt.Sprintf("  ptrace (%s) peer=%s,\n", strings.Join(ptrace.Permissions, ","), ptrace.Peer)
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		ruleSet += strings.Join(rules, "")
	}

	return ruleSet
}

func buildSignalRules(appArmor *varmor.AppArmor, profileName string, debug bool) string {
	ruleSet := "\n  # ---- SIGNAL ----\n"

	// From docker-default profile
	//   https://github.com/moby/moby/blob/master/profiles/apparmor/template.go
	//   https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go
	ruleSet += "  ## host (privileged) processes may send signals to container processes.\n"
	ruleSet += "  signal (receive) peer=unconfined,\n"
	ruleSet += "  ## container processes may send signals amongst themselves.\n"
	ruleSet += fmt.Sprintf("  signal (send,receive) peer=%s,\n", profileName)

	// From audit logs
	if debug && len(appArmor.Signals) > 0 {
		ruleSet += "  ## only for debug\n"

		rules := make([]string, 0, len(appArmor.Signals))
		for _, signal := range appArmor.Signals {
			rule := fmt.Sprintf("  signal (%s) set=(%s) peer=%s,\n",
				strings.Join(signal.Permissions, ","),
				strings.Join(signal.Signals, ","),
				profileName)
			rules = append(rules, rule)
		}
		ruleSet += strings.Join(rules, "")
	}

	return ruleSet
}

func buildDefaultAllowRules() string {
	// From docker-default profile
	//   https://github.com/moby/moby/blob/master/profiles/apparmor/template.go
	//   https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go
	ruleSet := "\n  # ---- ADDITIONAL ----\n"
	ruleSet += "  umount,\n"
	return ruleSet
}

func GenerateProfileWithBehaviorModel(appArmor *varmor.AppArmor, debug bool) (string, error) {
	if len(appArmor.Profiles) == 0 {
		return "", fmt.Errorf("no behavior information found for the target container")
	} else if len(appArmor.Profiles) == 1 {
		profileName := appArmor.Profiles[0]

		ruleSet := buildExecRules(appArmor)
		ruleSet += buildFileRules(appArmor)
		ruleSet += buildCapabilityRules(appArmor)
		ruleSet += buildNetworkRules(appArmor, debug)
		ruleSet += buildPtraceRules(appArmor, profileName, debug)
		ruleSet += buildSignalRules(appArmor, profileName, debug)
		ruleSet += buildDefaultAllowRules()

		profile := fmt.Sprintf(defenseInDepthTemplate, profileName, ruleSet)
		return base64.StdEncoding.EncodeToString([]byte(profile)), nil
	} else {
		return "", fmt.Errorf("fatal error: more than one profile exists or profile name is unexpected")
	}
}
