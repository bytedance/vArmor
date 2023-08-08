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

type ProfileBuilder struct {
	dynamicResult *varmor.DynamicResult
	profileName   string
	ruleSet       string
	debug         bool
}

func NewProfileBuilder(dynamicResult *varmor.DynamicResult, debug bool) *ProfileBuilder {
	builder := ProfileBuilder{
		dynamicResult: dynamicResult,
		debug:         debug,
	}

	return &builder
}

func (builder *ProfileBuilder) buildExecRules() {
	builder.ruleSet += "\n  # ---- EXEC ----\n"

	rules := make([]string, 0, len(builder.dynamicResult.Executions))

	for _, exec := range builder.dynamicResult.Executions {
		rule := fmt.Sprintf("  %s ix,\n", exec)
		rules = append(rules, rule)
	}

	sort.Strings(rules)
	builder.ruleSet += strings.Join(rules, "")
}

func (builder *ProfileBuilder) buildFileRules() {
	builder.ruleSet += "\n  # ---- FILE ----\n"

	rules := make([]string, 0, len(builder.dynamicResult.Files))

	for _, file := range builder.dynamicResult.Files {
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
	builder.ruleSet += strings.Join(rules, "")
}

func (builder *ProfileBuilder) buildCapabilityRules() {
	builder.ruleSet += "\n  # ---- CAPABILITY ----\n"

	rules := make([]string, 0, len(builder.dynamicResult.Capabilities))

	for _, cap := range builder.dynamicResult.Capabilities {
		rule := fmt.Sprintf("  capability %s,\n", cap)
		rules = append(rules, rule)
	}

	sort.Strings(rules)
	builder.ruleSet += strings.Join(rules, "")
}

func (builder *ProfileBuilder) buildNetworkRules() {
	builder.ruleSet += "\n  # ---- NETWORK ----\n"

	if builder.debug && len(builder.dynamicResult.Networks) > 0 {
		rules := make([]string, 0, len(builder.dynamicResult.Networks))
		for _, net := range builder.dynamicResult.Networks {
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
		builder.ruleSet += strings.Join(rules, "")
	} else {
		builder.ruleSet += "  network,\n"
	}
}

func (builder *ProfileBuilder) buildPtraceRules() {
	builder.ruleSet += "\n  # ---- PTRACE ----\n"

	// From docker-default profile, See:
	//   https://github.com/moby/moby/blob/master/profiles/apparmor/template.go
	//   https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go
	builder.ruleSet += "  ## suppress ptrace denials when using 'docker ps' or using 'ps' inside a container\n"
	builder.ruleSet += fmt.Sprintf("  ptrace (trace,read,tracedby,readby) peer=%s,\n", builder.profileName)

	// From audit logs
	if builder.debug && len(builder.dynamicResult.Ptraces) > 0 {
		builder.ruleSet += "  ## only for debug\n"

		rules := make([]string, 0, len(builder.dynamicResult.Ptraces))
		for _, ptrace := range builder.dynamicResult.Ptraces {
			rule := fmt.Sprintf("  ptrace (%s) peer=%s,\n", strings.Join(ptrace.Permissions, ","), ptrace.Peer)
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		builder.ruleSet += strings.Join(rules, "")
	}
}

func (builder *ProfileBuilder) buildSignalRules() {
	builder.ruleSet += "\n  # ---- SIGNAL ----\n"

	// From docker-default profile
	//   https://github.com/moby/moby/blob/master/profiles/apparmor/template.go
	//   https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go
	builder.ruleSet += "  ## host (privileged) processes may send signals to container processes.\n"
	builder.ruleSet += "  signal (receive) peer=unconfined,\n"
	builder.ruleSet += "  ## container processes may send signals amongst themselves.\n"
	builder.ruleSet += fmt.Sprintf("  signal (send,receive) peer=%s,\n", builder.profileName)

	// From audit logs
	if builder.debug && len(builder.dynamicResult.Signals) > 0 {
		builder.ruleSet += "  ## only for debug\n"

		rules := make([]string, 0, len(builder.dynamicResult.Signals))
		for _, signal := range builder.dynamicResult.Signals {
			rule := fmt.Sprintf("  signal (%s) set=(%s) peer=%s,\n",
				strings.Join(signal.Permissions, ","),
				strings.Join(signal.Signals, ","),
				builder.profileName)
			rules = append(rules, rule)
		}
		builder.ruleSet += strings.Join(rules, "")
	}
}

func (builder *ProfileBuilder) buildDefaultAllowRules() {
	// From docker-default profile
	//   https://github.com/moby/moby/blob/master/profiles/apparmor/template.go
	//   https://github.com/containerd/containerd/blob/main/contrib/apparmor/template.go
	builder.ruleSet += "\n  # ---- ADDITIONAL ----\n"
	builder.ruleSet += "  umount,\n"
}

func (builder *ProfileBuilder) Build() (string, error) {
	if len(builder.dynamicResult.Profiles) == 0 {
		return "", fmt.Errorf("no behavior information found for the target container")
	} else if len(builder.dynamicResult.Profiles) == 1 {
		builder.profileName = builder.dynamicResult.Profiles[0]

		builder.buildExecRules()
		builder.buildFileRules()
		builder.buildCapabilityRules()
		builder.buildNetworkRules()
		builder.buildPtraceRules()
		builder.buildSignalRules()
		builder.buildDefaultAllowRules()

		profile := fmt.Sprintf(defenseInDepthTemplate, builder.profileName, builder.ruleSet)
		return base64.StdEncoding.EncodeToString([]byte(profile)), nil
	} else {
		return "", fmt.Errorf("fatal error: more than one profile exists or profile name is unexpected")
	}
}
