// Copyright 2024 vArmor Authors
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

package bpf

import (
	"fmt"
	"net"
	"strings"

	"github.com/dlclark/regexp2"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func reverseString(s string) string {
	bytes := []byte(s)
	len := len(bytes)

	for i := 0; i < len/2; i++ {
		bytes[i], bytes[len-i-1] = bytes[len-i-1], bytes[i]
	}

	return string(bytes)
}

func regexp2FindAllString(re *regexp2.Regexp, s string) []string {
	var matches []string
	m, _ := re.FindStringMatch(s)
	for m != nil {
		matches = append(matches, m.String())
		m, _ = re.FindNextMatch(m)
	}
	return matches
}

func setBpfCapabilityRule(content *varmor.BpfContent, mode uint32, capabilities uint64) {
	if content.Capabilities == nil {
		content.Capabilities = &varmor.CapabilitiesContent{}
	}
	content.Capabilities.Mode = mode
	content.Capabilities.Capabilities |= capabilities
}

func setBpfPtraceRule(content *varmor.BpfContent, mode uint32, permissions uint32, flags uint32) {
	if content.Ptrace == nil {
		content.Ptrace = &varmor.PtraceContent{}
	}
	content.Ptrace.Mode = mode
	content.Ptrace.Permissions |= permissions
	content.Ptrace.Flags |= flags
}

func newBpfPathRule(mode uint32, pattern string, permissions uint32) (*varmor.FileContent, error) {
	// Pre-check
	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, pattern))

	if starWildcardLen > 0 && strings.Contains(pattern, "**") {
		return nil, fmt.Errorf("policy contains an illegal FileRule rule; the globbing * and ** in the pattern '%s' cannot be used at the same time", pattern)
	}

	if starWildcardLen > 1 || strings.Count(pattern, "**") > 1 {
		return nil, fmt.Errorf("policy contains an illegal FileRule rule; the globbing * or ** in the pattern '%s' can only be used once", pattern)
	}

	// Create bpfPathRule
	var pathRule varmor.FileContent
	var flags uint32

	pathRule.Mode = mode

	if starWildcardLen > 0 {
		if strings.Contains(pattern, "/") {
			return nil, fmt.Errorf("policy contains an illegal FileRule rule; the pattern '%s' with globbing * is not supported", pattern)
		}

		stringList := strings.Split(pattern, "*")

		if len(stringList[0]) > 0 {
			pathRule.Pattern.Prefix = stringList[0]
			flags |= bpfenforcer.PrefixMatch
		}

		if len(stringList[1]) > 0 {
			pathRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= bpfenforcer.SuffixMatch
		}
	} else if strings.Contains(pattern, "**") {
		flags |= bpfenforcer.GreedyMatch

		stringList := strings.Split(pattern, "**")

		if len(stringList[0]) > 0 {
			pathRule.Pattern.Prefix = stringList[0]
			flags |= bpfenforcer.PrefixMatch
		}

		if len(stringList[1]) > 0 {
			pathRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= bpfenforcer.SuffixMatch
		}
	} else {
		pathRule.Pattern.Prefix = pattern
		flags |= bpfenforcer.PreciseMatch | bpfenforcer.PrefixMatch
	}

	if len(pathRule.Pattern.Prefix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("policy contains an illegal FileRule rule; the length of prefix '%s' should be less than the %d",
			pathRule.Pattern.Prefix, bpfenforcer.MaxFilePathPatternLength)
	}

	if len(pathRule.Pattern.Suffix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("policy contains an illegal FileRule rule; the length of suffix '%s' should be less than the %d",
			pathRule.Pattern.Suffix, bpfenforcer.MaxFilePathPatternLength)
	}

	pathRule.Pattern.Flags = flags
	pathRule.Permissions = permissions

	return &pathRule, nil
}

func newBpfNetworkCreateRule(mode uint32, domains uint64, types uint64, protocols uint64) (*varmor.NetworkContent, error) {
	// Pre-check
	if types != 0 && protocols != 0 {
		return nil, fmt.Errorf("policy contains an illegal NetworkSocketRule rule; the types and protocols fields cannot be set at the same time")
	}
	if domains == 0 && types == 0 && protocols == 0 {
		return nil, fmt.Errorf("policy contains an illegal NetworkSocketRule rule; the domains, types and protocols fields cannot be empty at the same time")
	}

	return &varmor.NetworkContent{
		Mode:  mode,
		Flags: bpfenforcer.SocketMatch,
		Socket: &varmor.NetworkSocket{
			Domains:   domains,
			Types:     types,
			Protocols: protocols,
		}}, nil
}

func newBpfNetworkConnectRule(mode uint32, cidr string, ip string, port uint16, endPort uint16, ports *[]uint16) (*varmor.NetworkContent, error) {
	// Pre-check
	if cidr == "" && ip == "" && port == 0 && endPort == 0 && ports == nil {
		return nil, fmt.Errorf("cidr, ipAddress, port, endPort and ports cannot be empty at the same time")
	}

	if cidr != "" && ip != "" {
		return nil, fmt.Errorf("cannot set CIRD and IP address at the same time")
	}

	if (port != 0 || endPort != 0) && ports != nil {
		return nil, fmt.Errorf("cannot set port/endPort and ports at the same time")
	}

	if port == 0 && endPort != 0 {
		return nil, fmt.Errorf("port cannot be 0 when endPort is set")
	}

	if endPort != 0 && endPort < port {
		return nil, fmt.Errorf("endPort cannot be less than port")
	}

	if ports != nil && len(*ports) > 16 {
		return nil, fmt.Errorf("the number of ports cannot be greater than 16")
	}

	if ports != nil {
		for _, p := range *ports {
			if p == 0 {
				return nil, fmt.Errorf("invalid network port in ports")
			}
		}
	}

	networkRule := varmor.NetworkContent{
		Mode:    mode,
		Address: &varmor.NetworkAddress{},
	}

	if cidr != "" {
		networkRule.Flags |= bpfenforcer.CidrMatch
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		networkRule.Address.IP = ipNet.IP.String()
		networkRule.Address.CIDR = ipNet.String()
		if ipNet.IP.To4() != nil {
			networkRule.Flags |= bpfenforcer.Ipv4Match
		} else {
			networkRule.Flags |= bpfenforcer.Ipv6Match
		}
	} else {
		switch ip {
		case "":
			networkRule.Flags |= bpfenforcer.Ipv4Match | bpfenforcer.Ipv6Match
		case varmor.PodSelfIP:
			networkRule.Flags |= bpfenforcer.PodSelfIpMatch | bpfenforcer.Ipv4Match | bpfenforcer.Ipv6Match
			networkRule.Address.IP = varmor.PodSelfIP
		case varmor.Unspecified:
			networkRule.Flags |= bpfenforcer.PreciseMatch | bpfenforcer.Ipv4Match | bpfenforcer.Ipv6Match
			networkRule.Address.IP = varmor.Unspecified
		default:
			networkRule.Flags |= bpfenforcer.PreciseMatch
			i := net.ParseIP(ip)
			if i == nil {
				return nil, fmt.Errorf("policy contains an illegal NetworkEgressRule rule; the ip '%s' is not a valid textual representation of an IP address", ip)
			}
			networkRule.Address.IP = i.String()
			if i.To4() != nil {
				networkRule.Flags |= bpfenforcer.Ipv4Match
			} else {
				networkRule.Flags |= bpfenforcer.Ipv6Match
			}
		}
	}

	if ports != nil {
		networkRule.Flags |= bpfenforcer.PortsMatch
		networkRule.Address.Ports = make([]uint16, len(*ports))
		copy(networkRule.Address.Ports, *ports)
	} else if port != 0 && endPort != 0 {
		networkRule.Flags |= bpfenforcer.PortRangeMatch
		networkRule.Address.Port = port
		networkRule.Address.EndPort = endPort
	} else if port != 0 {
		networkRule.Flags |= bpfenforcer.PortMatch
		networkRule.Address.Port = port
	}

	return &networkRule, nil
}

func newBpfMountRule(mode uint32, sourcePattern string, fstype string, mountFlags uint32, reverseMountFlags uint32) (*varmor.MountContent, error) {
	// Pre-check
	if len(fstype) >= bpfenforcer.MaxFileSystemTypeLength {
		return nil, fmt.Errorf("policy contains an illegal MountRule rule; the length of fstype '%s' should be less than the maximum (%d)",
			fstype, bpfenforcer.MaxFileSystemTypeLength)
	}

	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, sourcePattern))

	if starWildcardLen > 0 && strings.Contains(sourcePattern, "**") {
		return nil, fmt.Errorf("policy contains an illegal MountRule rule; the globbing * and ** in the pattern '%s' cannot be used at the same time", sourcePattern)
	}

	if starWildcardLen > 1 || strings.Count(sourcePattern, "**") > 1 {
		return nil, fmt.Errorf("policy contains an illegal MountRule rule; the globbing * or ** in the pattern '%s' can only be used once", sourcePattern)
	}

	// Create bpfMountRule
	var mountRule varmor.MountContent
	var flags uint32

	mountRule.Mode = mode

	if starWildcardLen > 0 {
		if strings.Contains(sourcePattern, "/") {
			return nil, fmt.Errorf("policy contains an illegal MountRule rule; the pattern '%s' with globbing * is not supported", sourcePattern)
		}

		stringList := strings.Split(sourcePattern, "*")

		if len(stringList[0]) > 0 {
			mountRule.Pattern.Prefix = stringList[0]
			flags |= bpfenforcer.PrefixMatch
		}

		if len(stringList[1]) > 0 {
			mountRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= bpfenforcer.SuffixMatch
		}
	} else if strings.Contains(sourcePattern, "**") {
		flags |= bpfenforcer.GreedyMatch

		stringList := strings.Split(sourcePattern, "**")

		if len(stringList[0]) > 0 {
			mountRule.Pattern.Prefix = stringList[0]
			flags |= bpfenforcer.PrefixMatch
		}

		if len(stringList[1]) > 0 {
			mountRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= bpfenforcer.SuffixMatch
		}
	} else {
		mountRule.Pattern.Prefix = sourcePattern
		flags |= bpfenforcer.PreciseMatch | bpfenforcer.PrefixMatch
	}

	if len(mountRule.Pattern.Prefix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("policy contains an illegal MountRule rule; the length of prefix '%s' should be less than the maximum (%d)",
			mountRule.Pattern.Prefix, bpfenforcer.MaxFilePathPatternLength)
	}

	if len(mountRule.Pattern.Suffix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("policy contains an illegal MountRule rule; the length of suffix '%s' should be less than the maximum (%d)",
			mountRule.Pattern.Suffix, bpfenforcer.MaxFilePathPatternLength)
	}

	mountRule.Pattern.Flags = flags
	mountRule.MountFlags = mountFlags
	mountRule.ReverseMountflags = reverseMountFlags
	mountRule.Fstype = fstype

	return &mountRule, nil
}
