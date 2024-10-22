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
		return nil, fmt.Errorf("the globbing * and ** in the pattern '%s' cannot be used at the same time", pattern)
	}

	if starWildcardLen > 1 || strings.Count(pattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern '%s' can only be used once", pattern)
	}

	// Create bpfPathRule
	var pathRule varmor.FileContent
	var flags uint32

	pathRule.Mode = mode

	if starWildcardLen > 0 {
		if strings.Contains(pattern, "/") {
			return nil, fmt.Errorf("the pattern '%s' with globbing * is not supported", pattern)
		}

		stringList := strings.Split(pattern, "*")

		if len(stringList[0]) > 0 {
			pathRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			pathRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else if strings.Contains(pattern, "**") {
		flags |= GreedyMatch

		stringList := strings.Split(pattern, "**")

		if len(stringList[0]) > 0 {
			pathRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			pathRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else {
		pathRule.Pattern.Prefix = pattern
		flags |= PreciseMatch | PrefixMatch
	}

	if len(pathRule.Pattern.Prefix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of prefix '%s' should be less than the maximum (%d)", pathRule.Pattern.Prefix, bpfenforcer.MaxFilePathPatternLength)
	}

	if len(pathRule.Pattern.Suffix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of suffix '%s' should be less than the maximum (%d)", pathRule.Pattern.Suffix, bpfenforcer.MaxFilePathPatternLength)
	}

	pathRule.Pattern.Flags = flags
	pathRule.Permissions = permissions

	return &pathRule, nil
}

func newBpfNetworkRule(mode uint32, cidr string, ipAddress string, port uint32) (*varmor.NetworkContent, error) {
	// Pre-check
	if cidr == "" && ipAddress == "" && port == 0 {
		return nil, fmt.Errorf("cidr, ipAddress and port cannot be empty at the same time")
	}

	if cidr != "" && ipAddress != "" {
		return nil, fmt.Errorf("cannot set CIRD and IP address at the same time")
	}

	if port > 65535 {
		return nil, fmt.Errorf("invalid network port")
	}

	var networkRule varmor.NetworkContent
	networkRule.Mode = mode

	if cidr != "" {
		networkRule.Flags |= CidrMatch

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		networkRule.Address = ipNet.IP.String()
		networkRule.CIDR = ipNet.String()
		if ipNet.IP.To4() != nil {
			networkRule.Flags |= Ipv4Match
		} else {
			networkRule.Flags |= Ipv6Match
		}
	}

	if ipAddress != "" {
		networkRule.Flags |= PreciseMatch

		ip := net.ParseIP(ipAddress)
		if ip == nil {
			return nil, fmt.Errorf("the address is not a valid textual representation of an IP address")
		}

		networkRule.Address = ip.String()
		if ip.To4() != nil {
			networkRule.Flags |= Ipv4Match
		} else {
			networkRule.Flags |= Ipv6Match
		}
	}

	if port != 0 {
		networkRule.Flags |= PortMatch
		networkRule.Port = port
	}

	return &networkRule, nil
}

func newBpfMountRule(mode uint32, sourcePattern string, fstype string, mountFlags uint32, reverseMountFlags uint32) (*varmor.MountContent, error) {
	// Pre-check
	if len(fstype) >= bpfenforcer.MaxFileSystemTypeLength {
		return nil, fmt.Errorf("the length of fstype '%s' should be less than the maximum (%d)", fstype, bpfenforcer.MaxFileSystemTypeLength)
	}

	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, sourcePattern))

	if starWildcardLen > 0 && strings.Contains(sourcePattern, "**") {
		return nil, fmt.Errorf("the globbing * and ** in the pattern '%s' cannot be used at the same time", sourcePattern)
	}

	if starWildcardLen > 1 || strings.Count(sourcePattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern '%s' can only be used once", sourcePattern)
	}

	// Create bpfMountRule
	var mountRule varmor.MountContent
	var flags uint32

	mountRule.Mode = mode

	if starWildcardLen > 0 {
		if strings.Contains(sourcePattern, "/") {
			return nil, fmt.Errorf("the pattern '%s' with globbing * is not supported", sourcePattern)
		}

		stringList := strings.Split(sourcePattern, "*")

		if len(stringList[0]) > 0 {
			mountRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			mountRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else if strings.Contains(sourcePattern, "**") {
		flags |= GreedyMatch

		stringList := strings.Split(sourcePattern, "**")

		if len(stringList[0]) > 0 {
			mountRule.Pattern.Prefix = stringList[0]
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			mountRule.Pattern.Suffix = reverseString(stringList[1])
			flags |= SuffixMatch
		}
	} else {
		mountRule.Pattern.Prefix = sourcePattern
		flags |= PreciseMatch | PrefixMatch
	}

	if len(mountRule.Pattern.Prefix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of prefix '%s' should be less than the maximum (%d)", mountRule.Pattern.Prefix, bpfenforcer.MaxFilePathPatternLength)
	}

	if len(mountRule.Pattern.Suffix) >= bpfenforcer.MaxFilePathPatternLength {
		return nil, fmt.Errorf("the length of suffix '%s' should be less than the maximum (%d)", mountRule.Pattern.Suffix, bpfenforcer.MaxFilePathPatternLength)
	}

	mountRule.Pattern.Flags = flags
	mountRule.MountFlags = mountFlags
	mountRule.ReverseMountflags = reverseMountFlags
	mountRule.Fstype = fstype

	return &mountRule, nil
}
