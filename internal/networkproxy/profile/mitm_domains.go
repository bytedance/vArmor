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
	"net"
	"strings"
)

// ValidateMITMDomains rejects equivalent identities that would produce duplicate
// Envoy virtual hosts or filter-chain matches. It does not rewrite domains or
// merge header mutations: choosing between credentials on aliases is ambiguous.
// An empty list is permitted for callers representing disabled MITM.
func ValidateMITMDomains(domains []string) error {
	seen := make(map[string]int, len(domains))
	for i, raw := range domains {
		domain := strings.TrimSpace(raw)
		if domain == "" {
			return fmt.Errorf("mitm.domains[%d] must not be empty", i)
		}
		ip := net.ParseIP(domain)
		if strings.Contains(domain, "/") {
			parsedIP, network, err := net.ParseCIDR(domain)
			if err != nil {
				return fmt.Errorf("mitm.domains[%d]: invalid CIDR %q: %w", i, raw, err)
			}
			ones, bits := network.Mask.Size()
			if !((bits == 32 && ones == 32) || (bits == 128 && ones == 128)) {
				return fmt.Errorf("mitm.domains[%d]: CIDR %q has prefix length /%d; only /32 (IPv4) or /128 (IPv6) single-host CIDRs are allowed", i, raw, ones)
			}
			ip = parsedIP
		}
		identity := "dns:" + strings.ToLower(domain)
		if ip != nil {
			// net.IP.String also unifies IPv4-mapped IPv6 and IPv4 identities.
			identity = "ip:" + ip.String()
		}
		if previous, ok := seen[identity]; ok {
			return fmt.Errorf("mitm.domains[%d] %q duplicates the identity of mitm.domains[%d] %q", i, raw, previous, domains[previous])
		}
		seen[identity] = i
	}
	return nil
}
