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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestRenderPermissionRuleYAML_DestinationIP(t *testing.T) {
	for _, tc := range []struct {
		name, input, address string
		prefix               int
		allowed, denied      string
	}{
		{"IPv4 host", "192.0.2.1", "192.0.2.1", 32, "192.0.2.1", "192.0.2.2"},
		{"IPv6 host", "2001:db8::1", "2001:db8::1", 128, "2001:db8::1", "2001:db8::2"},
		{"expanded IPv6 host", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1", 128, "2001:db8::1", "2001:db8::2"},
		{"mapped IPv4 host", "::ffff:192.0.2.1", "192.0.2.1", 32, "192.0.2.1", "192.0.2.2"},
		{"IPv4 host CIDR", "192.0.2.1/32", "192.0.2.1", 32, "192.0.2.1", "192.0.2.2"},
		{"IPv6 host CIDR", "2001:db8::1/128", "2001:db8::1", 128, "2001:db8::1", "2001:db8::2"},
		{"mapped IPv4 host CIDR", "::ffff:192.0.2.1/128", "192.0.2.1", 32, "192.0.2.1", "192.0.2.2"},
		{"mapped IPv4 subnet", "::ffff:192.0.2.1/120", "192.0.2.0", 24, "192.0.2.2", "192.0.3.1"},
		{"mapped IPv4 pair", "::ffff:c000:201/127", "192.0.2.0", 31, "192.0.2.1", "192.0.2.2"},
		{"IPv4 subnet", "192.0.2.1/24", "192.0.2.0", 24, "192.0.2.2", "192.0.3.1"},
		{"IPv6 subnet", "2001:db8::1/64", "2001:db8::", 64, "2001:db8::2", "2001:db8:0:1::1"},
	} {
		for _, rbacType := range []string{"http", "network"} {
			t.Run(tc.name+"/"+rbacType, func(t *testing.T) {
				rendered := renderPermissionRuleYAML(PermissionRule{Type: "destination_ip", Value: tc.input}, 0, rbacType)
				var rules []struct {
					DestinationIP struct {
						Address string `json:"address_prefix"`
						Prefix  int    `json:"prefix_len"`
					} `json:"destination_ip"`
				}
				require.NoError(t, yaml.UnmarshalStrict([]byte(rendered), &rules))
				require.Len(t, rules, 1)
				got := rules[0].DestinationIP
				require.Equal(t, tc.address, got.Address)
				require.Equal(t, tc.prefix, got.Prefix)
				_, subnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", got.Address, got.Prefix))
				require.NoError(t, err)
				require.True(t, subnet.Contains(net.ParseIP(tc.allowed)), "configured destination must match")
				require.False(t, subnet.Contains(net.ParseIP(tc.denied)), "neighbor outside the configured range must not match")
			})
		}
	}
}

// Check address-set semantics independently of the renderer, including every
// prefix length and both sides of each prefix boundary. Wide IPv6 prefixes
// must keep their IPv6 family even when the input host is IPv4-mapped.
func TestCIDRToPrefixRange_AddressSets(t *testing.T) {
	for _, seed := range []string{"192.0.2.129", "2001:db8:1234::abcd", "::ffff:192.0.2.129"} {
		host := netip.MustParseAddr(seed)
		for bits := 0; bits <= host.BitLen(); bits++ {
			input := netip.PrefixFrom(host, bits)
			t.Run(input.String(), func(t *testing.T) {
				expected := input.Masked()
				if host.Is4In6() && bits >= 96 {
					expected = netip.PrefixFrom(host.Unmap(), bits-96).Masked()
				}
				address, prefix := cidrToPrefixRange(input.String())
				actual, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", address, prefix))
				require.NoError(t, err)
				require.Equal(t, expected, actual)
				first := expected.Addr()
				raw := first.AsSlice()
				for bit := expected.Bits(); bit < first.BitLen(); bit++ {
					raw[bit/8] |= byte(1 << (7 - bit%8))
				}
				last, ok := netip.AddrFromSlice(raw)
				require.True(t, ok)
				for _, dest := range []netip.Addr{first, last, first.Prev(), last.Next(), host, host.Unmap(), netip.MustParseAddr("::1")} {
					if dest.IsValid() {
						require.Equal(t, expected.Contains(dest), actual.Contains(dest), "destination %s", dest)
					}
				}
			})
		}
	}
}
