// Copyright 2025 vArmor Authors
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
	"testing"

	"gotest.tools/assert"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	"github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func TestGenerateRawNetworkEgressRule_1(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "fdbd:dc01:ff:307:9329:268d:3a27:2ca7",
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, uint32(bpfenforcer.Ipv6Match|bpfenforcer.PreciseMatch), bpfContent.Networks[0].Flags)
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "fdbd:dc01:ff:307:9329:268d:3a27:2ca7")
}

func TestGenerateRawNetworkEgressRule_2(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "192.168.1.1",
				Ports: []varmor.Port{
					{
						Port: 80,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "192.168.1.1")
	assert.Equal(t, bpfContent.Networks[0].Address.Port, uint16(80))
}

func TestGenerateRawNetworkEgressRule_3(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				Ports: []varmor.Port{
					{
						Port: 80,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.PortMatch|bpfenforcer.Ipv4Match|bpfenforcer.Ipv6Match))
	assert.Equal(t, bpfContent.Networks[0].Address.Port, uint16(80))
}

func TestGenerateRawNetworkEgressRule_4(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				Ports: []varmor.Port{
					{
						Port:    80,
						EndPort: 8080,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.PortRangeMatch|bpfenforcer.Ipv4Match|bpfenforcer.Ipv6Match))
	assert.Equal(t, bpfContent.Networks[0].Address.Port, uint16(80))
	assert.Equal(t, bpfContent.Networks[0].Address.EndPort, uint16(8080))
}

func TestGenerateRawNetworkEgressRule_5(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				Ports: []varmor.Port{
					{
						Port: 80,
					},
					{
						Port: 81,
					},
					{
						Port: 82,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.PortsMatch|bpfenforcer.Ipv4Match|bpfenforcer.Ipv6Match))
	assert.DeepEqual(t, bpfContent.Networks[0].Address.Ports, []uint16{80, 81, 82})
}

func TestGenerateRawNetworkEgressRule_6(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "192.168.1.1",
				Ports: []varmor.Port{
					{
						Port:    80,
						EndPort: 8080,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortRangeMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "192.168.1.1")
	assert.Equal(t, bpfContent.Networks[0].Address.Port, uint16(80))
	assert.Equal(t, bpfContent.Networks[0].Address.EndPort, uint16(8080))
}

func TestGenerateRawNetworkEgressRule_7(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "192.168.1.1",
				Ports: []varmor.Port{
					{
						Port: 80,
					},
					{
						Port: 90,
					},
					{
						Port: 100,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortsMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "192.168.1.1")
	assert.DeepEqual(t, bpfContent.Networks[0].Address.Ports, []uint16{80, 90, 100})
}

func TestGenerateRawNetworkEgressRule_8(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP:    "192.168.1.1",
				Ports: []varmor.Port{{Port: 1}, {Port: 2}, {Port: 3}, {Port: 4}, {Port: 5}, {Port: 6}, {Port: 7}, {Port: 8}, {Port: 9}, {Port: 10}, {Port: 11}, {Port: 12}, {Port: 13}, {Port: 14}, {Port: 15}, {Port: 16}, {Port: 17}, {Port: 18}},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 2)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortsMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "192.168.1.1")
	assert.DeepEqual(t, bpfContent.Networks[0].Address.Ports, []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	assert.Equal(t, bpfContent.Networks[1].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortsMatch))
	assert.Equal(t, bpfContent.Networks[1].Address.IP, "192.168.1.1")
	assert.DeepEqual(t, bpfContent.Networks[1].Address.Ports, []uint16{17, 18})
}

func TestGenerateRawNetworkEgressRule_9(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				CIDR: "192.168.1.1/24",
				Ports: []varmor.Port{
					{
						Port: 1,
					},
					{
						Port: 2,
					},
					{
						Port:    100,
						EndPort: 110,
					},
					{
						Port: 3,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 2)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.CidrMatch|bpfenforcer.PortRangeMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "192.168.1.0")
	assert.Equal(t, bpfContent.Networks[0].Address.CIDR, "192.168.1.0/24")
	assert.DeepEqual(t, bpfContent.Networks[0].Address.Port, uint16(100))
	assert.DeepEqual(t, bpfContent.Networks[0].Address.EndPort, uint16(110))
	assert.Equal(t, bpfContent.Networks[1].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.CidrMatch|bpfenforcer.PortsMatch))
	assert.Equal(t, bpfContent.Networks[1].Address.IP, "192.168.1.0")
	assert.Equal(t, bpfContent.Networks[1].Address.CIDR, "192.168.1.0/24")
	assert.DeepEqual(t, bpfContent.Networks[1].Address.Ports, []uint16{1, 2, 3})
}

func TestGenerateRawNetworkEgressRule_10(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "10.37.31.68",
				Ports: []varmor.Port{
					{
						Port: 1,
					},
					{
						Port:    100,
						EndPort: 110,
					},
					{
						Port: 2,
					},
					{
						Port:    1000,
						EndPort: 1100,
					},
					{
						Port: 3,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 3)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortRangeMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "10.37.31.68")
	assert.DeepEqual(t, bpfContent.Networks[0].Address.Port, uint16(100))
	assert.DeepEqual(t, bpfContent.Networks[0].Address.EndPort, uint16(110))
	assert.Equal(t, bpfContent.Networks[1].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortRangeMatch))
	assert.Equal(t, bpfContent.Networks[1].Address.IP, "10.37.31.68")
	assert.DeepEqual(t, bpfContent.Networks[1].Address.Port, uint16(1000))
	assert.DeepEqual(t, bpfContent.Networks[1].Address.EndPort, uint16(1100))
	assert.Equal(t, bpfContent.Networks[2].Flags, uint32(bpfenforcer.Ipv4Match|bpfenforcer.PreciseMatch|bpfenforcer.PortsMatch))
	assert.Equal(t, bpfContent.Networks[2].Address.IP, "10.37.31.68")
	assert.DeepEqual(t, bpfContent.Networks[2].Address.Ports, []uint16{1, 2, 3})
}

func TestGenerateRawNetworkEgressRule_11(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "unspecified",
				Ports: []varmor.Port{
					{
						Port: 80,
					},
					{
						Port: 90,
					},
					{
						Port: 100,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.PreciseMatch|bpfenforcer.Ipv4Match|bpfenforcer.Ipv6Match|bpfenforcer.PortsMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "unspecified")
	assert.DeepEqual(t, bpfContent.Networks[0].Address.Ports, []uint16{80, 90, 100})
}

func TestGenerateRawNetworkEgressRule_12(t *testing.T) {
	rule := varmor.NetworkEgressRule{
		ToDestinations: []varmor.Destination{
			{
				IP: "pod-self",
				Ports: []varmor.Port{
					{
						Port: 80,
					},
				},
			},
		},
	}

	bpfContent := &varmor.BpfContent{}
	_, err := generateRawNetworkEgressRule(nil, bpfContent, 0, &rule, false)
	assert.NilError(t, err)
	assert.Equal(t, len(bpfContent.Networks), 1)
	assert.Equal(t, bpfContent.Networks[0].Flags, uint32(bpfenforcer.PodSelfIpMatch|bpfenforcer.Ipv4Match|bpfenforcer.Ipv6Match|bpfenforcer.PortMatch))
	assert.Equal(t, bpfContent.Networks[0].Address.IP, "pod-self")
	assert.Equal(t, bpfContent.Networks[0].Address.Port, uint16(80))
}
