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
	"context"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func generateCustomRules(
	kubeClient *kubernetes.Clientset,
	enhanceProtect *varmor.EnhanceProtect,
	bpfContent *varmor.BpfContent,
	mode uint32,
	enablePodServiceEgressControl bool,
	egressInfo *varmortypes.EgressInfo) (err error) {
	for _, rule := range enhanceProtect.BpfRawRules.Files {
		err = generateRawFileRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}

		err = generateRawProcessRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}
	}

	for _, rule := range enhanceProtect.BpfRawRules.Processes {
		err = generateRawFileRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}

		err = generateRawProcessRule(bpfContent, mode, rule)
		if err != nil {
			return err
		}
	}

	if enhanceProtect.BpfRawRules.Network != nil {
		for _, socketRule := range enhanceProtect.BpfRawRules.Network.Sockets {
			err = generateRawNetworkSocketRule(bpfContent, mode, socketRule)
			if err != nil {
				return err
			}
		}
		if enhanceProtect.BpfRawRules.Network.Egress != nil {
			err = generateRawNetworkEgressRule(kubeClient, bpfContent, mode, enhanceProtect.BpfRawRules.Network.Egress, enablePodServiceEgressControl, egressInfo)
			if err != nil {
				return err
			}
		}
	}

	if enhanceProtect.BpfRawRules.Ptrace != nil {
		err = generateRawPtraceRule(bpfContent, mode, enhanceProtect.BpfRawRules.Ptrace)
		if err != nil {
			return err
		}
	}

	if enhanceProtect.Privileged {
		for _, rule := range enhanceProtect.BpfRawRules.Mounts {
			err = generateRawMountRule(bpfContent, mode, rule)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func generateRawFileRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.FileRule) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "all", "*":
			permissions |= bpfenforcer.AaMayRead | bpfenforcer.AaMayWrite | bpfenforcer.AaMayAppend
		case "read", "r":
			permissions |= bpfenforcer.AaMayRead
		case "write", "w":
			permissions |= bpfenforcer.AaMayWrite
			permissions |= bpfenforcer.AaMayAppend
		case "append", "a":
			permissions |= bpfenforcer.AaMayAppend
		}
	}

	if permissions == 0 {
		return nil
	}

	fileContent, err := newBpfPathRule(mode, rule.Pattern, permissions)
	if err != nil {
		return err
	}
	bpfContent.Files = append(bpfContent.Files, *fileContent)

	return nil
}

func generateRawProcessRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.FileRule) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "all", "*":
			permissions |= bpfenforcer.AaMayExec
		case "exec", "x":
			permissions |= bpfenforcer.AaMayExec
		}
	}

	if permissions == 0 {
		return nil
	}

	fileContent, err := newBpfPathRule(mode, rule.Pattern, permissions)
	if err != nil {
		return err
	}
	bpfContent.Processes = append(bpfContent.Processes, *fileContent)

	return nil
}

func generateRawNetworkSocketRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.NetworkSocketRule) error {
	var domains, types, protocols uint64

	for _, domain := range rule.Domains {
		switch strings.ToLower(domain) {
		case "all", "*":
			domains = 1<<unix.AF_UNIX | 1<<unix.AF_INET | 1<<unix.AF_AX25 | 1<<unix.AF_IPX |
				1<<unix.AF_APPLETALK | 1<<unix.AF_NETROM | 1<<unix.AF_BRIDGE | 1<<unix.AF_ATMPVC |
				1<<unix.AF_X25 | 1<<unix.AF_INET6 | 1<<unix.AF_ROSE | 1<<unix.AF_NETBEUI |
				1<<unix.AF_SECURITY | 1<<unix.AF_KEY | 1<<unix.AF_NETLINK | 1<<unix.AF_PACKET |
				1<<unix.AF_ASH | 1<<unix.AF_ECONET | 1<<unix.AF_ATMSVC | 1<<unix.AF_RDS |
				1<<unix.AF_SNA | 1<<unix.AF_IRDA | 1<<unix.AF_PPPOX | 1<<unix.AF_WANPIPE |
				1<<unix.AF_LLC | 1<<unix.AF_IB | 1<<unix.AF_MPLS | 1<<unix.AF_CAN |
				1<<unix.AF_TIPC | 1<<unix.AF_BLUETOOTH | 1<<unix.AF_IUCV | 1<<unix.AF_RXRPC |
				1<<unix.AF_ISDN | 1<<unix.AF_PHONET | 1<<unix.AF_IEEE802154 | 1<<unix.AF_CAIF |
				1<<unix.AF_ALG | 1<<unix.AF_NFC | 1<<unix.AF_VSOCK | 1<<unix.AF_KCM |
				1<<unix.AF_QIPCRTR | 1<<unix.AF_SMC | 1<<unix.AF_XDP | 1<<unix.AF_MCTP
		case "unix":
			domains |= 1 << unix.AF_UNIX
		case "inet":
			domains |= 1 << unix.AF_INET
		case "ax25":
			domains |= 1 << unix.AF_AX25
		case "ipx":
			domains |= 1 << unix.AF_IPX
		case "appletalk":
			domains |= 1 << unix.AF_APPLETALK
		case "netrom":
			domains |= 1 << unix.AF_NETROM
		case "bridge":
			domains |= 1 << unix.AF_BRIDGE
		case "atmpvc":
			domains |= 1 << unix.AF_ATMPVC
		case "x25":
			domains |= 1 << unix.AF_X25
		case "inet6":
			domains |= 1 << unix.AF_INET6
		case "rose":
			domains |= 1 << unix.AF_ROSE
		case "netbeui":
			domains |= 1 << unix.AF_NETBEUI
		case "security":
			domains |= 1 << unix.AF_SECURITY
		case "key":
			domains |= 1 << unix.AF_KEY
		case "netlink":
			domains |= 1 << unix.AF_NETLINK
		case "packet":
			domains |= 1 << unix.AF_PACKET
		case "ash":
			domains |= 1 << unix.AF_ASH
		case "econet":
			domains |= 1 << unix.AF_ECONET
		case "atmsvc":
			domains |= 1 << unix.AF_ATMSVC
		case "rds":
			domains |= 1 << unix.AF_RDS
		case "sna":
			domains |= 1 << unix.AF_SNA
		case "irda":
			domains |= 1 << unix.AF_IRDA
		case "pppox":
			domains |= 1 << unix.AF_PPPOX
		case "wanpipe":
			domains |= 1 << unix.AF_WANPIPE
		case "llc":
			domains |= 1 << unix.AF_LLC
		case "ib":
			domains |= 1 << unix.AF_IB
		case "mpls":
			domains |= 1 << unix.AF_MPLS
		case "can":
			domains |= 1 << unix.AF_CAN
		case "tipc":
			domains |= 1 << unix.AF_TIPC
		case "bluetooth":
			domains |= 1 << unix.AF_BLUETOOTH
		case "iucv":
			domains |= 1 << unix.AF_IUCV
		case "rxrpc":
			domains |= 1 << unix.AF_RXRPC
		case "isdn":
			domains |= 1 << unix.AF_ISDN
		case "phonet":
			domains |= 1 << unix.AF_PHONET
		case "ieee802154":
			domains |= 1 << unix.AF_IEEE802154
		case "caif":
			domains |= 1 << unix.AF_CAIF
		case "alg":
			domains |= 1 << unix.AF_ALG
		case "nfc":
			domains |= 1 << unix.AF_NFC
		case "vsock":
			domains |= 1 << unix.AF_VSOCK
		case "kcm":
			domains |= 1 << unix.AF_KCM
		case "qipcrtr":
			domains |= 1 << unix.AF_QIPCRTR
		case "smc":
			domains |= 1 << unix.AF_SMC
		case "xdp":
			domains |= 1 << unix.AF_XDP
		case "mctp":
			domains |= 1 << unix.AF_MCTP
		default:
			return fmt.Errorf("policy contains an illegal NetworkSocketRule rule, found unknown or unsupported socket domain (%s)", domain)
		}
	}

	for _, t := range rule.Types {
		switch strings.ToLower(t) {
		case "all", "*":
			types = 1<<unix.SOCK_STREAM | 1<<unix.SOCK_DGRAM | 1<<unix.SOCK_RAW |
				1<<unix.SOCK_RDM | 1<<unix.SOCK_SEQPACKET | 1<<unix.SOCK_DCCP | 1<<unix.SOCK_PACKET
		case "stream":
			types |= 1 << unix.SOCK_STREAM
		case "dgram":
			types |= 1 << unix.SOCK_DGRAM
		case "raw":
			types |= 1 << unix.SOCK_RAW
		case "rdm":
			types |= 1 << unix.SOCK_RDM
		case "seqpacket":
			types |= 1 << unix.SOCK_SEQPACKET
		case "dccp":
			types |= 1 << unix.SOCK_DCCP
		case "packet":
			types |= 1 << unix.SOCK_PACKET
		default:
			return fmt.Errorf("policy contains an illegal NetworkSocketRule rule, found unknown or unsupported socket type (%s)", t)
		}
	}

	for _, protocol := range rule.Protocols {
		switch strings.ToLower(protocol) {
		case "all", "*":
			protocols = 1<<unix.IPPROTO_ICMP | 1<<unix.IPPROTO_ICMPV6 | 1<<unix.IPPROTO_TCP | 1<<unix.IPPROTO_UDP
		case "icmp":
			protocols |= 1<<unix.IPPROTO_ICMP | 1<<unix.IPPROTO_ICMPV6
		case "tcp":
			protocols |= 1 << unix.IPPROTO_TCP
		case "udp":
			protocols |= 1 << unix.IPPROTO_UDP
		default:
			return fmt.Errorf("policy contains an illegal NetworkSocketRule rule, found unknown or unsupported socket protocol (%s)", protocol)
		}
	}

	networkContent, err := newBpfNetworkCreateRule(mode, domains, types, protocols)
	if err != nil {
		return err
	}
	if !varmorutils.InNetworksArray(*networkContent, bpfContent.Networks) {
		bpfContent.Networks = append(bpfContent.Networks, *networkContent)
	}

	return nil
}

func GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent *varmor.BpfContent, mode uint32, CIDR string, IP string, Ports []varmor.Port) error {
	var ports []uint16
	var portRanges []varmor.Port

	// Regroup the port and port range
	for _, port := range Ports {
		if port.Port != 0 && (port.EndPort == 0 || port.Port == port.EndPort) {
			if !varmorutils.InUint16Array(port.Port, ports) {
				ports = append(ports, port.Port)
			}
		} else if port.Port != 0 && port.EndPort != 0 && port.EndPort > port.Port {
			pr := varmor.Port{
				Port:    port.Port,
				EndPort: port.EndPort,
			}
			if !varmorutils.InPortRangeArray(pr, portRanges) {
				portRanges = append(portRanges, pr)
			}
		} else {
			return fmt.Errorf("policy contains an illegal NetworkEgressRule rule, found invalid port(%d) or endPort(%d)", port.Port, port.EndPort)
		}
	}

	if len(ports) == 0 && len(portRanges) == 0 {
		// If no ports or port ranges are specified, this rule matches all ports
		networkContent, err := newBpfNetworkConnectRule(mode, CIDR, IP, 0, 0, nil)
		if err != nil {
			return err
		}
		if !varmorutils.InNetworksArray(*networkContent, bpfContent.Networks) {
			bpfContent.Networks = append(bpfContent.Networks, *networkContent)
		}
		return nil
	} else {
		// For port ranges, we need to create a separate rule for each range
		for _, portRange := range portRanges {
			networkContent, err := newBpfNetworkConnectRule(mode, CIDR, IP, portRange.Port, portRange.EndPort, nil)
			if err != nil {
				return err
			}
			if !varmorutils.InNetworksArray(*networkContent, bpfContent.Networks) {
				bpfContent.Networks = append(bpfContent.Networks, *networkContent)
			}
		}

		// If multiple ports are specified, we need to group them into chunks of 16
		for i := 0; i < len(ports); i += 16 {
			end := i + 16
			if end > len(ports) {
				end = len(ports)
			}
			group := ports[i:end]
			if len(group) == 1 {
				// If only one port is specified, we can use it directly
				networkContent, err := newBpfNetworkConnectRule(mode, CIDR, IP, group[0], 0, nil)
				if err != nil {
					return err
				}
				if !varmorutils.InNetworksArray(*networkContent, bpfContent.Networks) {
					bpfContent.Networks = append(bpfContent.Networks, *networkContent)
				}
			} else {
				networkContent, err := newBpfNetworkConnectRule(mode, CIDR, IP, 0, 0, &group)
				if err != nil {
					return err
				}
				if !varmorutils.InNetworksArray(*networkContent, bpfContent.Networks) {
					bpfContent.Networks = append(bpfContent.Networks, *networkContent)
				}
			}
		}
	}
	return nil
}

func generateRawNetworkEgressRuleForDestinations(bpfContent *varmor.BpfContent, mode uint32, destinations []varmor.Destination) error {
	for _, destination := range destinations {
		if destination.IP == varmor.LocalhostIP {
			err := GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, destination.CIDR, "127.0.0.1", destination.Ports)
			if err != nil {
				return err
			}
			err = GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, destination.CIDR, "::1", destination.Ports)
			if err != nil {
				return err
			}
		} else {
			err := GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, destination.CIDR, destination.IP, destination.Ports)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func generateRawNetworkEgressRuleForPods(
	kubeClient *kubernetes.Clientset,
	bpfContent *varmor.BpfContent,
	mode uint32,
	toPod varmor.Pod) (pod *varmortypes.Pod, err error) {

	p := varmortypes.Pod{
		Mode:        mode,
		Namespace:   toPod.Namespace,
		PodSelector: toPod.PodSelector,
		Ports:       toPod.Ports,
	}

	// Select pods and retrieve their IPs
	podSelector, err := metav1.LabelSelectorAsSelector(toPod.PodSelector)
	if err != nil {
		return nil, err
	}
	podList, err := kubeClient.CoreV1().Pods(toPod.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector:   podSelector.String(),
		ResourceVersion: "0",
	})
	if err != nil {
		return nil, err
	}

	var IPs []string
	for _, p := range podList.Items {
		for _, ip := range p.Status.PodIPs {
			IPs = append(IPs, ip.IP)
		}
	}

	// generate rules with pods' IPs
	for _, IP := range IPs {
		err := GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, "", IP, toPod.Ports)
		if err != nil {
			return nil, err
		}
	}

	return &p, nil
}

func generateRawNetworkEgressRuleForServices(
	kubeClient *kubernetes.Clientset,
	bpfContent *varmor.BpfContent,
	mode uint32,
	toService varmor.Service) (*varmortypes.Service, error) {

	if toService.ServiceSelector != nil && toService.Name != "" {
		return nil, fmt.Errorf("the ServiceSelector field and name field are mutually exclusive")
	}

	if toService.ServiceSelector == nil && (toService.Name == "" || toService.Namespace == "") {
		return nil, fmt.Errorf("please set both the name and namespace fields to select a service")
	}

	s := varmortypes.Service{
		Mode:            mode,
		Namespace:       toService.Namespace,
		Name:            toService.Name,
		ServiceSelector: toService.ServiceSelector,
	}

	var epsLabelSelector string

	if toService.ServiceSelector != nil {
		// Retrieve the services with the label selector
		serviceSelector, err := metav1.LabelSelectorAsSelector(toService.ServiceSelector)
		if err != nil {
			return nil, err
		}
		serviceList, err := kubeClient.CoreV1().Services(toService.Namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector:   serviceSelector.String(),
			ResourceVersion: "0",
		})
		if err != nil {
			return nil, err
		}
		epsLabelSelector = serviceSelector.String()

		// Generate rules for the services
		for _, service := range serviceList.Items {
			for _, ip := range service.Spec.ClusterIPs {
				err := GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, "", ip, []varmor.Port{})
				if err != nil {
					return nil, err
				}
			}
		}
	} else {
		// Retrieve the service with name and namespace
		service, err := kubeClient.CoreV1().Services(toService.Namespace).Get(context.TODO(), toService.Name, metav1.GetOptions{})
		if err != nil {
			if k8errors.IsNotFound(err) {
				return &s, nil
			} else {
				return nil, err
			}
		}
		epsLabelSelector = fmt.Sprintf("kubernetes.io/service-name=%s", toService.Name)

		// Generate rules for the service
		for _, ip := range service.Spec.ClusterIPs {
			err := GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, "", ip, []varmor.Port{})
			if err != nil {
				return nil, err
			}
		}
	}

	// Retrieve the endpointslices of services with the label selector
	epsList, err := kubeClient.DiscoveryV1().EndpointSlices(toService.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector:   epsLabelSelector,
		ResourceVersion: "0",
	})
	if err != nil {
		return nil, err
	}

	// Generate rules for the endpointslices
	for _, eps := range epsList.Items {
		ips := []string{}
		for _, ep := range eps.Endpoints {
			ips = append(ips, ep.Addresses...)
		}

		ports := []varmor.Port{}
		for _, port := range eps.Ports {
			if port.Port != nil {
				ports = append(ports, varmor.Port{
					Port: uint16(*port.Port),
				})
			}
		}

		for _, ip := range ips {
			err := GenerateRawNetworkEgressRuleWithIpCidrPorts(bpfContent, mode, "", ip, ports)
			if err != nil {
				return nil, err
			}
		}
	}

	return &s, nil
}

func generateRawNetworkEgressRule(
	kubeClient *kubernetes.Clientset,
	bpfContent *varmor.BpfContent,
	mode uint32,
	rule *varmor.NetworkEgressRule,
	enablePodServiceEgressControl bool,
	egressInfo *varmortypes.EgressInfo) error {

	err := generateRawNetworkEgressRuleForDestinations(bpfContent, mode, rule.ToDestinations)
	if err != nil {
		return fmt.Errorf("failed to generate network egress rule for bolocking access destinations. error: %w", err)
	}

	if len(rule.ToPods) == 0 && len(rule.ToServices) == 0 {
		return nil
	}

	if (len(rule.ToPods) != 0 || len(rule.ToServices) != 0) && !enablePodServiceEgressControl {
		return fmt.Errorf("the PodServiceEgressControl feature is required to generate network egress rule for Pods and Services")
	}

	for _, toPod := range rule.ToPods {
		pod, err := generateRawNetworkEgressRuleForPods(kubeClient, bpfContent, mode, toPod)
		if err != nil {
			return fmt.Errorf("failed to generate network egress rule for blocking access k8s pods. error: %w", err)
		}
		if pod != nil {
			egressInfo.ToPods = append(egressInfo.ToPods, *pod)
		}
	}

	for _, toService := range rule.ToServices {
		service, err := generateRawNetworkEgressRuleForServices(kubeClient, bpfContent, mode, toService)
		if err != nil {
			return fmt.Errorf("failed to generate network egress rule for blocking access k8s services. error: %w", err)
		}
		if service != nil {
			egressInfo.ToServices = append(egressInfo.ToServices, *service)
		}
	}

	return nil
}

func generateRawPtraceRule(bpfContent *varmor.BpfContent, mode uint32, rule *varmor.PtraceRule) error {
	var permissions uint32

	for _, permission := range rule.Permissions {
		switch strings.ToLower(permission) {
		case "all", "*":
			permissions |= bpfenforcer.AaPtraceTrace | bpfenforcer.AaPtraceRead | bpfenforcer.AaMayBeTraced | bpfenforcer.AaMayBeRead
		case "trace":
			permissions |= bpfenforcer.AaPtraceTrace
		case "read":
			permissions |= bpfenforcer.AaPtraceRead
		case "traceby":
			permissions |= bpfenforcer.AaMayBeTraced
		case "readby":
			permissions |= bpfenforcer.AaMayBeRead
		}
	}

	if permissions != 0 {
		if rule.StrictMode {
			setBpfPtraceRule(bpfContent, mode, permissions, bpfenforcer.GreedyMatch)
		} else {
			setBpfPtraceRule(bpfContent, mode, permissions, bpfenforcer.PreciseMatch)
		}
	}

	return nil
}

func generateRawMountRule(bpfContent *varmor.BpfContent, mode uint32, rule varmor.MountRule) error {
	var mountFlags, reverseMountFlags uint32

	for _, flag := range rule.Flags {
		switch strings.ToLower(flag) {
		// All Flags:
		case "all", "*":
			mountFlags = 0xFFFFFFFF
			reverseMountFlags = 0xFFFFFFFF
		// Command Flags
		case "remount":
			mountFlags |= unix.MS_REMOUNT
		case "bind", "B":
			mountFlags |= unix.MS_BIND
		case "move", "M":
			mountFlags |= unix.MS_MOVE
		case "rbind", "R":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
		case "make-unbindable":
			mountFlags |= unix.MS_UNBINDABLE
		case "make-private":
			mountFlags |= unix.MS_PRIVATE
		case "make-slave":
			mountFlags |= unix.MS_SLAVE
		case "make-shared":
			mountFlags |= unix.MS_SHARED
		case "make-runbindable":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_UNBINDABLE
		case "make-rprivate":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_PRIVATE
		case "make-rslave":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_SLAVE
		case "make-rshared":
			mountFlags |= unix.MS_BIND
			mountFlags |= unix.MS_REC
			mountFlags |= unix.MS_SHARED
		// Generic Flags
		case "ro", "r", "read-only":
			mountFlags |= unix.MS_RDONLY
		case "nosuid":
			mountFlags |= unix.MS_NOSUID
		case "nodev":
			mountFlags |= unix.MS_NODEV
		case "noexec":
			mountFlags |= unix.MS_NOEXEC
		case "sync":
			mountFlags |= unix.MS_SYNCHRONOUS
		case "mand":
			mountFlags |= unix.MS_MANDLOCK
		case "dirsync":
			mountFlags |= unix.MS_DIRSYNC
		case "noatime":
			mountFlags |= unix.MS_NOATIME
		case "nodiratime":
			mountFlags |= unix.MS_NODIRATIME
		case "silent":
			mountFlags |= unix.MS_SILENT
		case "relatime":
			mountFlags |= unix.MS_RELATIME
		case "iversion":
			mountFlags |= unix.MS_I_VERSION
		case "strictatime":
			mountFlags |= unix.MS_STRICTATIME
		case "rw", "w":
			reverseMountFlags |= unix.MS_RDONLY
		case "suid":
			reverseMountFlags |= unix.MS_NOSUID
		case "dev":
			reverseMountFlags |= unix.MS_NODEV
		case "exec":
			reverseMountFlags |= unix.MS_NOEXEC
		case "async":
			reverseMountFlags |= unix.MS_SYNCHRONOUS
		case "nomand":
			reverseMountFlags |= unix.MS_MANDLOCK
		case "atime":
			reverseMountFlags |= unix.MS_NOATIME
		case "diratime":
			reverseMountFlags |= unix.MS_NODIRATIME
		case "loud":
			reverseMountFlags |= unix.MS_SILENT
		case "norelatime":
			reverseMountFlags |= unix.MS_RELATIME
		case "noiversion":
			reverseMountFlags |= unix.MS_I_VERSION
		case "nostrictatime":
			reverseMountFlags |= unix.MS_STRICTATIME
		// Custom Flags
		case "umount":
			mountFlags |= bpfenforcer.AaMayUmount
		}
	}

	mountContent, err := newBpfMountRule(mode, rule.SourcePattern, rule.Fstype, mountFlags, reverseMountFlags)
	if err != nil {
		return err
	}
	bpfContent.Mounts = append(bpfContent.Mounts, *mountContent)

	return nil
}
