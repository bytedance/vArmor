/*
Copyright The vArmor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FileRule struct {
	// pattern can be any string (maximum length 128 bytes) that conforms to the policy syntax,
	// used for matching file paths and filenames.
	Pattern string `json:"pattern"`
	// permissions are used to specify the file permissions.
	//
	// Available values: all(*), read(r), write(w), exec(x), append(a)
	Permissions []string `json:"permissions"`
}

type Service struct {
	// namespace selects a service by the name and namespace pair.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// name selects a service by the name and namespace pair.
	// +optional
	Name string `json:"name,omitempty"`
	// serviceSelector is a label selector which selects services. This field follows standard label
	// selector semantics. It selects the services matching serviceSelector in all namespaces.
	// Note that the serviceSelector field and other fields are mutually exclusive.
	// +optional
	ServiceSelector *metav1.LabelSelector `json:"serviceSelector,omitempty"`
}

// Port describes a port or port range to match traffic.
type Port struct {
	// port is the port number to match traffic. The port number must be in the range [1, 65535].
	Port uint16 `json:"port"`
	// If endPort is set, it indicates that the range of ports from port to endPort. The endPort must be equal or greater
	// than port and must be in the range [1, 65535].
	// +optional
	EndPort uint16 `json:"endPort,omitempty"`
}

type Pod struct {
	// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
	// standard label selector semantics; if not present, it selects all namespaces.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// podSelector is a label selector which selects pods. This field follows standard label
	// selector semantics.
	//
	// If namespaceSelector is also set, then this rule selects the pods matching podSelector in
	// the namespaces selected by NamespaceSelector. Otherwise it selects the pods matching podSelector
	// in all namespaces.
	PodSelector *metav1.LabelSelector `json:"podSelector"`
	// ports define this rule on particular ports. Each item in this list is combined using a logical OR.
	// If this field is empty or not present, this rule matches all ports. If this field is present and contains
	// at least one item, then this rule matches all ports in the list.
	// +optional
	Ports []Port `json:"ports,omitempty"`
}

const (
	// PodSelfIP is an entity that represents the Pod's own IP addresses.
	// Please note that pods may be allocated at most 1 address for each of IPv4 and IPv6.
	PodSelfIP string = "pod-self"
	// Unspecified is an entity that represents the all-zeros address — specifically, 0.0.0.0 and ::.
	// Its full name is unspecified address, referring to binding to all interfaces.
	Unspecified string = "unspecified"
	// LocalhostIP is an entity that represents the loopback addresses - specifically, 127.0.0.1 and ::1.
	LocalhostIP string = "localhost"
)

type Destination struct {
	// ip defines this rule on a particular IP. Please use a valid textual representation of an IP, or special
	// entities like "pod-self", "unspecified" or "localhost". Note that the ip field and cidr field are mutually exclusive.
	// +optional
	IP string `json:"ip,omitempty"`
	// cidr defines this rule on a particular CIDR. Note that the ip field and cidr field are mutually exclusive.
	// +optional
	CIDR string `json:"cidr,omitempty"`
	// ports defines this rule on particular ports. Each item in this list is combined using a logical OR.
	// If this field is empty or not present, this rule matches all ports. If this field is present and contains
	// at least one item, then this rule matches all ports in the list.
	// +optional
	Ports []Port `json:"ports,omitempty"`
}

// Egress describes the network egress rules to match traffic for connect(2) operations.
// Notes:
// - The ToDestinations, ToEntities, ToServices, and ToPods fields are in a logical OR relationship.
// - Within the same field, multiple rules are also in a logical OR relationship.
// - Overlapping rules targeting the same Pod/Service/IP may cause unintended port combinations or conflicts.
// - The system does NOT guarantee deduplication or conflict resolution for overlapping targets. Users must ensure that
// rules within these fields do NOT repeatedly define the same Pod/Service/IP to avoid unpredictable traffic control behavior.
type NetworkEgressRule struct {
	// toDestinations describes specific IPs or IP blocks with ports to match traffic.
	// Please ensure each IP/CIDR target is unique to avoid configuration ambiguity.
	// +optional
	ToDestinations []Destination `json:"toDestinations,omitempty"`
	// toServices describes k8s services and their endpoints to match traffic.
	// Please ensure selectors across service rules do NOT overlap. Overlapping rules may cause undefined behavior.
	// +optional
	ToServices []Service `json:"toServices,omitempty"`
	// toPods describes pods with ports to match traffic.
	// Please ensure selectors across pod rules do NOT overlap. Overlapping rules may cause undefined behavior.
	// +optional
	ToPods []Pod `json:"toPods,omitempty"`
}

// NetworkSocketRule describes a network socket rule to match traffic for socket(2) operations.
type NetworkSocketRule struct {
	// domains specifies the communication domains of socket.
	//
	// Available values:
	//       all(*), unix, inet, ax25, ipx, appletalk, netrom, bridge, atmpvc, x25,
	//       inet6, rose, netbeui, security, key, netlink, packet, ash, econet, atmsvc,
	//       rds, sna, irda, pppox, wanpipe, llc, ib, mpls, can, tipc, bluetooth, iucv,
	//       rxrpc, isdn, phonet, ieee802154, caif, alg, nfc, vsock, kcm, qipcrtr, smc,
	//       xdp, mctp
	// +optional
	Domains []string `json:"domains,omitempty"`
	// types specifies the communication semantics of socket.
	//
	// Available values: all(*), stream, dgram, raw, rdm, seqpacket, dccp, packet
	// +optional
	Types []string `json:"types,omitempty"`
	// protocols specifies the particular protocols to be used with the socket.
	// Note that the protocols field and types field are mutually exclusive.
	//
	// Available values: all(*), icmp, tcp, udp
	// +optional
	Protocols []string `json:"protocols,omitempty"`
}

// NetworkRule describes a network rule to match traffic
type NetworkRule struct {
	// sockets are the list of network socket rules to match traffic for socket(2) operations.
	// +optional
	Sockets []NetworkSocketRule `json:"sockets,omitempty"`
	// egress defines network egress rules to match traffic for connect(2) operations.
	// Notes:
	// - The ToDestinations, ToServices, and ToPods fields are in a logical OR relationship.
	// - Within the same field, multiple rules are also in a logical OR relationship.
	// - Overlapping rules targeting the same Pod/Service/IP may cause unintended port combinations or conflicts.
	// - The system does not guarantee deduplication or conflict resolution for overlapping targets. Users must ensure that
	// rules within these fields do not repeatedly define the same Pod/Service/IP to avoid unpredictable traffic control behavior.
	// +optional
	Egress *NetworkEgressRule `json:"egress,omitempty"`
}

type PtraceRule struct {
	// strictMode is used to indicate whether to restrict ptrace operations for all source and destination processes.
	// Default is false.
	// If set to false, it allows a process to perform trace and read operations on other processes within the same container,
	// and also allows a process to be subjected to traceby and readby operations by other processes within the same container.
	// If set to true, it prohibits all trace, read, traceby, and readby operations within the container.
	// +optional
	StrictMode bool `json:"strictMode,omitempty"`
	// permissions are used to indicate which ptrace-related permissions of the target container should be restricted.
	//
	// Available values: all(*), trace, traceby, read, readby.
	//    - trace: prohibiting tracing of other processes.
	//    - read: prohibiting reading of other processes.
	//    - traceby: prohibiting being traced by other processes (excluding the host processes).
	//    - readby: prohibiting being read by other processes (excluding the host processes).
	//
	//  The trace, traceby permissions for "write" operations, or other operations that are more dangerous, such as:
	//  ptrace attaching (PTRACE_ATTACH) to another process or calling process_vm_writev(2).
	//
	//  The read, readby permissions for "read" operations or other operations that are less dangerous, such as:
	//  get_robust_list(2); kcmp(2); reading /proc/pid/auxv, /proc/pid/environ, or /proc/pid/stat; or readlink(2)
	//  of a /proc/pid/ns/* file.
	Permissions []string `json:"permissions"`
}

type MountRule struct {
	// sourcePattern can be any string (maximum length 128 bytes) that conforms to the policy syntax, used for matching the
	// source paramater of mount(2), the target paramater of umount(2), and the from_pathname paramater of move_mount(2).
	SourcePattern string `json:"sourcePattern"`
	// fstype is used to specify the type of filesystem (maximum length 16 bytes) to enforce. It can be '*' to match any type.
	Fstype string `json:"fstype"`
	// flags are used to specify the mount flags to enforce. They are almost the same as the 'MOUNT FLAGS LIST' of AppArmor.
	//
	// Available values:
	//       All Flags: all(*)
	//   Command Flags: ro(r, read-only), rw(w), suid, nosuid, dev, nodev, exec, noexec,
	//                  sync, async, mand, nomand, dirsync, atime, noatime, diratime, nodiratime,
	//                  silent, loud, relatime, norelatime, iversion, noiversion, strictatime,
	//                  nostrictatime
	//   Generic Flags: remount, bind(B), move(M), rbind(R), make-unbindable, make-private(private),
	//                  make-slave(slave), make-shared(shared), make-runbindable, make-rprivate,
	//                  make-rslave, make-rshared
	//     Other Flags: umount
	Flags []string `json:"flags"`
}

type BpfRawRules struct {
	// files specifies the file access control rules.
	Files []FileRule `json:"files,omitempty"`
	// processes specifies the process access control rules.
	Processes []FileRule `json:"processes,omitempty"`
	// network specifies the network access control rules.
	Network *NetworkRule `json:"network,omitempty"`
	// ptrace specifies the ptrace-based access control rules.
	Ptrace *PtraceRule `json:"ptrace,omitempty"`
	// mounts specifies mount point access control rules.
	Mounts []MountRule `json:"mounts,omitempty"`
}
