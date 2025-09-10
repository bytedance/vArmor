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

package bpfenforcer

import "golang.org/x/sys/unix"

const (
	// MaxTargetContainerCountForBpfLsm is the maximum count of target containers for BPF LSM,
	// it's equal to the OUTER_MAP_ENTRIES_MAX of BPF code
	MaxTargetContainerCountForBpfLsm int = 110

	// MaxBpfFileRuleCount is the maximum rule count of file operation primitive.
	MaxBpfFileRuleCount = 50

	// MaxBpfBprmRuleCount is the maximum rule count of execution file primitive.
	MaxBpfBprmRuleCount = 50

	// MaxBpfNetworkRuleCount is the maximum rule count of network access primitive.
	MaxBpfNetworkRuleCount = 50

	// MaxBpfMountRuleCount is the maximum rule count of mount operation primitive.
	MaxBpfMountRuleCount = 50

	// MaxFilePathPatternLength is the maximum length of path pattern,
	// it's equal to FILE_PATH_PATTERN_SIZE_MAX in BPF code
	MaxFilePathPatternLength = 64

	// PathPatternSize is the size of pathPattern in bpfPathRule structure
	PathPatternSize = 4 + MaxFilePathPatternLength*2

	// PathRuleSize is the size of bpfPathRule structure, which must match
	// the size of `struct path_rule` in BPF code for consistent map entry size.
	PathRuleSize = 4*2 + PathPatternSize

	// MaxFileSystemTypeLength is the maximum length of fstype pattern,
	// it's equal to FILE_SYSTEM_TYPE_MAX in BPF code
	MaxFileSystemTypeLength = 16

	// MountRuleSize is the size of bpfMountRule structure, which must match
	// the size of `struct mount_rule` in BPF code for consistent map entry size.
	MountRuleSize = 4*3 + MaxFileSystemTypeLength + PathPatternSize

	// IPAddressSize is the size of IP address and mask.
	IPAddressSize = 16

	// MaxPortsCount is the maximum count of ports in network rule,
	// it's equal to PORTS_COUNT_MAX in BPF code
	MaxPortsCount = 16

	// NetRuleSize is the size of bpfNetworkRule structure, which must match
	// the size of `struct net_rule` in BPF code for consistent map entry size.
	NetRuleSize = 4*2 + 8*3 + 2*(2+MaxPortsCount) + IPAddressSize*2

	// PinPath is the path we want to pin the maps
	PinPath = "/sys/fs/bpf/varmor"

	// AuditRingBufPinPath is the path we pin the audit ringbuf
	AuditRingBufPinPath = "/sys/fs/bpf/varmor/v_audit_rb"

	// Profile Mode
	EnforceMode  = 0x00000001
	ComplainMode = 0x00000002

	// Rule Mode
	DenyMode  = 0x00000001
	AuditMode = 0x00000002

	// Matching Flag
	PreciseMatch = 0x00000001
	GreedyMatch  = 0x00000002
	PrefixMatch  = 0x00000004
	SuffixMatch  = 0x00000008

	// Matching Flag for Network Rule
	CidrMatch      = 0x00000020
	Ipv4Match      = 0x00000040
	Ipv6Match      = 0x00000080
	PortMatch      = 0x00000100
	SocketMatch    = 0x00000200
	PortRangeMatch = 0x00000400
	PortsMatch     = 0x00000800
	PodSelfIPMatch = 0x00001000

	// Matching Permission
	AaMayExec     = 0x00000001
	AaMayWrite    = 0x00000002
	AaMayRead     = 0x00000004
	AaMayAppend   = 0x00000008
	AaMayCreate   = 0x00000010
	AaMayRename   = 0x00000080
	AaMayLink     = 0x00040000
	AaPtraceTrace = 0x00000002
	AaPtraceRead  = 0x00000004
	AaMayBeTraced = 0x00000008
	AaMayBeRead   = 0x00000010
	AaMayUmount   = 0x00000200

	// EventHeaderSize is the size of bpf audit event header
	EventHeaderSize = 24

	// Enforcement action
	DeniedAction  = 0x00000001
	AuditAction   = 0x00000002
	AllowedAction = 0x00000004

	// Event type
	CapabilityType EventType = 0x00000001
	FileType       EventType = 0x00000002
	BprmType       EventType = 0x00000004
	NetworkType    EventType = 0x00000008
	PtraceType     EventType = 0x00000010
	MountType      EventType = 0x00000020

	// Event Subtype for Network Event
	ConnectType = 0x00000001
	SocketType  = 0x00000002
)

var (
	EnforcementActionMap = map[uint32]string{
		DeniedAction:  "DENIED",
		AuditAction:   "AUDIT",
		AllowedAction: "ALLOWED",
	}

	EventTypeMap = map[EventType]string{
		CapabilityType: "Capability",
		FileType:       "File",
		BprmType:       "Bprm",
		NetworkType:    "Network",
		PtraceType:     "Ptrace",
		MountType:      "Mount",
	}

	NetworkEventTypeMap = map[uint32]string{
		ConnectType: "connect",
		SocketType:  "socket",
	}

	CapabilityMap = map[uint32]string{
		unix.CAP_CHOWN:              "chown",
		unix.CAP_DAC_OVERRIDE:       "dac_override",
		unix.CAP_DAC_READ_SEARCH:    "dac_read_search",
		unix.CAP_FOWNER:             "fowner",
		unix.CAP_FSETID:             "fsetid",
		unix.CAP_KILL:               "kill",
		unix.CAP_SETGID:             "setgid",
		unix.CAP_SETUID:             "setuid",
		unix.CAP_SETPCAP:            "setpcap",
		unix.CAP_LINUX_IMMUTABLE:    "linux_immutable",
		unix.CAP_NET_BIND_SERVICE:   "net_bind_service",
		unix.CAP_NET_BROADCAST:      "net_broadcast",
		unix.CAP_NET_ADMIN:          "net_admin",
		unix.CAP_NET_RAW:            "net_raw",
		unix.CAP_IPC_LOCK:           "ipc_lock",
		unix.CAP_IPC_OWNER:          "ipc_owner",
		unix.CAP_SYS_MODULE:         "sys_module",
		unix.CAP_SYS_RAWIO:          "sys_rawio",
		unix.CAP_SYS_CHROOT:         "sys_chroot",
		unix.CAP_SYS_PTRACE:         "sys_ptrace",
		unix.CAP_SYS_PACCT:          "sys_pacct",
		unix.CAP_SYS_ADMIN:          "sys_admin",
		unix.CAP_SYS_BOOT:           "sys_boot",
		unix.CAP_SYS_NICE:           "sys_nice",
		unix.CAP_SYS_RESOURCE:       "sys_resource",
		unix.CAP_SYS_TIME:           "sys_time",
		unix.CAP_SYS_TTY_CONFIG:     "sys_tty_config",
		unix.CAP_MKNOD:              "mknod",
		unix.CAP_LEASE:              "lease",
		unix.CAP_AUDIT_WRITE:        "audit_write",
		unix.CAP_AUDIT_CONTROL:      "audit_control",
		unix.CAP_SETFCAP:            "setfcap",
		unix.CAP_MAC_OVERRIDE:       "mac_override",
		unix.CAP_MAC_ADMIN:          "mac_admin",
		unix.CAP_SYSLOG:             "syslog",
		unix.CAP_WAKE_ALARM:         "wake_alarm",
		unix.CAP_BLOCK_SUSPEND:      "block_suspend",
		unix.CAP_AUDIT_READ:         "audit_read",
		unix.CAP_PERFMON:            "perfmon",
		unix.CAP_BPF:                "bpf",
		unix.CAP_CHECKPOINT_RESTORE: "checkpoint_restore",
	}

	PathPermissionMap = map[uint32]string{
		AaMayExec:   "exec",
		AaMayWrite:  "write",
		AaMayRead:   "read",
		AaMayAppend: "append",
		AaMayCreate: "create",
		AaMayRename: "rename",
		AaMayLink:   "link",
	}

	NetworkEventType = map[uint32]string{
		ConnectType: "connect",
		SocketType:  "socket",
	}

	SocketDomainMap = map[uint32]string{
		unix.AF_UNSPEC:     "AF_UNSPEC",
		unix.AF_UNIX:       "AF_UNIX",
		unix.AF_INET:       "AF_INET",
		unix.AF_AX25:       "AF_AX25",
		unix.AF_IPX:        "AF_IPX",
		unix.AF_APPLETALK:  "AF_APPLETALK",
		unix.AF_NETROM:     "AF_NETROM",
		unix.AF_BRIDGE:     "AF_BRIDGE",
		unix.AF_ATMPVC:     "AF_ATMPVC",
		unix.AF_X25:        "AF_X25",
		unix.AF_INET6:      "AF_INET6",
		unix.AF_ROSE:       "AF_ROSE",
		unix.AF_DECnet:     "AF_DECnet",
		unix.AF_NETBEUI:    "AF_NETBEUI",
		unix.AF_SECURITY:   "AF_SECURITY",
		unix.AF_KEY:        "AF_KEY",
		unix.AF_NETLINK:    "AF_NETLINK",
		unix.AF_PACKET:     "AF_PACKET",
		unix.AF_ASH:        "AF_ASH",
		unix.AF_ECONET:     "AF_ECONET",
		unix.AF_ATMSVC:     "AF_ATMSVC",
		unix.AF_RDS:        "AF_RDS",
		unix.AF_SNA:        "AF_SNA",
		unix.AF_IRDA:       "AF_IRDA",
		unix.AF_PPPOX:      "AF_PPPOX",
		unix.AF_WANPIPE:    "AF_WANPIPE",
		unix.AF_LLC:        "AF_LLC",
		unix.AF_IB:         "AF_IB",
		unix.AF_MPLS:       "AF_MPLS",
		unix.AF_CAN:        "AF_CAN",
		unix.AF_TIPC:       "AF_TIPC",
		unix.AF_BLUETOOTH:  "AF_BLUETOOTH",
		unix.AF_IUCV:       "AF_IUCV",
		unix.AF_RXRPC:      "AF_RXRPC",
		unix.AF_ISDN:       "AF_ISDN",
		unix.AF_PHONET:     "AF_PHONET",
		unix.AF_IEEE802154: "AF_IEEE802154",
		unix.AF_CAIF:       "AF_CAIF",
		unix.AF_ALG:        "AF_ALG",
		unix.AF_NFC:        "AF_NFC",
		unix.AF_VSOCK:      "AF_VSOCK",
		unix.AF_KCM:        "AF_KCM",
		unix.AF_QIPCRTR:    "AF_QIPCRTR",
		unix.AF_SMC:        "AF_SMC",
		unix.AF_XDP:        "AF_XDP",
		unix.AF_MCTP:       "AF_MCTP",
	}

	SocketTypeMap = map[uint32]string{
		unix.SOCK_STREAM:    "SOCK_STREAM",
		unix.SOCK_DGRAM:     "SOCK_DGRAM",
		unix.SOCK_RAW:       "SOCK_RAW",
		unix.SOCK_RDM:       "SOCK_RDM",
		unix.SOCK_SEQPACKET: "SOCK_SEQPACKET",
		unix.SOCK_DCCP:      "SOCK_DCCP",
		unix.SOCK_PACKET:    "SOCK_PACKET",
	}

	SocketProtocolMap = map[uint32]string{
		unix.IPPROTO_IP:       "IPPROTO_IP",
		unix.IPPROTO_ICMP:     "IPPROTO_ICMP",
		unix.IPPROTO_IGMP:     "IPPROTO_IGMP",
		unix.IPPROTO_IPIP:     "IPPROTO_IPIP",
		unix.IPPROTO_TCP:      "IPPROTO_TCP",
		unix.IPPROTO_EGP:      "IPPROTO_EGP",
		unix.IPPROTO_PUP:      "IPPROTO_PUP",
		unix.IPPROTO_UDP:      "IPPROTO_UDP",
		unix.IPPROTO_IDP:      "IPPROTO_IDP",
		unix.IPPROTO_TP:       "IPPROTO_TP",
		unix.IPPROTO_DCCP:     "IPPROTO_DCCP",
		unix.IPPROTO_IPV6:     "IPPROTO_IPV6",
		unix.IPPROTO_RSVP:     "IPPROTO_RSVP",
		unix.IPPROTO_GRE:      "IPPROTO_GRE",
		unix.IPPROTO_ESP:      "IPPROTO_ESP",
		unix.IPPROTO_AH:       "IPPROTO_AH",
		unix.IPPROTO_MTP:      "IPPROTO_MTP",
		unix.IPPROTO_BEETPH:   "IPPROTO_BEETPH",
		unix.IPPROTO_ENCAP:    "IPPROTO_ENCAP",
		unix.IPPROTO_PIM:      "IPPROTO_PIM",
		unix.IPPROTO_COMP:     "IPPROTO_COMP",
		unix.IPPROTO_L2TP:     "IPPROTO_L2TP",
		unix.IPPROTO_SCTP:     "IPPROTO_SCTP",
		unix.IPPROTO_UDPLITE:  "IPPROTO_UDPLITE",
		unix.IPPROTO_MPLS:     "IPPROTO_MPLS",
		unix.IPPROTO_ETHERNET: "IPPROTO_ETHERNET",
		unix.IPPROTO_RAW:      "IPPROTO_RAW",
		unix.IPPROTO_SMC:      "IPPROTO_SMC",
		unix.IPPROTO_MPTCP:    "IPPROTO_MPTCP",
	}

	PtracePermissionMap = map[uint32]string{
		AaPtraceTrace: "trace",
		AaPtraceRead:  "read",
		AaMayBeTraced: "traceby",
		AaMayBeRead:   "readby",
	}

	MountFlagsMap = map[uint32]string{
		unix.MS_RDONLY:      "ro",
		unix.MS_NOSUID:      "nosuid",
		unix.MS_NODEV:       "nodev",
		unix.MS_NOEXEC:      "noexec",
		unix.MS_SYNCHRONOUS: "sync",
		unix.MS_REMOUNT:     "remount",
		unix.MS_MANDLOCK:    "mand",
		unix.MS_DIRSYNC:     "dirsync",
		AaMayUmount:         "umount",
		unix.MS_NOATIME:     "noatime",
		unix.MS_NODIRATIME:  "nodiratime",
		unix.MS_MOVE:        "move",
		unix.MS_SILENT:      "silent",
		unix.MS_UNBINDABLE:  "make-unbindable",
		unix.MS_PRIVATE:     "make-private",
		unix.MS_SLAVE:       "make-slave",
		unix.MS_SHARED:      "make-shared",
		unix.MS_RELATIME:    "relatime",
		unix.MS_I_VERSION:   "iversion",
		unix.MS_STRICTATIME: "strictatime",
	}

	MountBindFlagsMap = map[uint32]string{
		unix.MS_BIND | unix.MS_REC | unix.MS_UNBINDABLE: "make-runbindable",
		unix.MS_BIND | unix.MS_REC | unix.MS_PRIVATE:    "make-rprivate",
		unix.MS_BIND | unix.MS_REC | unix.MS_SLAVE:      "make-rslave",
		unix.MS_BIND | unix.MS_REC | unix.MS_SHARED:     "make-rshared",
		unix.MS_BIND | unix.MS_REC:                      "rbind",
		unix.MS_BIND:                                    "bind",
	}
)
