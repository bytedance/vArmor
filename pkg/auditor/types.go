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

package audit

type BpfEvent struct {
	Header BpfEventHeader `json:"header"`
	Body   interface{}    `json:"body"`
}

type BpfEventHeader struct {
	Action string `json:"action"`
	Type   string `json:"type"`
	MntNs  uint32 `json:"mntNs"`
	Tgid   uint32 `json:"tgid"`
	Ktime  uint64 `json:"ktime"`
}

type BpfPathEvent struct {
	Operation   string   `json:"operation"`
	Permissions []string `json:"permissions"`
	Path        string   `json:"path"`
}

type BpfCapabilityEvent struct {
	Operation  string `json:"operation"`
	Capability string `json:"capability"`
}

type BpfNetworkSocket struct {
	Operation string `json:"operation"`
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	Protocol  string `json:"protocol"`
}

type BpfNetworkSockAddr struct {
	Operation string `json:"operation"`
	IP        string `json:"ip"`
	Port      uint16 `json:"port"`
}

type BpfNetworkEvent struct {
	Operation string             `json:"operation"`
	Type      string             `json:"type"`
	Socket    BpfNetworkSocket   `json:"socket"`
	Address   BpfNetworkSockAddr `json:"address"`
}

type BpfPtraceEvent struct {
	Operation  string `json:"operation"`
	Permission string `json:"permission"`
	External   bool   `json:"external"`
}

type BpfMountEvent struct {
	Operation string   `json:"operation"`
	Path      string   `json:"path"`
	Type      string   `json:"type"`
	Flags     []string `json:"flags"`
}

type AppArmorEvent struct {
	Version        uint32 `json:"version"`
	Event          uint32 `json:"event"`
	PID            uint64 `json:"pid"`
	PeerPID        uint64 `json:"peerPID"`
	Task           uint64 `json:"task"`
	MagicToken     uint64 `json:"magicToken"`
	Epoch          int64  `json:"epoch"`
	AuditSubID     uint32 `json:"auditSubID"`
	BitMask        int32  `json:"bitMask"`
	AuditID        string `json:"auditID"`
	Operation      string `json:"operation"`
	DeniedMask     string `json:"deniedMask"`
	RequestedMask  string `json:"requestedMask"`
	Fsuid          uint64 `json:"fsuid"`
	Ouid           uint64 `json:"ouid"`
	Profile        string `json:"profile"`
	PeerProfile    string `json:"peerProfile"`
	Comm           string `json:"comm"`
	Name           string `json:"name"`
	Name2          string `json:"name2"`
	Namespace      string `json:"namespace"`
	Attribute      string `json:"attribute"`
	Parent         uint64 `json:"parent"`
	Info           string `json:"info"`
	PeerInfo       string `json:"peerInfo"`
	ErrorCode      int32  `json:"errorCode"`
	ActiveHat      string `json:"activeHat"`
	NetFamily      string `json:"netFamily"`
	NetProtocol    string `json:"netProtocol"`
	NetSockType    string `json:"netSockType"`
	NetLocalAddr   string `json:"netLocalAddr"`
	NetLocalPort   uint64 `json:"netLocalPort"`
	NetForeignAddr string `json:"netForeignAddr"`
	NetForeignPort uint64 `json:"netForeignPort"`
	DbusBus        string `json:"dbusBus"`
	DbusPath       string `json:"dbusPath"`
	DbusInterface  string `json:"dbusInterface"`
	DbusMember     string `json:"dbusMember"`
	Signal         string `json:"signal"`
	Peer           string `json:"peer"`
	FsType         string `json:"fsType"`
	Flags          string `json:"flags"`
	SrcName        string `json:"srcName"`
}

type SeccompEvent struct {
	AuditID string `json:"auditID"`
	Epoch   uint64 `json:"epoch"`
	Subj    string `json:"subj"`
	PID     uint64 `json:"pid"`
	Comm    string `json:"comm"`
	Exe     string `json:"exe"`
	Syscall string `json:"syscall"`
}
