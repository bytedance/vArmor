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

type BpfPathEvent struct {
	Permissions []string `json:"permissions"`
	Path        string   `json:"path"`
}

type BpfCapabilityEvent struct {
	Capability string `json:"capability"`
}

type BpfNetworkCreateEvent struct {
	Domain   uint32 `json:"domain"`
	Type     uint32 `json:"type"`
	Protocol uint32 `json:"protocol"`
}

type BpfNetworkConnectEvent struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type BpfPtraceEvent struct {
	Permissions []string `json:"permissions"`
	External    bool     `json:"external"`
}

type BpfMountEvent struct {
	DevName string   `json:"devName"`
	Type    string   `json:"type"`
	Flags   []string `json:"flags"`
}

type AppArmorEvent struct {
	Version        uint32 `json:"version"`
	Event          uint32 `json:"event"`
	PID            uint64 `json:"pid"`
	PeerPID        uint64 `json:"peerPID"`
	Task           uint64 `json:"task"`
	MagicToken     uint64 `json:"magicToken"`
	Epoch          int64  `json:"epoch"`
	AuditSubId     uint32 `json:"auditSubId"`
	BitMask        int32  `json:"bitMask"`
	AuditId        string `json:"auditID"`
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
