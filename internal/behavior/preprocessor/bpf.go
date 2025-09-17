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

package preprocessor

import (
	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
)

func (p *DataPreprocessor) parseBpfEventForTree(event *varmorauditor.BpfEvent) error {
	switch event.Header.Type {
	case "Capability":
		e := event.Body.(*varmorauditor.BpfCapabilityEvent)
		if !varmorutils.InStringArray(e.Capability, p.behaviorData.DynamicResult.Bpf.Capabilities) {
			p.behaviorData.DynamicResult.Bpf.Capabilities = append(p.behaviorData.DynamicResult.Bpf.Capabilities, e.Capability)
		}
	case "Bprm":
		e := event.Body.(*varmorauditor.BpfPathEvent)
		if !varmorutils.InStringArray(e.Path, p.behaviorData.DynamicResult.Bpf.Executions) {
			p.behaviorData.DynamicResult.Bpf.Executions = append(p.behaviorData.DynamicResult.Bpf.Executions, e.Path)
		}
	case "File":
		e := event.Body.(*varmorauditor.BpfPathEvent)

		oldPath := e.Path
		var dmask string
		for _, perm := range e.Permissions {
			switch perm {
			case "write":
				dmask += "w"
			case "read":
				dmask += "r"
			case "append":
				dmask += "a"
			case "create":
				dmask += "w"
			}
		}
		path := p.trimPath(oldPath, dmask)

		for i, f := range p.behaviorData.DynamicResult.Bpf.Files {
			if f.Path == path {
				for _, perm := range e.Permissions {
					if !varmorutils.InStringArray(perm, f.Permissions) {
						p.behaviorData.DynamicResult.Bpf.Files[i].Permissions = append(p.behaviorData.DynamicResult.Bpf.Files[i].Permissions, perm)
					}
				}

				if f.OldPath == "" && path != oldPath {
					p.behaviorData.DynamicResult.Bpf.Files[i].OldPath = oldPath
				}

				return nil
			}
		}

		if oldPath == path {
			oldPath = ""
		}
		p.behaviorData.DynamicResult.Bpf.Files = append(p.behaviorData.DynamicResult.Bpf.Files, varmor.File{
			Path:        path,
			Permissions: e.Permissions,
			OldPath:     oldPath,
		})

	case "Network":
		e := event.Body.(*varmorauditor.BpfNetworkEvent)

		if p.behaviorData.DynamicResult.Bpf.Network == nil {
			p.behaviorData.DynamicResult.Bpf.Network = &varmor.Network{}
		}

		switch e.Type {
		case "socket":
			for _, socket := range p.behaviorData.DynamicResult.Bpf.Network.Sockets {
				if socket.Domain == e.Socket.Domain && socket.Type == e.Socket.Type && socket.Protocol == e.Socket.Protocol {
					return nil
				}
			}
			p.behaviorData.DynamicResult.Bpf.Network.Sockets = append(p.behaviorData.DynamicResult.Bpf.Network.Sockets, varmor.Socket{
				Domain:   e.Socket.Domain,
				Type:     e.Socket.Type,
				Protocol: e.Socket.Protocol,
			})
		case "connect":
			for i, egress := range p.behaviorData.DynamicResult.Bpf.Network.Egresses {
				if egress.IP == e.Address.IP {
					if !varmorutils.InUint16Array(e.Address.Port, egress.Ports) {
						p.behaviorData.DynamicResult.Bpf.Network.Egresses[i].Ports = append(p.behaviorData.DynamicResult.Bpf.Network.Egresses[i].Ports, e.Address.Port)
					}
					return nil
				}
			}
			p.behaviorData.DynamicResult.Bpf.Network.Egresses = append(p.behaviorData.DynamicResult.Bpf.Network.Egresses, varmor.Address{
				IP:    e.Address.IP,
				Ports: []uint16{e.Address.Port},
			})
		}
	case "Ptrace":
		e := event.Body.(*varmorauditor.BpfPtraceEvent)

		for i, ptrace := range p.behaviorData.DynamicResult.Bpf.Ptraces {
			if ptrace.External == e.External {
				if !varmorutils.InStringArray(e.Permission, ptrace.Permissions) {
					p.behaviorData.DynamicResult.Bpf.Ptraces[i].Permissions = append(p.behaviorData.DynamicResult.Bpf.Ptraces[i].Permissions, e.Permission)
				}
				return nil
			}
		}

		p.behaviorData.DynamicResult.Bpf.Ptraces = append(p.behaviorData.DynamicResult.Bpf.Ptraces, varmor.Ptrace{
			External:    e.External,
			Permissions: []string{e.Permission},
		})

	case "Mount":
		e := event.Body.(*varmorauditor.BpfMountEvent)

		for i, mount := range p.behaviorData.DynamicResult.Bpf.Mounts {
			if mount.Path == e.Path && mount.Type == e.Type {
				for _, flag := range e.Flags {
					if !varmorutils.InStringArray(flag, mount.Flags) {
						p.behaviorData.DynamicResult.Bpf.Mounts[i].Flags = append(p.behaviorData.DynamicResult.Bpf.Mounts[i].Flags, flag)
					}
				}
				return nil
			}
		}
		p.behaviorData.DynamicResult.Bpf.Mounts = append(p.behaviorData.DynamicResult.Bpf.Mounts, varmor.Mount{
			Path:  e.Path,
			Type:  e.Type,
			Flags: e.Flags,
		})
	}

	return nil
}
