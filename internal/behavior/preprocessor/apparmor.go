// Copyright 2022 vArmor Authors
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

/*
#cgo CFLAGS: -I /usr/include/ -Wall
#cgo LDFLAGS: -L /usr/lib/ -lapparmor
#include "aalogparse/aalogparse.h"
#include "stdlib.h"
*/
import "C"

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unsafe"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

type AaLogRecord struct {
	Resource      string
	ActiveHat     string
	AaMode        string
	Time          int64
	Operation     string
	Profile       string
	Name          string
	Name2         string
	Attr          string
	Parent        uint64
	Pid           uint64
	Task          uint64
	Info          string
	ErrorCode     int32
	DeniedMask    string
	RequestedMask string
	MagicToken    uint64
	Family        string
	Protocol      string
	SockType      string
	Fsuid         uint64
	Ouid          uint64
	Signal        string
	Peer          string
	PeerProfile   string
	Bus           string
	Path          string
	Interface     string
	Member        string
}

const (
	regexProc      = "\\/proc\\/[0-9]+"
	regexProcTask  = "\\/proc\\/[0-9]+\\/task\\/[0-9]+"
	regexSnapshots = "\\/snapshots\\/\\d+\\/fs\\/" // \/snapshots\/\d+\/fs\/
	regexOverlay   = "\\b\\d+\\b"                  //  \b\d+\b   \\/\\d+\\/
)

var (
	procRegex      = regexp.MustCompile(regexProc)
	procTaskRegex  = regexp.MustCompile(regexProcTask)
	snapshotsRegex = regexp.MustCompile(regexSnapshots)
	overlayRegex   = regexp.MustCompile(regexOverlay)

	modeConvertor = map[uint32]string{
		0: "INVALID",
		1: "ERROR",
		2: "AUDIT",
		3: "ALLOWED",
		4: "DENIED",
		5: "HINT",
		6: "STATUS",
	}

	randomExclusions = []string{
		"/lib/",
		"/usr/lib/",
		"/usr/local/lib/",
		"/sys/",
		"/proc/",
		"/var/lib/",
	}

	overlayPrefixes = make([]string, 0)
)

// Retrieve and parse all overlayfs path of container in the node.
// TODO: need more tests
func (p *DataPreprocessor) parseOverlayInfo() error {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		p.log.Error(err, "os.Open() failed")
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				break
			}
		}

		// overlay /xxx/rootfs overlay rw,relatime,lowerdir=xxx:xxx:xxx,upperdir=xxx,workdir=xxx,index=off,nfs_export=off 0 0
		if !strings.HasPrefix(line, "overlay ") {
			continue
		}

		patterns := strings.Split(line, ",")
		for _, pattern := range patterns {
			// lowerdir=xxx:xxx:xxx,
			if !strings.Contains(pattern, "/") || !strings.Contains(pattern, "=") {
				continue
			}

			dir := pattern[strings.Index(pattern, "=")+1:]
			paths := strings.Split(dir, ":")
			for _, path := range paths {
				// /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4961/fs
				loc := overlayRegex.FindStringIndex(path)
				if loc == nil {
					continue
				}
				prefix := path[:loc[0]]
				if !varmorutils.InStringArray(prefix, overlayPrefixes) {
					// /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/
					overlayPrefixes = append(overlayPrefixes, prefix)
				}
			}
		}
	}

	return nil
}

// Extrace the file path from the peer.
// custom.profile//null-/usr/bin/top --> custom.profile
func (p *DataPreprocessor) converProfileToParents(profile string) string {
	i := strings.Index(profile, "//null-")
	if i != -1 {
		return profile[0:i]
	}
	return profile
}

// Returns the operation type if known, unknown otherwise.
func (p *DataPreprocessor) opType(event *AaLogRecord) string {
	if strings.HasPrefix(event.Operation, "file_") ||
		strings.HasPrefix(event.Operation, "inode_") ||
		event.Operation == "create" ||
		event.Operation == "post_create" ||
		event.Operation == "bind" ||
		event.Operation == "connect" ||
		event.Operation == "listen" ||
		event.Operation == "accept" ||
		event.Operation == "sendmsg" ||
		event.Operation == "recvmsg" ||
		event.Operation == "getsockname" ||
		event.Operation == "getpeername" ||
		event.Operation == "getsockopt" ||
		event.Operation == "setsockopt" ||
		event.Operation == "socket_create" ||
		event.Operation == "sock_shutdown" ||
		event.Operation == "open" ||
		event.Operation == "truncate" ||
		event.Operation == "mkdir" ||
		event.Operation == "mknod" ||
		event.Operation == "chmod" ||
		event.Operation == "chown" ||
		event.Operation == "rename_src" ||
		event.Operation == "rename_dest" ||
		event.Operation == "unlink" ||
		event.Operation == "rmdir" ||
		event.Operation == "symlink" ||
		event.Operation == "symlink_create" ||
		event.Operation == "link" ||
		event.Operation == "sysctl" ||
		event.Operation == "getattr" ||
		event.Operation == "setattr" ||
		event.Operation == "xattr" {

		if event.Family != "" && event.SockType != "" && event.Protocol != "" {
			// 'unix' events also use keywords like 'connect', but protocol is 0 and should therefore be filtered out
			return "net"
		} else if event.DeniedMask != "" {
			return "file"
		} else {
			return "unknown"
		}

	} else {
		return "unknown"
	}
}

func (p *DataPreprocessor) trimPath(path, dmask string) string {
	// In rare cases, the path may be an absolute path in the host.
	// We need to replace the digits to '*'
	// e.g.
	//    /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/86/fs/etc/nginx/geoip/ -->
	//    /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs/etc/nginx/geoip/
	// 	  /containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/149/fs/etc/ -->
	//	  /containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs/etc/
	// Attention:
	//    This may cause compatibility issues if nodes use different runtime.
	//    This feature is necessary, because the child process need the access to the file when AppArmor LSM does mandatory access control.)
	// TODO:
	//	  Analyze the root reason of these case.
	overlayPath := false
	for _, prefix := range overlayPrefixes {
		if strings.HasPrefix(path, prefix) {
			path = overlayRegex.ReplaceAllString(path, "*")
			overlayPath = true
			break
		}
	}
	if !overlayPath && strings.Contains(path, "/snapshots/") && strings.Contains(path, "/fs/") {
		path = snapshotsRegex.ReplaceAllString(path, "/snapshots/*/fs/")
	}

	// Reduce the number of rules for the system dynamic library.
	if !strings.Contains(dmask, "a") && !strings.Contains(dmask, "w") && !strings.Contains(dmask, "l") && !strings.Contains(dmask, "k") {
		if path == "/lib/x86_64-linux-gnu/" {
			return path
		} else if strings.HasPrefix(path, "/lib/x86_64-linux-gnu/") {
			return "/lib/x86_64-linux-gnu/**"
		} else if path == "/usr/lib/x86_64-linux-gnu/" {
			return path
		} else if strings.HasPrefix(path, "/usr/lib/x86_64-linux-gnu/") {
			return "/usr/lib/x86_64-linux-gnu/**"
		} else if path == "/usr/lib/aarch64-linux-gnu/" {
			return path
		} else if strings.HasPrefix(path, "/usr/lib/aarch64-linux-gnu/") {
			return "/usr/lib/aarch64-linux-gnu/**"
		}
	}

	// Reduce the number of rules for /tmp directory
	// e.g. /tmp、/tmp/、/tmp/dwda.lgo、/tmp/dw/fw.log
	if strings.HasPrefix(path, "/tmp/") {
		if path != "/tmp/" {
			return "/tmp/**"
		} else {
			return "/tmp/"
		}
	}

	// For ServiceAccount token/namespace/...
	if strings.HasPrefix(path, "/run/secrets/kubernetes.io/serviceaccount/") {
		return "/run/secrets/kubernetes.io/serviceaccount/**"
	} else if strings.HasPrefix(path, "/var/run/secrets/kubernetes.io/serviceaccount/") {
		return "/var/run/secrets/kubernetes.io/serviceaccount/**"
	}

	// Reduce the number of rules for /proc/[PID]/task/[PID]/*, /proc/[PID]/*, /xxxx/proc/[PID]/*, ...
	// TODO: * ? ** ?
	if strings.HasPrefix(path, "/proc") {
		if strings.Contains(path, "/task") {
			path = procTaskRegex.ReplaceAllString(path, "/proc/*/task/*")
		}
		path = procRegex.ReplaceAllString(path, "/proc/*")
		return path
	}

	// Exclude some sensitive directories before replacing the random pattern of path with the classifier.
	for _, excludePath := range randomExclusions {
		if strings.HasPrefix(path, excludePath) {
			return path
		}
	}

	// Replace the random pattern of path with the classifier.
	output, err := varmorutils.RequestClassifierService([]byte(path), p.inContainer, p.mlIP, p.mlPort)
	if err != nil {
		p.log.Error(err, "varmorutils.RequestClassifierService() failed")
		return path
	}

	index := bytes.IndexByte(output, 0)
	if index == -1 {
		path = string(output)
	} else {
		path = string(output[0:index])
	}

	return path
}

func (p *DataPreprocessor) parseAppArmorEventForTree(event *AaLogRecord) error {
	// aamode is aa_log_record.event, the type of aa_log_record.event is aa_record_event_type
	// aa_record_event_type was defined in /apparmor/libraries/libapparmor/include/aalogparse.h
	switch event.AaMode {
	case "INVALID":
		return fmt.Errorf("aamod is INVALID - INVALID")
	case "AUDIT", "STATUS", "ERROR":
		return fmt.Errorf("aamode is not expected - %s", event.AaMode)
	case "DENIED", "HINT":
		return fmt.Errorf("aamode is not support - %s", event.AaMode)
	}

	// Skip if AUDIT event was issued due to a change_hat in unconfined mode.
	if event.Profile == "" {
		return fmt.Errorf("event.Profile is nil")
	}

	event.Profile = p.converProfileToParents(event.Profile)
	if !varmorutils.InStringArray(event.Profile, p.behaviorData.DynamicResult.AppArmor.Profiles) {
		p.behaviorData.DynamicResult.AppArmor.Profiles = append(p.behaviorData.DynamicResult.AppArmor.Profiles, event.Profile)
	}

	// Execution
	if event.Operation == "exec" {
		if event.Name == "" {
			return fmt.Errorf("exec without executed binary")
		}

		if !varmorutils.InStringArray(event.Name, p.behaviorData.DynamicResult.AppArmor.Executions) {
			p.behaviorData.DynamicResult.AppArmor.Executions = append(p.behaviorData.DynamicResult.AppArmor.Executions, event.Name)
		}
		return nil
	}

	opType := p.opType(event)

	// File
	if opType == "file" {
		// Map c (create) and d (delete) to w (logging is more detailed than the profile language).
		dmask := event.DeniedMask
		dmask = strings.Replace(dmask, "c", "w", -1)
		dmask = strings.Replace(dmask, "d", "w", -1)

		owner := false
		if strings.Contains(dmask, "::") {
			// Old log styles used :: to indicate if permissions are meant for owner or other.
			s := strings.Split(dmask, "::")
			if s[0] != "" && s[1] != "" {
				return fmt.Errorf("found log event with both owner and other permissions(%s), please open a bugreport", dmask)
			}
			if s[0] != "" {
				dmask = s[0]
				owner = true
			} else {
				dmask = s[1]
			}
		}

		if event.Ouid != 0xFFFFFFFFFFFFFFFF && event.Ouid == event.Fsuid {
			// In current log style, owner permissions are indicated by a match of fsuid and ouid.
			owner = true
		}

		oldPath := event.Name
		event.Name = p.trimPath(event.Name, dmask)

		for i, f := range p.behaviorData.DynamicResult.AppArmor.Files {
			if f.Path == event.Name {
				// disable owner priority
				p.behaviorData.DynamicResult.AppArmor.Files[i].Owner = f.Owner && owner

				for _, perm := range dmask {
					// intentionally not allowing 'x' here
					if strings.Contains("mrwalk", string(perm)) {
						if !varmorutils.InStringArray(string(perm), f.Permissions) {
							p.behaviorData.DynamicResult.AppArmor.Files[i].Permissions = append(p.behaviorData.DynamicResult.AppArmor.Files[i].Permissions, string(perm))
						}
					} else {
						return fmt.Errorf(fmt.Sprintf("log event contains unknown denied_mask %s", dmask))
					}
				}

				if f.OldPath == "" && event.Name != oldPath {
					p.behaviorData.DynamicResult.AppArmor.Files[i].OldPath = oldPath
				}

				return nil
			}
		}

		if event.Name == "" {
			return fmt.Errorf("fatal error: event.Name == \"\"")
		}

		file := varmor.File{
			Path:        event.Name,
			Owner:       owner,
			Permissions: make([]string, 0),
			OldPath:     "",
		}

		for _, perm := range dmask {
			// intentionally not allowing 'x' here
			if strings.Contains("mrwalk", string(perm)) {
				if !varmorutils.InStringArray(string(perm), file.Permissions) {
					file.Permissions = append(file.Permissions, string(perm))
				}
			} else {
				return fmt.Errorf(fmt.Sprintf("log event contains unknown denied_mask %s", dmask))
			}
		}

		if oldPath != event.Name {
			file.OldPath = oldPath
		}

		p.behaviorData.DynamicResult.AppArmor.Files = append(p.behaviorData.DynamicResult.AppArmor.Files, file)
		return nil
	}

	// Capability
	if event.Operation == "capable" {
		if !varmorutils.InStringArray(event.Name, p.behaviorData.DynamicResult.AppArmor.Capabilities) {
			p.behaviorData.DynamicResult.AppArmor.Capabilities = append(p.behaviorData.DynamicResult.AppArmor.Capabilities, event.Name)
		}
		return nil
	}

	// Network
	if opType == "net" {
		for _, n := range p.behaviorData.DynamicResult.AppArmor.Networks {
			if n.Family == event.Family && n.SockType != "" && n.SockType == event.SockType {
				return nil
			}

			if n.Family == event.Family && n.SockType == event.SockType && n.Protocol == event.Protocol {
				return nil
			}
		}

		net := varmor.Network{
			Family:   event.Family,
			SockType: event.SockType,
			Protocol: event.Protocol,
		}
		p.behaviorData.DynamicResult.AppArmor.Networks = append(p.behaviorData.DynamicResult.AppArmor.Networks, net)
		return nil
	}

	// Ptrace
	if event.Operation == "ptrace" {
		if event.Peer == "" || event.DeniedMask == "" {
			return nil
		}

		// Convert the new null profile to its parent profile.
		// custom.profile//null-/usr/bin/top --> /usr/bin/top
		event.Peer = p.converProfileToParents(event.Peer)

		for i, ptrace := range p.behaviorData.DynamicResult.AppArmor.Ptraces {
			if ptrace.Peer == event.Peer {
				if !varmorutils.InStringArray(event.DeniedMask, ptrace.Permissions) {
					p.behaviorData.DynamicResult.AppArmor.Ptraces[i].Permissions = append(p.behaviorData.DynamicResult.AppArmor.Ptraces[i].Permissions, event.DeniedMask)
				}
				return nil
			}
		}

		ptrace := varmor.Ptrace{
			Peer:        event.Peer,
			Permissions: make([]string, 0),
		}
		ptrace.Permissions = append(ptrace.Permissions, event.DeniedMask)

		p.behaviorData.DynamicResult.AppArmor.Ptraces = append(p.behaviorData.DynamicResult.AppArmor.Ptraces, ptrace)
		return nil
	}

	// Signal
	if event.Operation == "signal" {
		if event.Peer == "" || event.DeniedMask == "" || event.Signal == "" {
			return nil
		}

		// Convert the new null profile to its parent profile
		// custom.profile//null-/usr/bin/top --> /usr/bin/top
		event.Peer = p.converProfileToParents(event.Peer)

		for i, s := range p.behaviorData.DynamicResult.AppArmor.Signals {
			if s.Peer == event.Peer {
				if !varmorutils.InStringArray(event.DeniedMask, s.Permissions) {
					p.behaviorData.DynamicResult.AppArmor.Signals[i].Permissions = append(p.behaviorData.DynamicResult.AppArmor.Signals[i].Permissions, event.DeniedMask)
				}

				if !varmorutils.InStringArray(event.Signal, s.Signals) {
					p.behaviorData.DynamicResult.AppArmor.Signals[i].Signals = append(p.behaviorData.DynamicResult.AppArmor.Signals[i].Signals, event.Signal)
				}

				return nil
			}
		}

		signal := varmor.Signal{
			Peer:        event.Peer,
			Permissions: make([]string, 0),
			Signals:     make([]string, 0),
		}
		signal.Permissions = append(signal.Permissions, event.DeniedMask)
		signal.Signals = append(signal.Signals, event.Signal)

		p.behaviorData.DynamicResult.AppArmor.Signals = append(p.behaviorData.DynamicResult.AppArmor.Signals, signal)
		return nil
	}

	// Ignore change_hat, change_profile, and allow all signal, dbus...
	unhandled := fmt.Sprintf("Resource - %v, ActiveHat - %v, AaMode - %v, Time - %v, Operation - %v, Profile - %v, Name - %v, Name2 - %v, Attr - %v, Parent - %v, Pid - %v, Task - %v, Info - %v, ErrorCode - %v, DeniedMask - %v, RequestedMask - %v, MagicToken - %v, Family - %v, Protocol - %v, SockType - %v, Fsuid - %v, Ouid - %v, Signal - %v, Peer - %v, PeerProfile - %v, Bus - %v, Path - %v, Interface - %v, Member - %v",
		event.Resource, event.ActiveHat, event.AaMode,
		event.Time, event.Operation, event.Profile,
		event.Name, event.Name2, event.Attr,
		event.Parent, event.Pid, event.Task,
		event.Info, event.ErrorCode, event.DeniedMask,
		event.RequestedMask, event.MagicToken, event.Family,
		event.Protocol, event.SockType, event.Fsuid,
		event.Ouid, event.Signal, event.Peer,
		event.PeerProfile, event.Bus, event.Path,
		event.Interface, event.Member)
	if !varmorutils.InStringArray(unhandled, p.behaviorData.DynamicResult.AppArmor.Unhandled) {
		p.behaviorData.DynamicResult.AppArmor.Unhandled = append(p.behaviorData.DynamicResult.AppArmor.Unhandled, unhandled)
	}

	return nil
}

func parseAppArmorEvent(line string) (*AaLogRecord, error) {
	// Normalize audit events from rsyslog.
	// 		rsyslog format: <5>Nov 28 10:12:32 n248-145-253 kernel: [5326493.467434] audit: type=1400 audit(1669601552.623:916365): apparmor="STATUS" ...
	// 		auditd format: type=AVC msg=audit(1669252886.558:860805): apparmor="STATUS" ...
	index := strings.Index(line, "type=1400 audit")
	if index != -1 {
		line = strings.Replace(line[index:], "type=1400 audit", "type=AVC msg=audit", 1)
	}

	// call parse_record() of libapparmor.so to parse the event
	msg := C.CString(line)
	defer C.free(unsafe.Pointer(msg))
	record := C.parse_record(msg)
	defer C.free_record(record)

	if record == nil {
		return nil, fmt.Errorf("parse_record() failed")
	}

	r := AaLogRecord{
		Resource:      C.GoString(record.info),
		ActiveHat:     C.GoString(record.active_hat),
		Time:          int64(record.epoch),
		Operation:     C.GoString(record.operation),
		Profile:       C.GoString(record.profile),
		Name:          C.GoString(record.name),
		Name2:         C.GoString(record.name2),
		Attr:          C.GoString(record.attribute),
		Parent:        uint64(record.parent),
		Pid:           uint64(record.pid),
		Task:          uint64(record.task),
		Info:          C.GoString(record.info),
		ErrorCode:     int32(record.error_code),
		DeniedMask:    C.GoString(record.denied_mask),
		RequestedMask: C.GoString(record.requested_mask),
		MagicToken:    uint64(record.magic_token),
		Family:        C.GoString(record.net_family),
		Protocol:      C.GoString(record.net_protocol),
		SockType:      C.GoString(record.net_sock_type),
	}

	if uint64(record.ouid) != 0xFFFFFFFFFFFFFFFF {
		r.Ouid = uint64(record.ouid)
		r.Fsuid = uint64(record.fsuid)
	} else {
		r.Ouid = 0xFFFFFFFFFFFFFFFF
		r.Fsuid = 0xFFFFFFFFFFFFFFFF
	}

	if r.Operation == "signal" {
		r.Signal = C.GoString(record.signal)
		r.Peer = C.GoString(record.peer)
	} else if r.Operation == "ptrace" {
		r.Peer = C.GoString(record.peer)
	} else if strings.HasPrefix(r.Operation, "dbus_") {
		r.PeerProfile = C.GoString(record.peer_profile)
		r.Bus = C.GoString(record.dbus_bus)
		r.Path = C.GoString(record.dbus_path)
		r.Interface = C.GoString(record.dbus_interface)
		r.Member = C.GoString(record.dbus_member)
	}

	if r.Time == 0 {
		r.Time = time.Now().Unix()
	}

	// Convert aamode values to their counter-parts.
	if mode, ok := modeConvertor[uint32(record.event)]; ok {
		r.AaMode = mode
	} else {
		r.AaMode = "INVALID"
	}

	// 'translate' disconnected paths to errors, which means the event will be ignored.
	// Ideally we should propose to add the attach_disconnected flag to the profile.
	if r.ErrorCode == 13 && r.Info == "Failed name lookup - disconnected path" {
		r.AaMode = "ERROR"
	}

	return &r, nil
}
