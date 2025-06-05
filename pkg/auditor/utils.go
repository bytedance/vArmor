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

/*
#cgo CFLAGS: -I /usr/include/ -Wall
#cgo LDFLAGS: -L /usr/lib/ -lapparmor
#include "aalogparse/aalogparse.h"
#include "stdlib.h"
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"

	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

func readBootTime() (uint64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseUint(fields[1], 10, 64)
			}
			break
		}
	}
	return 0, fmt.Errorf("btime not found")
}

func sysctl_read(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.Trim(string(content), "\n"), nil
}

func sysctl_write(path string, value uint64) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	_, err = file.WriteString(fmt.Sprintf("%d", value))
	return err
}

func initCapabilityMap() map[uint32]string {
	return map[uint32]string{
		unix.CAP_AUDIT_CONTROL:      "CAP_AUDIT_CONTROL",
		unix.CAP_AUDIT_READ:         "CAP_AUDIT_READ",
		unix.CAP_AUDIT_WRITE:        "CAP_AUDIT_WRITE",
		unix.CAP_BLOCK_SUSPEND:      "CAP_BLOCK_SUSPEND",
		unix.CAP_BPF:                "CAP_BPF",
		unix.CAP_CHECKPOINT_RESTORE: "CAP_CHECKPOINT_RESTORE",
		unix.CAP_CHOWN:              "CAP_CHOWN",
		unix.CAP_DAC_OVERRIDE:       "CAP_DAC_OVERRIDE",
		unix.CAP_DAC_READ_SEARCH:    "CAP_DAC_READ_SEARCH",
		unix.CAP_FOWNER:             "CAP_FOWNER",
		unix.CAP_FSETID:             "CAP_FSETID",
		unix.CAP_IPC_LOCK:           "CAP_IPC_LOCK",
		unix.CAP_IPC_OWNER:          "CAP_IPC_OWNER",
		unix.CAP_KILL:               "CAP_KILL",
		unix.CAP_LEASE:              "CAP_LEASE",
		unix.CAP_LINUX_IMMUTABLE:    "CAP_LINUX_IMMUTABLE",
		unix.CAP_MAC_ADMIN:          "CAP_MAC_ADMIN",
		unix.CAP_MAC_OVERRIDE:       "CAP_MAC_OVERRIDE",
		unix.CAP_MKNOD:              "CAP_MKNOD",
		unix.CAP_NET_ADMIN:          "CAP_NET_ADMIN",
		unix.CAP_NET_BIND_SERVICE:   "CAP_NET_BIND_SERVICE",
		unix.CAP_NET_BROADCAST:      "CAP_NET_BROADCAST",
		unix.CAP_NET_RAW:            "CAP_NET_RAW",
		unix.CAP_PERFMON:            "CAP_PERFMON",
		unix.CAP_SETFCAP:            "CAP_SETFCAP",
		unix.CAP_SETGID:             "CAP_SETGID",
		unix.CAP_SETPCAP:            "CAP_SETPCAP",
		unix.CAP_SETUID:             "CAP_SETUID",
		unix.CAP_SYSLOG:             "CAP_SYSLOG",
		unix.CAP_SYS_ADMIN:          "CAP_SYS_ADMIN",
		unix.CAP_SYS_BOOT:           "CAP_SYS_BOOT",
		unix.CAP_SYS_CHROOT:         "CAP_SYS_CHROOT",
		unix.CAP_SYS_MODULE:         "CAP_SYS_MODULE",
		unix.CAP_SYS_NICE:           "CAP_SYS_NICE",
		unix.CAP_SYS_PACCT:          "CAP_SYS_PACCT",
		unix.CAP_SYS_PTRACE:         "CAP_SYS_PTRACE",
		unix.CAP_SYS_RAWIO:          "CAP_SYS_RAWIO",
		unix.CAP_SYS_RESOURCE:       "CAP_SYS_RESOURCE",
		unix.CAP_SYS_TIME:           "CAP_SYS_TIME",
		unix.CAP_SYS_TTY_CONFIG:     "CAP_SYS_TTY_CONFIG",
		unix.CAP_WAKE_ALARM:         "CAP_WAKE_ALARM",
	}
}

func initFilePermissionMap() map[uint32]string {
	return map[uint32]string{
		bpfenforcer.AaMayExec:   "exec",
		bpfenforcer.AaMayWrite:  "write",
		bpfenforcer.AaMayRead:   "read",
		bpfenforcer.AaMayAppend: "append",
	}
}

func initPtracePermissionMap() map[uint32]string {
	return map[uint32]string{
		bpfenforcer.AaPtraceTrace: "trace",
		bpfenforcer.AaPtraceRead:  "read",
		bpfenforcer.AaMayBeTraced: "traceby",
		bpfenforcer.AaMayBeRead:   "readby",
	}
}

// https://elixir.bootlin.com/linux/v6.11.5/source/include/uapi/linux/mount.h#L24
// #define MS_NOSYMFOLLOW  256 /* Do not follow symlinks */
// #define MS_VERBOSE  32768   /* War is peace. Verbosity is silence.
// #define MS_POSIXACL (1<<16) /* VFS does not apply the umask */
// #define MS_KERNMOUNT    (1<<22) /* this is a kern_mount call */
// #define MS_LAZYTIME (1<<25) /* Update the on-disk [acm]times lazily */
// #define MS_SUBMOUNT     (1<<26)
// #define MS_NOREMOTELOCK (1<<27)
// #define MS_NOSEC    (1<<28)
// #define MS_BORN     (1<<29)
// #define MS_ACTIVE   (1<<30)
// #define MS_NOUSER   (1<<31)
func initMountFlagMap() map[uint32]string {
	return map[uint32]string{
		unix.MS_REMOUNT:         "MS_REMOUNT",
		unix.MS_BIND:            "MS_BIND",
		unix.MS_MOVE:            "MS_MOVE",
		unix.MS_REC:             "MS_REC",
		unix.MS_UNBINDABLE:      "MS_UNBINDABLE",
		unix.MS_PRIVATE:         "MS_PRIVATE",
		unix.MS_SLAVE:           "MS_SLAVE",
		unix.MS_SHARED:          "MS_SHARED",
		unix.MS_RDONLY:          "MS_RDONLY",
		unix.MS_NOSUID:          "MS_NOSUID",
		unix.MS_NODEV:           "MS_NODEV",
		unix.MS_NOEXEC:          "MS_NOEXEC",
		unix.MS_SYNCHRONOUS:     "MS_SYNCHRONOUS",
		unix.MS_MANDLOCK:        "MS_MANDLOCK",
		unix.MS_DIRSYNC:         "MS_DIRSYNC",
		unix.MS_NOATIME:         "MS_NOATIME",
		unix.MS_NODIRATIME:      "MS_NODIRATIME",
		unix.MS_SILENT:          "MS_SILENT",
		unix.MS_RELATIME:        "MS_RELATIME",
		unix.MS_I_VERSION:       "MS_I_VERSION",
		unix.MS_STRICTATIME:     "MS_STRICTATIME",
		bpfenforcer.AaMayUmount: "UMOUNT",
	}
}

func loadAuditEventMetadata() map[string]string {
	metadata := make(map[string]string)
	s := os.Getenv(metadataJSONEnv)
	if s != "" {
		json.Unmarshal([]byte(s), &metadata)
	}
	return metadata
}

func ParseAppArmorEvent(e string) (*AppArmorEvent, error) {
	msg := C.CString(e)
	defer C.free(unsafe.Pointer(msg))
	record := C.parse_record(msg)
	defer C.free_record(record)

	if record == nil {
		return nil, fmt.Errorf("C.parse_record(msg) failed")
	}

	event := AppArmorEvent{
		Version:        uint32(record.version),
		Event:          uint32(record.event),
		PID:            uint64(record.pid),
		PeerPID:        uint64(record.peer_pid),
		Task:           uint64(record.task),
		MagicToken:     uint64(record.magic_token),
		Epoch:          int64(record.epoch),
		AuditSubId:     uint32(record.audit_sub_id),
		BitMask:        int32(record.bitmask),
		AuditId:        C.GoString(record.audit_id),
		Operation:      C.GoString(record.operation),
		DeniedMask:     C.GoString(record.denied_mask),
		RequestedMask:  C.GoString(record.requested_mask),
		Fsuid:          uint64(record.fsuid),
		Ouid:           uint64(record.ouid),
		Profile:        C.GoString(record.profile),
		PeerProfile:    C.GoString(record.peer_profile),
		Comm:           C.GoString(record.comm),
		Name:           C.GoString(record.name),
		Name2:          C.GoString(record.name2),
		Namespace:      C.GoString(record.namespace),
		Attribute:      C.GoString(record.attribute),
		Parent:         uint64(record.parent),
		Info:           C.GoString(record.info),
		PeerInfo:       C.GoString(record.peer_info),
		ErrorCode:      int32(record.error_code),
		ActiveHat:      C.GoString(record.active_hat),
		NetFamily:      C.GoString(record.net_family),
		NetProtocol:    C.GoString(record.net_protocol),
		NetSockType:    C.GoString(record.net_sock_type),
		NetLocalAddr:   C.GoString(record.net_local_addr),
		NetLocalPort:   uint64(record.net_local_port),
		NetForeignAddr: C.GoString(record.net_foreign_addr),
		NetForeignPort: uint64(record.net_foreign_port),
		DbusBus:        C.GoString(record.dbus_bus),
		DbusPath:       C.GoString(record.dbus_path),
		DbusInterface:  C.GoString(record.dbus_interface),
		DbusMember:     C.GoString(record.dbus_member),
		Signal:         C.GoString(record.signal),
		Peer:           C.GoString(record.peer),
		FsType:         C.GoString(record.fs_type),
		Flags:          C.GoString(record.flags),
		SrcName:        C.GoString(record.src_name),
	}

	return &event, nil
}

func ParseSeccompAuditEvent(e string) (*SeccompEvent, error) {
	var event SeccompEvent
	var err error
	var auditid, subj, pid, comm, exe, syscall string
	var i, s int

	buf := []byte(e)

	// extract audit id
	for i < len(buf)-6 {
		if buf[i] == 'a' && buf[i+1] == 'u' && buf[i+2] == 'd' && buf[i+3] == 'i' && buf[i+4] == 't' && buf[i+5] == '(' {
			i += 6
			start := i
			for i < len(buf) && buf[i] != ')' {
				i++
			}
			auditid = string(buf[start:i])
			break
		}
		i++
	}

	for i < len(buf) {
		// extract subj
		if len(event.Subj) == 0 && i+6 < len(buf) && buf[i] == 's' && buf[i+1] == 'u' && buf[i+2] == 'b' && buf[i+3] == 'j' && buf[i+4] == '=' {
			if buf[i+5] == '=' {
				i += len("subj==")
			} else {
				i += len("subj=")
			}

			start := i
			// We assume that the pid field is following the subj field
			for i < len(buf)-5 {
				if buf[i] == ' ' && buf[i+1] == 'p' && buf[i+2] == 'i' && buf[i+3] == 'd' && buf[i+4] == '=' {
					subj = strings.Trim(string(buf[start:i]), "\"")
					break
				} else {
					i++
				}
			}
		}

		// extract other fields
		extractField := func(prefix string, target *string) {
			if len(*target) == 0 && i+len(prefix) <= len(buf) && string(buf[i:i+len(prefix)]) == prefix {
				i += len(prefix)
				start := i
				for i < len(buf) && buf[i] != ' ' {
					i++
				}
				s := string(buf[start:i])
				*target = strings.Trim(s, "\"")
			}
		}

		extractField(" pid=", &pid)
		extractField(" comm=", &comm)
		extractField(" exe=", &exe)
		extractField(" syscall=", &syscall)

		i++
	}

	if auditid == "" || pid == "" || syscall == "" {
		return nil, fmt.Errorf("failed to extract the fields of seccomp event")
	}

	event.AuditID = auditid
	event.Subj = subj
	event.Comm = comm
	event.Exe = exe

	t := auditid[:strings.Index(auditid, ".")]
	event.Epoch, err = strconv.ParseUint(t, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse epoch")
	}

	event.PID, err = strconv.ParseUint(pid, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pid")
	}

	s, err = strconv.Atoi(syscall)
	if err != nil {
		return nil, fmt.Errorf("failed to parse syscall")
	}
	event.Syscall, err = seccomp.ScmpSyscall(s).GetName()
	if err != nil {
		return nil, fmt.Errorf("failed to parse syscall with seccomp.ScmpSyscall()")
	}

	return &event, nil
}

func ParseProfileName(profile string) string {
	if profile == "" || profile == "?" {
		return ""
	}
	s := strings.Split(profile, "/")[0]
	return strings.Split(s, " ")[0]
}
