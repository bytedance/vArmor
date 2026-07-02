// Copyright 2026 vArmor Authors
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

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	dataaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	als "github.com/bytedance/vArmor/pkg/networkproxy/als"
)

// alsGracefulStopTimeout bounds how long closeALSConsumer waits for the ALS
// gRPC server to drain its open StreamAccessLogs streams before force-stopping
// it. Sidecars keep their streams open indefinitely, so without this bound
// GracefulStop would block forever while the agent is shutting down.
const alsGracefulStopTimeout = 2 * time.Second

// enforcerNetworkProxy is the enforcer label stamped onto NetworkProxy
// violation events so they line up with the "AppArmor"/"Seccomp" events that
// already flow into the violations log.
const enforcerNetworkProxy = "NetworkProxy"

// The normalised action labels recorded in the violations log. They match the
// AppArmor collector's "DENIED"/"AUDIT" strings so downstream consumers parse a
// single action vocabulary across all enforcers.
const (
	actionDenied = "DENIED"
	actionAudit  = "AUDIT"
)

// OSI layer tags stamped onto a NetworkProxy event. L4 comes from listener-level
// (TCP) access-log entries, L7 from HTTP connection-manager entries.
const (
	layerL4 = "L4"
	layerL7 = "L7"
)

// node.metadata keys that carry the Pod identity in the ALS Identifier. They
// MUST match the keys emitted by the sidecar's Envoy "--config-yaml" overlay
// (varmorpolicy.AuditNodeMetadataOverlay), whose $(POD_*) references the
// kubelet resolves from the POD_NAME / POD_NAMESPACE / POD_UID Downward API
// environment variables. The agent reads them straight from
// Identifier.Node.Metadata, so a NetworkProxy event is attributed to its Pod
// without any reverse lookup by profile name.
const (
	nodeMetaPodName      = "pod_name"
	nodeMetaPodNamespace = "pod_namespace"
	nodeMetaPodUID       = "pod_uid"
)

// NetworkProxyEvent is the enforcer-specific payload of a NetworkProxy
// violation. It is normalised from Envoy's HTTPAccessLogEntry /
// TCPAccessLogEntry so NetworkProxy events land in the same violations log as
// AppArmor and BPF events.
type NetworkProxyEvent struct {
	Layer string `json:"layer"`
	// FilterChain is the Envoy filter chain the event originated from (e.g.
	// "http_chain", "mitm_tls_dns_chain"). It is recovered from the gRPC ALS
	// filter_chain custom_tag and is only populated for L7 (HCM) chains; the L4
	// listener-level access_log is shared across the passthrough chains and
	// cannot carry it, so it is omitted there.
	FilterChain  string `json:"filterChain,omitempty"`
	DstAddress   string `json:"dstAddress,omitempty"`
	SNI          string `json:"sni,omitempty"`
	Authority    string `json:"authority,omitempty"`
	Method       string `json:"method,omitempty"`
	Path         string `json:"path,omitempty"`
	ResponseCode uint32 `json:"responseCode,omitempty"`
	Reason       string `json:"reason,omitempty"`
	DurationMs   uint64 `json:"durationMs,omitempty"`
}

// parseLogName decodes an ALS identifier log_name of the form
// "<class>:<profileName>" into the normalised action and the profile name. The
// class prefix selects the action: a deny class maps to DENIED, an audit class
// to AUDIT. Because deny and audit (shadow) events are rendered as two separate
// access_log entries with distinct log_name prefixes, the action is decided
// entirely by the prefix and never by inspecting the entry body. An
// unrecognised class or an empty profile name yields ok=false so the caller can
// drop the stream defensively. The class vocabulary is a shared convention
// between the renderer and this auditor.
func parseLogName(logName string) (action, profileName string, ok bool) {
	idx := strings.IndexByte(logName, ':')
	if idx < 0 {
		return "", "", false
	}
	class, profileName := logName[:idx], logName[idx+1:]
	if profileName == "" {
		return "", "", false
	}
	switch class {
	case als.LogNameClassDeny:
		return actionDenied, profileName, true
	case als.LogNameClassAudit:
		return actionAudit, profileName, true
	default:
		return "", "", false
	}
}

// podIdentity carries the Pod attribution parsed once from the ALS Identifier's
// node.metadata. NetworkProxy events are attributed at Pod granularity (the
// container/process-level fields are not applicable), so the Pod uid/name/
// namespace recorded here are the complete identity for every entry of a
// stream.
type podIdentity struct {
	podName      string
	podNamespace string
	podUID       string
}

// alsServer implements envoy.service.accesslog.v3.AccessLogService. Each Envoy
// sidecar opens one StreamAccessLogs stream and pushes the violation entries its
// CEL filters selected; the server classifies the stream from the first
// message's identifier and emits a normalised event per entry.
type alsServer struct {
	accesslogv3.UnimplementedAccessLogServiceServer
	auditor *Auditor
}

// StreamAccessLogs consumes a single sidecar's access-log stream. Per the ALS
// contract the identifier (carrying log_name and node.metadata) is sent only on
// the first message and reused for the rest of the stream, so the action,
// profile name and Pod identity are parsed once and cached. Entries arrive as
// either HTTP (L7) or TCP (L4) batches; each entry is normalised and written to
// the violations log.
func (s *alsServer) StreamAccessLogs(stream accesslogv3.AccessLogService_StreamAccessLogsServer) error {
	var (
		action, profileName string
		pod                 podIdentity
		identified          bool
	)
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if !identified {
			id := msg.GetIdentifier()
			if id == nil {
				// The first message must carry the identifier; without it the
				// stream cannot be classified. Drop it cleanly so Envoy does
				// not spin in a reconnect loop on a returned error.
				s.auditor.log.V(1).Info("dropping ALS stream without identifier")
				return nil
			}
			a, p, ok := parseLogName(id.GetLogName())
			if !ok {
				s.auditor.log.V(1).Info("dropping ALS stream with unrecognised log_name",
					"logName", id.GetLogName())
				return nil
			}
			action, profileName = a, p
			pod = parsePodIdentity(id.GetNode())
			identified = true
		}

		for _, e := range msg.GetHttpLogs().GetLogEntry() {
			event, eventTime := buildHTTPNetworkProxyEvent(e)
			s.auditor.recordNetworkProxyViolation(action, profileName, pod, eventTime, event)
		}
		for _, e := range msg.GetTcpLogs().GetLogEntry() {
			event, eventTime := buildTCPNetworkProxyEvent(e)
			s.auditor.recordNetworkProxyViolation(action, profileName, pod, eventTime, event)
		}
	}
}

// parsePodIdentity extracts the Pod name, namespace and uid from the ALS
// Identifier's node.metadata. Missing keys yield empty strings, which the
// violations log records verbatim so an operator can still see that attribution
// was unavailable.
func parsePodIdentity(node *corev3.Node) podIdentity {
	fields := node.GetMetadata().GetFields()
	return podIdentity{
		podName:      fields[nodeMetaPodName].GetStringValue(),
		podNamespace: fields[nodeMetaPodNamespace].GetStringValue(),
		podUID:       fields[nodeMetaPodUID].GetStringValue(),
	}
}

// recordNetworkProxyViolation writes a normalised NetworkProxy violation to the
// violations log, using the same field set as the AppArmor and BPF collectors.
// The container/process-level fields (containerID, containerName, image, pid,
// mntNsID) are not applicable to a NetworkProxy event and are left empty; the
// event is attributed at Pod granularity by podUID/podName/podNamespace
// resolved from node.metadata. ALLOWED events are not produced: the CEL filters
// only select deny and shadow entries.
func (auditor *Auditor) recordNetworkProxyViolation(action, profileName string, pod podIdentity, eventTime time.Time, event NetworkProxyEvent) {
	auditor.log.V(2).Info("received a NetworkProxy audit event",
		"pod uid", pod.podUID,
		"pod name", pod.podName,
		"pod namespace", pod.podNamespace,
		"enforcer", enforcerNetworkProxy,
		"action", action,
		"profile", profileName,
		"event", event)

	var eventTimestamp uint64
	if !eventTime.IsZero() {
		eventTimestamp = uint64(eventTime.Unix())
	}
	auditor.violationLogger.Warn().
		Interface("metadata", auditor.auditEventMetadata).
		Str("nodeName", auditor.nodeName).
		Str("podUID", pod.podUID).
		Str("podName", pod.podName).
		Str("podNamespace", pod.podNamespace).
		Str("containerID", "").
		Str("containerName", "").
		Str("image", "").
		Uint32("pid", 0).
		Uint32("mntNsID", 0).
		Uint64("eventTimestamp", eventTimestamp).
		Str("enforcer", enforcerNetworkProxy).
		Str("action", action).
		Str("profileName", profileName).
		Func(auditor.withPolicyIdentity(profileName)).
		Interface("event", event).Msg("violation event")
}

func buildTCPNetworkProxyEvent(e *dataaccesslogv3.TCPAccessLogEntry) (NetworkProxyEvent, time.Time) {
	c := e.GetCommonProperties()
	return NetworkProxyEvent{
		Layer:       layerL4,
		FilterChain: filterChainTag(c),
		DstAddress:  formatAddress(c.GetDownstreamLocalAddress()),
		SNI:         c.GetTlsProperties().GetTlsSniHostname(),
		Reason:      c.GetConnectionTerminationDetails(),
		DurationMs:  commonDurationMillis(c),
	}, accessLogStartTime(c)
}

func buildHTTPNetworkProxyEvent(e *dataaccesslogv3.HTTPAccessLogEntry) (NetworkProxyEvent, time.Time) {
	c := e.GetCommonProperties()
	req := e.GetRequest()
	resp := e.GetResponse()
	return NetworkProxyEvent{
		Layer:       layerL7,
		FilterChain: filterChainTag(c),
		DstAddress:  formatAddress(c.GetDownstreamLocalAddress()),
		// SNI is the TLS-handshake server name only; it is never backfilled from
		// the HTTP Host/:authority. Keeping the two fields independent is what
		// lets an analyst detect domain fronting, where the TLS SNI (an allowed
		// front domain) deliberately differs from the encrypted Host that names
		// the real backend. The Host is recorded separately in Authority.
		SNI:          c.GetTlsProperties().GetTlsSniHostname(),
		Authority:    firstNonEmpty(req.GetRequestHeaders()[":authority"], req.GetAuthority()),
		Method:       requestMethodString(req.GetRequestMethod()),
		Path:         req.GetPath(),
		ResponseCode: responseCode(resp),
		Reason:       resp.GetResponseCodeDetails(),
		DurationMs:   commonDurationMillis(c),
	}, accessLogStartTime(c)
}

// filterChainTag returns the originating Envoy filter chain name carried in the
// gRPC ALS filter_chain custom_tag, or "" if absent. The renderer emits this
// tag only on L7 (HCM) access_log entries; the L4 listener-level access_log is
// shared across the passthrough chains and never carries it, so this returns ""
// for them.
func filterChainTag(c *dataaccesslogv3.AccessLogCommon) string {
	return c.GetCustomTags()[als.ALSFilterChainTagKey]
}

func accessLogStartTime(c *dataaccesslogv3.AccessLogCommon) time.Time {
	if ts := c.GetStartTime(); ts != nil {
		return ts.AsTime()
	}
	return time.Time{}
}

func responseCode(resp *dataaccesslogv3.HTTPResponseProperties) uint32 {
	if rc := resp.GetResponseCode(); rc != nil {
		return rc.GetValue()
	}
	return 0
}

// commonDurationMillis returns the total connection/request duration in
// milliseconds.
//
// The protobuf AccessLogCommon.duration field is the authoritative total: for
// HTTP it is start-to-last-byte-out, and for TCP it is the total downstream
// connection duration. We prefer it and fall back to
// time_to_last_downstream_tx_byte only when duration is absent. This matters
// for L4 passthrough (tcp_proxy) entries: Envoy populates the connection total
// in duration but does not always set time_to_last_downstream_tx_byte (a
// response-oriented field), so reading the latter alone yielded 0 and the
// omitempty JSON tag dropped durationMs entirely.
func commonDurationMillis(c *dataaccesslogv3.AccessLogCommon) uint64 {
	if d := c.GetDuration(); d != nil {
		return durationMillis(d)
	}
	return durationMillis(c.GetTimeToLastDownstreamTxByte())
}

func durationMillis(d *durationpb.Duration) uint64 {
	if d == nil {
		return 0
	}
	ms := d.AsDuration().Milliseconds()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}

func requestMethodString(m corev3.RequestMethod) string {
	if m == corev3.RequestMethod_METHOD_UNSPECIFIED {
		return ""
	}
	return m.String()
}

func formatAddress(addr *corev3.Address) string {
	if addr == nil {
		return ""
	}
	if sa := addr.GetSocketAddress(); sa != nil {
		if port := sa.GetPortValue(); port != 0 {
			return net.JoinHostPort(sa.GetAddress(), portString(port))
		}
		return sa.GetAddress()
	}
	if pipe := addr.GetPipe(); pipe != nil {
		return pipe.GetPath()
	}
	return addr.String()
}

func portString(port uint32) string {
	return strconv.FormatUint(uint64(port), 10)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// startALSConsumer binds the host-side UDS and serves the ALS gRPC service on a
// background goroutine. It is called from Run. Like the other collectors, a
// bind failure is not fatal: the agent logs and continues so the remaining
// collectors still run, and a failed ALS connection only loses audit data
// without affecting the sidecar's traffic forwarding.
func (auditor *Auditor) startALSConsumer() {
	if auditor.alsSocketPath == "" {
		auditor.log.V(1).Info("ALS socket path empty, skipping NetworkProxy ALS collector")
		return
	}
	// Two-level directory isolation with no chown, so the model never depends on
	// the sidecar's (configurable) uid/gid:
	//
	//   socketDir = filepath.Dir(socketPath)  the leaf the sidecar mounts
	//   gateDir   = filepath.Dir(socketDir)   the root-owned access gate
	//
	// gateDir is the access gate: root-owned 0700, and it is NOT mounted into
	// the sidecar. A non-root host user must traverse gateDir to reach the
	// socket and is denied there, so it cannot enter or enumerate anything
	// below. socketDir IS the sidecar's mount point and is 0711: traverse
	// without list, so the sidecar's Envoy (a non-root uid) can path-walk into
	// it to connect, but host users (already blocked at gateDir) gain no
	// exposure. The sidecar reaches socketDir through its own container path
	// tree, not through the host's gateDir, so gateDir 0700 does not block it.
	socketDir := filepath.Dir(auditor.alsSocketPath)
	gateDir := filepath.Dir(socketDir)
	if err := os.MkdirAll(socketDir, 0o711); err != nil {
		auditor.log.Info("cannot create ALS socket directory, skipping NetworkProxy ALS collector",
			"dir", socketDir, "reason", err.Error())
		return
	}
	// Enforce modes on the directories so the isolation model holds even when
	// the kubelet auto-created them for a DirectoryOrCreate hostPath with its
	// default root:root 0755. gateDir and socketDir are distinct directories,
	// so the order of the two chmods does not matter.
	if err := os.Chmod(gateDir, 0o700); err != nil {
		auditor.log.Info("cannot chmod ALS gate directory", "dir", gateDir, "reason", err.Error())
	}
	if err := os.Chmod(socketDir, 0o711); err != nil {
		auditor.log.Info("cannot chmod ALS socket directory", "dir", socketDir, "reason", err.Error())
	}
	// Remove a stale socket left by a previous run before binding.
	if err := os.Remove(auditor.alsSocketPath); err != nil && !os.IsNotExist(err) {
		auditor.log.Info("cannot remove stale ALS socket, skipping NetworkProxy ALS collector",
			"path", auditor.alsSocketPath, "reason", err.Error())
		return
	}
	lis, err := net.Listen("unix", auditor.alsSocketPath)
	if err != nil {
		auditor.log.Info("cannot listen on ALS socket, skipping NetworkProxy ALS collector",
			"path", auditor.alsSocketPath, "reason", err.Error())
		return
	}
	// connect(2) to a UNIX stream socket requires write permission on the
	// socket file. The socket is 0666 so the sidecar's Envoy (a non-root uid,
	// whatever it is configured to) can connect; this is safe because access is
	// already gated by the root-owned 0700 gateDir above, which keeps every
	// other non-root host user away from the socket entirely.
	if err := os.Chmod(auditor.alsSocketPath, 0o666); err != nil {
		auditor.log.Info("cannot chmod ALS socket", "path", auditor.alsSocketPath, "reason", err.Error())
	}

	srv := grpc.NewServer()
	accesslogv3.RegisterAccessLogServiceServer(srv, &alsServer{auditor: auditor})
	auditor.alsListener = lis
	auditor.alsServer = srv

	auditor.alsWg.Add(1)
	go func() {
		defer auditor.alsWg.Done()
		auditor.log.Info("starting NetworkProxy ALS gRPC server", "path", auditor.alsSocketPath)
		if err := srv.Serve(lis); err != nil {
			auditor.log.V(1).Info("NetworkProxy ALS gRPC server stopped", "reason", err.Error())
		}
	}()
}

// closeALSConsumer stops the ALS gRPC server (which also closes the listener
// and unblocks the serve goroutine) and removes the socket file. It is called
// from Close.
//
// GracefulStop alone is not enough here: each Envoy sidecar holds a long-lived
// StreamAccessLogs server stream that only returns from stream.Recv() when the
// sidecar closes it. GracefulStop waits for in-flight RPCs to finish but never
// cancels them, so as long as a sidecar keeps its stream open the call blocks
// forever. We therefore run GracefulStop in a goroutine and fall back to a
// forceful Stop (which cancels active streams) if it does not finish within a
// short grace period.
func (auditor *Auditor) closeALSConsumer() {
	if auditor.alsServer != nil {
		stopped := make(chan struct{})
		go func() {
			auditor.alsServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(alsGracefulStopTimeout):
			// Sidecar streams are still open; force-cancel them.
			auditor.alsServer.Stop()
			<-stopped
		}
	}
	auditor.alsWg.Wait()
	if auditor.alsSocketPath != "" {
		_ = os.Remove(auditor.alsSocketPath)
	}
}
