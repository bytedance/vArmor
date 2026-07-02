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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	dataaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/go-logr/logr"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	als "github.com/bytedance/vArmor/pkg/networkproxy/als"
)

var (
	tcpStartTime  = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	httpStartTime = time.Date(2026, 6, 17, 12, 0, 1, 0, time.UTC)
)

// recordedViolation is the decoded shape of one JSON line written by the
// violationLogger. Only the fields the NetworkProxy collector populates are
// declared; the rest are ignored by the JSON decoder.
type recordedViolation struct {
	NodeName       string            `json:"nodeName"`
	PodName        string            `json:"podName"`
	PodNamespace   string            `json:"podNamespace"`
	PodUID         string            `json:"podUID"`
	ContainerID    string            `json:"containerID"`
	Enforcer       string            `json:"enforcer"`
	Action         string            `json:"action"`
	ProfileName    string            `json:"profileName"`
	EventTimestamp uint64            `json:"eventTimestamp"`
	Event          NetworkProxyEvent `json:"event"`
}

// newTestAuditor builds an Auditor whose violationLogger writes JSON lines to
// the returned buffer, bypassing NewAuditor's file/tail/ringbuf setup so the
// ALS path can be exercised in isolation.
func newTestAuditor(buf *bytes.Buffer) *Auditor {
	return &Auditor{
		nodeName:           "node-a",
		auditEventMetadata: map[string]interface{}{"cluster": "test"},
		violationLogger:    zerolog.New(buf).With().Timestamp().Logger(),
		log:                logr.Discard(),
	}
}

func decodeViolations(t *testing.T, buf *bytes.Buffer) []recordedViolation {
	t.Helper()
	var out []recordedViolation
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for {
		var v recordedViolation
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode violation line: %v", err)
		}
		out = append(out, v)
	}
	return out
}

func TestParseLogName(t *testing.T) {
	tests := []struct {
		name        string
		logName     string
		wantAction  string
		wantProfile string
		wantOK      bool
	}{
		{
			name:        "deny",
			logName:     als.LogNameClassDeny + ":profile-a",
			wantAction:  actionDenied,
			wantProfile: "profile-a",
			wantOK:      true,
		},
		{
			name:        "audit",
			logName:     als.LogNameClassAudit + ":profile-b",
			wantAction:  actionAudit,
			wantProfile: "profile-b",
			wantOK:      true,
		},
		{name: "unknown class", logName: "unknown:profile", wantOK: false},
		{name: "missing separator", logName: "profile", wantOK: false},
		{name: "empty profile", logName: als.LogNameClassDeny + ":", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAction, gotProfile, gotOK := parseLogName(tt.logName)
			if gotOK != tt.wantOK || gotAction != tt.wantAction || gotProfile != tt.wantProfile {
				t.Fatalf("parseLogName(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.logName, gotAction, gotProfile, gotOK, tt.wantAction, tt.wantProfile, tt.wantOK)
			}
		})
	}
}

func TestALSStreamAccessLogsEmitsNetworkProxyEvents(t *testing.T) {
	var buf bytes.Buffer
	a := newTestAuditor(&buf)

	stream := &fakeALSStream{
		ctx: context.Background(),
		messages: []*accesslogv3.StreamAccessLogsMessage{
			{
				Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{
					LogName: als.LogNameClassDeny + ":profile-a",
					Node:    podNode("workload-a", "team-x", "uid-123"),
				},
				LogEntries: &accesslogv3.StreamAccessLogsMessage_TcpLogs{
					TcpLogs: &accesslogv3.StreamAccessLogsMessage_TCPAccessLogEntries{
						LogEntry: []*dataaccesslogv3.TCPAccessLogEntry{tcpAccessLogEntry()},
					},
				},
			},
			{
				LogEntries: &accesslogv3.StreamAccessLogsMessage_HttpLogs{
					HttpLogs: &accesslogv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
						LogEntry: []*dataaccesslogv3.HTTPAccessLogEntry{httpAccessLogEntry()},
					},
				},
			},
		},
	}

	if err := (&alsServer{auditor: a}).StreamAccessLogs(stream); err != nil {
		t.Fatalf("StreamAccessLogs() error = %v", err)
	}

	events := decodeViolations(t, &buf)
	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(events))
	}

	// Both entries share the Pod identity parsed once from the first message's
	// node.metadata and the deny action/profile from its log_name.
	for i, ev := range events {
		if ev.Enforcer != enforcerNetworkProxy {
			t.Errorf("event[%d] enforcer = %q, want %q", i, ev.Enforcer, enforcerNetworkProxy)
		}
		if ev.Action != actionDenied || ev.ProfileName != "profile-a" {
			t.Errorf("event[%d] action/profile = (%q, %q), want (DENIED, profile-a)", i, ev.Action, ev.ProfileName)
		}
		if ev.NodeName != "node-a" {
			t.Errorf("event[%d] nodeName = %q, want node-a", i, ev.NodeName)
		}
		if ev.PodName != "workload-a" || ev.PodNamespace != "team-x" || ev.PodUID != "uid-123" {
			t.Errorf("event[%d] pod identity = (%q, %q, %q), want (workload-a, team-x, uid-123)", i, ev.PodName, ev.PodNamespace, ev.PodUID)
		}
		// Container/process-level fields are not applicable to NetworkProxy.
		if ev.ContainerID != "" {
			t.Errorf("event[%d] expected empty container-level fields, got containerID=%q", i, ev.ContainerID)
		}
	}

	wantTCP := NetworkProxyEvent{
		Layer:      layerL4,
		DstAddress: "10.0.0.10:443",
		SNI:        "example.org",
		Reason:     "rbac_access_denied_matched_policy[deny-all]",
		DurationMs: 125,
	}
	if events[0].Event != wantTCP {
		t.Fatalf("TCP event = %+v, want %+v", events[0].Event, wantTCP)
	}
	if events[0].EventTimestamp != uint64(tcpStartTime.Unix()) {
		t.Fatalf("TCP eventTimestamp = %d, want %d", events[0].EventTimestamp, tcpStartTime.Unix())
	}

	wantHTTP := NetworkProxyEvent{
		Layer:        layerL7,
		DstAddress:   "10.0.0.20:8443",
		SNI:          "allowed-front.example.com",
		Authority:    "secret-backend.example.org",
		Method:       "POST",
		Path:         "/v1/orders",
		ResponseCode: 403,
		Reason:       "rbac_access_denied_matched_policy[http-deny]",
		DurationMs:   250,
	}
	if events[1].Event != wantHTTP {
		t.Fatalf("HTTP event = %+v, want %+v", events[1].Event, wantHTTP)
	}
	if events[1].EventTimestamp != uint64(httpStartTime.Unix()) {
		t.Fatalf("HTTP eventTimestamp = %d, want %d", events[1].EventTimestamp, httpStartTime.Unix())
	}
}

func TestALSStreamAccessLogsAuditAction(t *testing.T) {
	var buf bytes.Buffer
	a := newTestAuditor(&buf)
	stream := &fakeALSStream{
		ctx: context.Background(),
		messages: []*accesslogv3.StreamAccessLogsMessage{{
			Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{
				LogName: als.LogNameClassAudit + ":profile-b",
			},
			LogEntries: &accesslogv3.StreamAccessLogsMessage_HttpLogs{
				HttpLogs: &accesslogv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
					LogEntry: []*dataaccesslogv3.HTTPAccessLogEntry{{}},
				},
			},
		}},
	}

	if err := (&alsServer{auditor: a}).StreamAccessLogs(stream); err != nil {
		t.Fatalf("StreamAccessLogs() error = %v", err)
	}
	events := decodeViolations(t, &buf)
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	if events[0].Action != actionAudit || events[0].ProfileName != "profile-b" {
		t.Fatalf("action/profile = (%q, %q), want (AUDIT, profile-b)", events[0].Action, events[0].ProfileName)
	}
	if events[0].Event.Layer != layerL7 {
		t.Fatalf("layer = %q, want L7", events[0].Event.Layer)
	}
	// A missing node.metadata leaves Pod attribution empty rather than failing.
	if events[0].PodName != "" || events[0].PodNamespace != "" || events[0].PodUID != "" {
		t.Fatalf("expected empty pod identity, got (%q, %q, %q)", events[0].PodName, events[0].PodNamespace, events[0].PodUID)
	}
}

func TestALSStreamAccessLogsDropsUnidentifiedStreams(t *testing.T) {
	tests := []struct {
		name     string
		messages []*accesslogv3.StreamAccessLogsMessage
	}{
		{
			name: "missing identifier",
			messages: []*accesslogv3.StreamAccessLogsMessage{{
				LogEntries: &accesslogv3.StreamAccessLogsMessage_TcpLogs{
					TcpLogs: &accesslogv3.StreamAccessLogsMessage_TCPAccessLogEntries{
						LogEntry: []*dataaccesslogv3.TCPAccessLogEntry{{}},
					},
				},
			}},
		},
		{
			name: "unknown log name",
			messages: []*accesslogv3.StreamAccessLogsMessage{{
				Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{LogName: "unknown:profile-a"},
				LogEntries: &accesslogv3.StreamAccessLogsMessage_TcpLogs{
					TcpLogs: &accesslogv3.StreamAccessLogsMessage_TCPAccessLogEntries{
						LogEntry: []*dataaccesslogv3.TCPAccessLogEntry{{}},
					},
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			a := newTestAuditor(&buf)
			stream := &fakeALSStream{ctx: context.Background(), messages: tt.messages}

			if err := (&alsServer{auditor: a}).StreamAccessLogs(stream); err != nil {
				t.Fatalf("StreamAccessLogs() error = %v", err)
			}
			if got := len(decodeViolations(t, &buf)); got != 0 {
				t.Fatalf("emitted %d events, want 0", got)
			}
		})
	}
}

func TestBuildTCPNetworkProxyEventDurationFromDurationField(t *testing.T) {
	// For a TCP passthrough connection Envoy reports the total connection time
	// in AccessLogCommon.duration. It does NOT necessarily set time_to_last_downstream_tx_byte,
	// a response-oriented field. This entry mimics that real-world shape
	// (duration set, tx-byte unset) and pins that the L4 branch reads duration
	// so durationMs is populated instead of being dropped by the omitempty tag.
	entry := &dataaccesslogv3.TCPAccessLogEntry{
		CommonProperties: &dataaccesslogv3.AccessLogCommon{
			DownstreamLocalAddress: socketAddress("10.0.0.5", 443),
			TlsProperties:          &dataaccesslogv3.TLSProperties{TlsSniHostname: "open.feishu.cn"},
			StartTime:              timestamppb.New(tcpStartTime),
			Duration:               durationpb.New(991 * time.Millisecond),
		},
	}

	got, gotTime := buildTCPNetworkProxyEvent(entry)
	want := NetworkProxyEvent{
		Layer:      layerL4,
		DstAddress: "10.0.0.5:443",
		SNI:        "open.feishu.cn",
		DurationMs: 991,
	}
	if got != want {
		t.Fatalf("buildTCPNetworkProxyEvent() = %+v, want %+v", got, want)
	}
	if !gotTime.Equal(tcpStartTime) {
		t.Fatalf("event time = %s, want %s", gotTime, tcpStartTime)
	}
}

func TestFilterChainTagOnlyOnL7(t *testing.T) {
	// The renderer injects the filter_chain custom_tag only on L7 (HCM) entries;
	// the L4 listener access_log is shared across passthrough chains and carries
	// no tag. Verify the HTTP builder surfaces it and the TCP builder omits it.
	httpEntry := &dataaccesslogv3.HTTPAccessLogEntry{
		CommonProperties: &dataaccesslogv3.AccessLogCommon{
			CustomTags: map[string]string{als.ALSFilterChainTagKey: als.FilterChainNameHTTP},
		},
	}
	httpEvent, _ := buildHTTPNetworkProxyEvent(httpEntry)
	if httpEvent.FilterChain != als.FilterChainNameHTTP {
		t.Fatalf("HTTP filterChain = %q, want %q", httpEvent.FilterChain, als.FilterChainNameHTTP)
	}

	tcpEntry := &dataaccesslogv3.TCPAccessLogEntry{
		CommonProperties: &dataaccesslogv3.AccessLogCommon{},
	}
	tcpEvent, _ := buildTCPNetworkProxyEvent(tcpEntry)
	if tcpEvent.FilterChain != "" {
		t.Fatalf("TCP filterChain = %q, want empty", tcpEvent.FilterChain)
	}
}

func tcpAccessLogEntry() *dataaccesslogv3.TCPAccessLogEntry {
	return &dataaccesslogv3.TCPAccessLogEntry{
		CommonProperties: &dataaccesslogv3.AccessLogCommon{
			DownstreamLocalAddress:       socketAddress("10.0.0.10", 443),
			TlsProperties:                &dataaccesslogv3.TLSProperties{TlsSniHostname: "example.org"},
			StartTime:                    timestamppb.New(tcpStartTime),
			TimeToLastDownstreamTxByte:   durationpb.New(125 * time.Millisecond),
			ConnectionTerminationDetails: "rbac_access_denied_matched_policy[deny-all]",
		},
	}
}

func httpAccessLogEntry() *dataaccesslogv3.HTTPAccessLogEntry {
	return &dataaccesslogv3.HTTPAccessLogEntry{
		CommonProperties: &dataaccesslogv3.AccessLogCommon{
			DownstreamLocalAddress: socketAddress("10.0.0.20", 8443),
			// Domain fronting: the TLS SNI is an allowed front domain that
			// differs from the encrypted HTTP Host below. The two must be
			// recorded in distinct fields so the mismatch stays detectable.
			TlsProperties:              &dataaccesslogv3.TLSProperties{TlsSniHostname: "allowed-front.example.com"},
			StartTime:                  timestamppb.New(httpStartTime),
			TimeToLastDownstreamTxByte: durationpb.New(250 * time.Millisecond),
		},
		Request: &dataaccesslogv3.HTTPRequestProperties{
			RequestMethod:  corev3.RequestMethod_POST,
			Authority:      "request-authority.example.org",
			RequestHeaders: map[string]string{":authority": "secret-backend.example.org"},
			Path:           "/v1/orders",
		},
		Response: &dataaccesslogv3.HTTPResponseProperties{
			ResponseCode:        wrapperspb.UInt32(403),
			ResponseCodeDetails: "rbac_access_denied_matched_policy[http-deny]",
		},
	}
}

func socketAddress(address string, port uint32) *corev3.Address {
	return &corev3.Address{
		Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{
				Address: address,
				PortSpecifier: &corev3.SocketAddress_PortValue{
					PortValue: port,
				},
			},
		},
	}
}

// podNode builds an ALS node carrying the Pod identity in node.metadata, the
// same shape the sidecar's Envoy "--config-yaml" overlay emits from the
// POD_NAME / POD_NAMESPACE / POD_UID Downward API environment variables.
func podNode(podName, podNamespace, podUID string) *corev3.Node {
	return &corev3.Node{
		Metadata: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				nodeMetaPodName:      structpb.NewStringValue(podName),
				nodeMetaPodNamespace: structpb.NewStringValue(podNamespace),
				nodeMetaPodUID:       structpb.NewStringValue(podUID),
			},
		},
	}
}

type fakeALSStream struct {
	accesslogv3.AccessLogService_StreamAccessLogsServer
	ctx      context.Context
	messages []*accesslogv3.StreamAccessLogsMessage
	idx      int
}

func (s *fakeALSStream) Recv() (*accesslogv3.StreamAccessLogsMessage, error) {
	if s.idx >= len(s.messages) {
		return nil, io.EOF
	}
	msg := s.messages[s.idx]
	s.idx++
	return msg, nil
}

func (s *fakeALSStream) SendAndClose(*accesslogv3.StreamAccessLogsResponse) error { return nil }
func (s *fakeALSStream) SetHeader(metadata.MD) error                              { return nil }
func (s *fakeALSStream) SendHeader(metadata.MD) error                             { return nil }
func (s *fakeALSStream) SetTrailer(metadata.MD)                                   {}
func (s *fakeALSStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
func (s *fakeALSStream) SendMsg(any) error { return nil }
func (s *fakeALSStream) RecvMsg(any) error { return nil }

func TestStartAndCloseALSConsumerLifecycle(t *testing.T) {
	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "als.sock")

	var buf bytes.Buffer
	a := newTestAuditor(&buf)
	a.alsSocketPath = socketPath

	a.startALSConsumer()
	if a.alsServer == nil {
		t.Fatal("alsServer is nil; server did not start (socket dir perms?)")
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("ALS socket not created: %v", err)
	}

	// Open a long-lived StreamAccessLogs stream and keep it in flight, exactly
	// like a live sidecar, so closeALSConsumer must fall back from GracefulStop
	// to a forceful Stop and still return within the grace window.
	conn, err := grpc.NewClient(
		"unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	defer conn.Close()

	stream, err := accesslogv3.NewAccessLogServiceClient(conn).StreamAccessLogs(context.Background())
	if err != nil {
		t.Fatalf("StreamAccessLogs() error = %v", err)
	}
	if err := stream.Send(&accesslogv3.StreamAccessLogsMessage{
		Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{
			LogName: als.LogNameClassDeny + ":profile-a",
		},
	}); err != nil {
		t.Fatalf("stream.Send() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		a.closeALSConsumer()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closeALSConsumer did not return; force-stop fallback failed")
	}

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket path still exists after closeALSConsumer: %v", err)
	}
}

func TestStartALSConsumerNoopWhenSocketPathEmpty(t *testing.T) {
	var buf bytes.Buffer
	a := newTestAuditor(&buf)
	a.alsSocketPath = ""

	a.startALSConsumer()
	if a.alsServer != nil {
		t.Fatal("alsServer should be nil when socket path is empty")
	}
	// closeALSConsumer must be safe to call when nothing was started.
	a.closeALSConsumer()
}
