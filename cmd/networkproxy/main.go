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

// Command networkproxy-audit-sink is the in-sidecar NetworkProxy ALS audit
// sink for the kata runtime.
//
// Background. In the runc runtime the Envoy sidecar streams its violation
// events over gRPC ALS to a node-local Unix domain socket that the node-central
// varmor-agent listens on; the agent enriches and writes them to
// /var/log/varmor/violations.log. In the kata runtime that socket cannot be
// reached: the sidecar runs inside a micro-VM and a hostPath UDS cannot be
// connect(2)-ed across the VM/virtio-fs boundary, so the node-central agent
// never receives the stream and the violations are lost.
//
// This binary closes that gap. It is baked into the custom Envoy image and
// started by the image entrypoint ONLY when the entrypoint's connect(2)
// self-check against the fixed ALS socket path fails (i.e. no agent socket is
// reachable -> running on kata). It binds the very same socket path inside the
// sidecar, so Envoy -- which always targets that fixed path and is therefore
// 100%% runtime-agnostic (zero fork of the Envoy config Secret) -- streams to
// this in-sidecar sink instead. The sink reuses the exact same auditor code
// path as the agent, so it produces byte-identical enriched records at
// /var/log/varmor/violations.log inside the sidecar container.
//
// It deliberately reuses internal/auditor via the lean NewAuditor path
// (appArmor=false, bpf=false, behaviorModeling=false, auditLogPaths=""), which
// skips the AppArmor audit-log tail and the BPF ringbuf map and only wires up
// the ALS gRPC server plus the violation logger. Enrichment inputs that the
// agent normally derives from its ArmorProfile watch and Downward API are
// instead injected as environment variables at admission time (see the
// NetworkProxy injection path): NODE_NAME, AUDIT_EVENT_METADATA and the policy
// identity (PROFILE_NAME / POLICY_KIND / POLICY_NAME / POLICY_NAMESPACE).
package main

import (
	"flag"
	"net"
	"os"
	"time"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"

	varmorauditor "github.com/bytedance/vArmor/internal/auditor"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorsignal "github.com/bytedance/vArmor/pkg/signal"
)

func main() {
	// -check turns the binary into a one-shot runtime probe used by the custom
	// Envoy image entrypoint to decide whether it is running on runc or kata.
	// It attempts a connect(2) to the fixed ALS socket path and exits 0 when a
	// listener answers (runc: the node-central agent's socket is reachable, so
	// no in-sidecar sink is needed) or non-zero when it does not (kata: the
	// agent socket is unreachable across the VM boundary, so the entrypoint
	// starts this same binary as the in-sidecar sink). Reusing the sink binary
	// for the probe keeps the Envoy image free of extra tooling such as nc.
	checkMode := flag.Bool("check", false,
		"probe the ALS socket and exit 0 if a listener is reachable, non-zero otherwise")
	socketPath := flag.String("socket", varmorconfig.AuditNetworkProxySocketPath,
		"the ALS Unix domain socket path to bind (sink) or probe (-check)")
	flag.Parse()

	if *checkMode {
		conn, err := net.DialTimeout("unix", *socketPath, 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		os.Exit(0)
	}

	zl := zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	logger := zerologr.New(&zl).WithName("NP-AUDIT-SINK")

	// nodeName attributes every record to the physical node hosting the kata
	// Pod. It is injected via the Downward API (spec.nodeName) at admission.
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Info("NODE_NAME is empty; violation records will carry an empty nodeName")
	}

	// Build the auditor over the lean ALS-only path: no AppArmor tail, no BPF
	// ringbuf, just the ALS gRPC server on the fixed in-sidecar socket path and
	// the violation logger at /var/log/varmor/violations.log. AuditEventMetadata
	// is derived by internal/config from the AUDIT_EVENT_METADATA env var.
	auditor, err := varmorauditor.NewAuditor(
		nodeName,
		false, // appArmorSupported
		false, // bpfLsmSupported
		false, // enableBehaviorModeling
		"",    // auditLogPaths (unused when appArmor/bpf are false)
		*socketPath,
		varmorconfig.AuditEventMetadata,
		logger.WithName("AUDITOR"),
	)
	if err != nil {
		logger.Error(err, "failed to create the NetworkProxy audit sink")
		os.Exit(1)
	}

	// The sink shares the container/mount namespace with the Envoy sidecar it
	// collects from, so the ALS gate directory must be traversable by the
	// co-located non-root Envoy. Mark the auditor accordingly before Run so it
	// relaxes the gate directory to 0711 instead of the agent's root-only 0700.
	auditor.SetColocatedSidecar(true)

	// Seed the policy identity so violation records carry the owning policy's
	// Kind/Name/Namespace. The agent normally learns this from its ArmorProfile
	// watch, which this sink has no access to; instead the injection path passes
	// the identity as environment variables keyed by the sidecar's own
	// ArmorProfile name (PROFILE_NAME), the same key the ALS log_name carries.
	if profileName := os.Getenv("PROFILE_NAME"); profileName != "" {
		auditor.UpsertPolicyIdentity(profileName, varmorauditor.PolicyIdentity{
			Kind:      os.Getenv("POLICY_KIND"),
			Name:      os.Getenv("POLICY_NAME"),
			Namespace: os.Getenv("POLICY_NAMESPACE"),
		})
	} else {
		logger.Info("PROFILE_NAME is empty; violation records will carry empty policy identity fields")
	}

	stopCh := varmorsignal.SetupSignalHandler()

	logger.Info("starting the in-sidecar NetworkProxy audit sink",
		"socket", *socketPath,
		"logDirectory", "/var/log/varmor")

	// Run blocks on the auditor's event loop (an idle select over the
	// containerd task channels plus stopCh) while the ALS gRPC server serves in
	// the background. It returns when stopCh is closed by a SIGTERM/SIGINT.
	auditor.Run(stopCh)

	auditor.Close()
	logger.Info("the in-sidecar NetworkProxy audit sink has stopped")
}
