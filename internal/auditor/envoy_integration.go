//go:build envoyintegration

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

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/go-logr/logr"
	"github.com/rs/zerolog"
)

// NewALSIntegrationService connects integration tests to the production ALS
// handler without opening host log files, kernel collectors or Docker clients.
// This adapter is excluded from normal builds by the envoyintegration tag.
func NewALSIntegrationService(output io.Writer) accesslogv3.AccessLogServiceServer {
	a := &Auditor{nodeName: "node-a", auditEventMetadata: map[string]interface{}{"cluster": "test"},
		violationLogger: zerolog.New(output), policyIdentityCache: make(map[string]PolicyIdentity), log: logr.Discard()}
	return &alsServer{auditor: a}
}
