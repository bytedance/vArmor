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

import (
	"testing"
	"time"

	"gotest.tools/assert"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_SystemdJournald(t *testing.T) {

	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	a, err := NewAuditor("test", true, false, true, "/var/log/audit/audit.log|/var/log/kern.log", log.Log.WithName("AUDITOR"))
	assert.NilError(t, err)

	syncCh := make(chan struct{}, 1)

	go a.Run(syncCh)

	stopTicker := time.NewTicker(3 * time.Second)
	<-stopTicker.C

	a.Close()
}
