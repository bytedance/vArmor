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

package preprocessor

import (
	"testing"

	"gotest.tools/assert"
	log "sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_trimPath(t *testing.T) {
	targetPIDs := make(map[uint32]struct{}, 10)
	targetMnts := make(map[uint32]struct{}, 10)

	p := NewDataPreprocessor(
		"LOCALHOST",
		"test",
		"/",
		"test",
		"AppArmor",
		targetPIDs,
		targetMnts,
		nil,
		true,
		true,
		log.Log.WithName("TEST"))

	testCases := []struct {
		name         string
		path         string
		expectedPath string
	}{
		{
			name:         "proc_0",
			path:         "/proc/1",
			expectedPath: "/proc/*",
		},
		{
			name:         "proc_1",
			path:         "/proc/1/",
			expectedPath: "/proc/*/",
		},
		{
			name:         "proc_2",
			path:         "/proc/1106048/fdinfo/10",
			expectedPath: "/proc/*/fdinfo/*",
		},
		{
			name:         "proc_3",
			path:         "/proc/1106110/net/ip6_tables_names",
			expectedPath: "/proc/*/net/ip6_tables_names",
		},
		{
			name:         "proc_4",
			path:         "/proc/1106048/task/10",
			expectedPath: "/proc/*/task/*",
		},
		{
			name:         "proc_5",
			path:         "/proc/9/fd/107",
			expectedPath: "/proc/*/fd/*",
		},
		{
			name:         "proc_6",
			path:         "/proc/1106048/mountinfo",
			expectedPath: "/proc/*/mountinfo",
		},
		{
			name:         "proc_7",
			path:         "/proc/1106048/fdinfo/10",
			expectedPath: "/proc/*/fdinfo/*",
		},
		{
			name:         "proc_8",
			path:         "/proc/122/map_files",
			expectedPath: "/proc/*/map_files",
		},
		{
			name:         "proc_9",
			path:         "/proc/122/map_files/5565eaa95000-5565eaac3000",
			expectedPath: "/proc/*/map_files/*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := p.trimPath(tc.path, "wr")
			assert.Equal(t, path, tc.expectedPath)
		})
	}
}
