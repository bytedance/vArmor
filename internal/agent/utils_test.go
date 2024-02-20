// Copyright 2021-2023 vArmor Authors
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

package agent

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
)

func Test_versionGreaterThanOrEqual(t *testing.T) {
	testCases := []struct {
		current        string
		minimumVersion string
		expectedResult bool
		expectedErr    error
	}{
		{
			current:        "4-43",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: false,
			expectedErr:    fmt.Errorf(fmt.Sprintf("the current version (4) < the minimum version (%s)", minKernelVersionForAppArmorLSM)),
		},
		{
			current:        "4.13.117.23.bsk.10-amd64",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: false,
			expectedErr:    fmt.Errorf(fmt.Sprintf("the current version (4.13.117) < the minimum version (%s)", minKernelVersionForAppArmorLSM)),
		},
		{
			current:        "4.14.117.bsk.10-amd64",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: false,
			expectedErr:    fmt.Errorf(fmt.Sprintf("the current version (4.14.117) < the minimum version (%s)", minKernelVersionForAppArmorLSM)),
		},
		{
			current:        "4.15",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "4.15.143",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.4.143-1-velinux1-amd64",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.4.55.9",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.44-velinux",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.4.3-372",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.4.9.4565-344",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.4.119-19-0009.11",
			minimumVersion: minKernelVersionForAppArmorLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.4.0-148-generic",
			minimumVersion: minKernelVersionForBPFLSM,
			expectedResult: false,
			expectedErr:    fmt.Errorf(fmt.Sprintf("the current version (5.4.0) < the minimum version (%s)", minKernelVersionForBPFLSM)),
		},
		{
			current:        "5.6.135-2-velinux1-amd64",
			minimumVersion: minKernelVersionForBPFLSM,
			expectedResult: false,
			expectedErr:    fmt.Errorf(fmt.Sprintf("the current version (5.6.135) < the minimum version (%s)", minKernelVersionForBPFLSM)),
		},
		{
			current:        "5.10.134-13.1.al8.x86_64",
			minimumVersion: minKernelVersionForBPFLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
		{
			current:        "5.10.135-2-velinux1-amd64",
			minimumVersion: minKernelVersionForBPFLSM,
			expectedResult: true,
			expectedErr:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.current, func(t *testing.T) {
			ret, err := versionGreaterThanOrEqual(tc.current, tc.minimumVersion)
			if err != nil {
				assert.Equal(t, err.Error(), tc.expectedErr.Error())
			}
			assert.Equal(t, ret, tc.expectedResult)
		})
	}
}
