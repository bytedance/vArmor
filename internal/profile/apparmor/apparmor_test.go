// Copyright 2025 vArmor Authors
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

package apparmor

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"gotest.tools/assert"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
)

func Test_preprocessAttackProtectionRulesAndCustomRules(t *testing.T) {
	testCases := []struct {
		name               string
		enhanceProtect     varmor.EnhanceProtect
		expectedFinalRules []appArmorRules
	}{
		{
			name: "test_1",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/bash"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/bash"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:    []string{"mitigate-sa-leak"},
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/bash"},
				},
			},
		},
		{
			name: "test_2",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/sh", "/bin/bash"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/bash"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:   []string{"mitigate-sa-leak"},
					Targets: []string{"/bin/sh"},
				},
				{
					Rules:    []string{"mitigate-sa-leak"},
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/bash"},
				},
			},
		},
		{
			name: "test_3",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/bash", "/bin/sh"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/bash"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:    []string{"mitigate-sa-leak"},
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/bash"},
				},
				{
					Rules:   []string{"mitigate-sa-leak"},
					Targets: []string{"/bin/sh"},
				},
			},
		},
		{
			name: "test_4",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/bash", "/bin/sh"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/bash", "/bin/sh"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:    []string{"mitigate-sa-leak"},
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/bash", "/bin/sh"},
				},
			},
		},
		{
			name: "test_5",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak", "disable-curl"},
						Targets: []string{"/bin/bash", "/bin/sh", "/usr/bin/bash"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/sh", "/bin/webshell"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:   []string{"mitigate-sa-leak", "disable-curl"},
					Targets: []string{"/bin/bash", "/usr/bin/bash"},
				},
				{
					Rules:    []string{"mitigate-sa-leak", "disable-curl"},
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/sh"},
				},
				{
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/webshell"},
				},
			},
		},
		{
			name: "test_6",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/bash"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/sh"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:   []string{"mitigate-sa-leak"},
					Targets: []string{"/bin/bash"},
				},
				{
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/sh"},
				},
			},
		},
		{
			name: "test_7",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/bash", "/bin/sh"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/webshell"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:   []string{"mitigate-sa-leak"},
					Targets: []string{"/bin/bash", "/bin/sh"},
				},
				{
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/webshell"},
				},
			},
		},
		{
			name: "test_8",
			enhanceProtect: varmor.EnhanceProtect{
				AttackProtectionRules: []varmor.AttackProtectionRules{
					{
						Rules: []string{"disable-write-etc"},
					},
					{
						Rules:   []string{"mitigate-sa-leak"},
						Targets: []string{"/bin/bash"},
					},
				},
				AppArmorRawRules: []varmor.AppArmorRawRules{
					{
						Rules:   "deny /etc/hosts r,",
						Targets: []string{"/bin/webshell", "/bin/sh"},
					},
				},
			},
			expectedFinalRules: []appArmorRules{
				{
					Rules:   []string{"mitigate-sa-leak"},
					Targets: []string{"/bin/bash"},
				},
				{
					RawRules: []string{"deny /etc/hosts r,"},
					Targets:  []string{"/bin/webshell", "/bin/sh"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			finalRules := preprocessAttackProtectionAndCustomRulesForTargets(&tc.enhanceProtect)
			r, _ := json.MarshalIndent(finalRules, "", "  ")
			fmt.Println("Result:\n" + string(r))
			r, _ = json.MarshalIndent(tc.expectedFinalRules, "", "  ")
			fmt.Println("ExpectedResult:\n" + string(r))
			ret := reflect.DeepEqual(finalRules, tc.expectedFinalRules)
			assert.Equal(t, ret, true)
		})
	}
}
