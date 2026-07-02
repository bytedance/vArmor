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

package agent

import (
	"testing"

	"gotest.tools/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
)

func TestPolicyIdentityFromArmorProfile(t *testing.T) {
	testCases := []struct {
		name     string
		ap       *varmor.ArmorProfile
		expected varmorauditor.PolicyIdentity
	}{
		{
			name: "namespaced VarmorPolicy keeps its namespace",
			ap: &varmor.ArmorProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "varmor-default-demo",
					Namespace: "default",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "VarmorPolicy", Name: "demo"},
					},
				},
			},
			expected: varmorauditor.PolicyIdentity{
				Kind:      "VarmorPolicy",
				Name:      "demo",
				Namespace: "default",
			},
		},
		{
			name: "cluster VarmorClusterPolicy drops the install namespace",
			ap: &varmor.ArmorProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "varmor-cluster-varmor-demo",
					Namespace: "varmor",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "VarmorClusterPolicy", Name: "demo"},
					},
				},
			},
			expected: varmorauditor.PolicyIdentity{
				Kind:      "VarmorClusterPolicy",
				Name:      "demo",
				Namespace: "",
			},
		},
		{
			name: "missing OwnerReference yields an empty identity",
			ap: &varmor.ArmorProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "varmor-default-orphan",
					Namespace: "default",
				},
			},
			expected: varmorauditor.PolicyIdentity{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := policyIdentityFromArmorProfile(tc.ap)
			assert.Equal(t, got.Kind, tc.expected.Kind)
			assert.Equal(t, got.Name, tc.expected.Name)
			assert.Equal(t, got.Namespace, tc.expected.Namespace)
		})
	}
}
