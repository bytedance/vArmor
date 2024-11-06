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

package profile

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	apparmorprofile "github.com/bytedance/vArmor/internal/profile/apparmor"
	bpfprofile "github.com/bytedance/vArmor/internal/profile/bpf"
	seccompprofile "github.com/bytedance/vArmor/internal/profile/seccomp"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

// profileNameTemplate is the name of ArmorProfile object in k8s and AppArmor profile in host machine.
//
//	For namespace-scope profile, its format is "varmor-{VarmorProfile Namespace}-{VarmorProfile Name}"
//	For cluster-scope profile, its format is "varmor-cluster-{vArmor Namespace}-{VarmorClusterProfile Name}"
const (
	ClusterProfileNameTemplate = "varmor-cluster-%s-%s"
	ProfileNameTemplate        = "varmor-%s-%s"
)

func GenerateArmorProfileName(ns string, name string, clusterScope bool) string {
	profileName := ""

	if clusterScope {
		profileName = fmt.Sprintf(ClusterProfileNameTemplate, ns, name)
	} else {
		profileName = fmt.Sprintf(ProfileNameTemplate, ns, name)
	}

	return strings.ToLower(profileName)
}

func GenerateProfile(policy varmor.Policy, name string, namespace string, varmorInterface varmorinterface.CrdV1beta1Interface, complete bool) (*varmor.Profile, error) {
	var err error

	profile := varmor.Profile{
		Name:     name,
		Enforcer: policy.Enforcer,
		Mode:     "enforce",
	}

	e := varmortypes.GetEnforcerType(policy.Enforcer)

	switch policy.Mode {
	case varmortypes.AlwaysAllowMode:
		if e == varmortypes.Unknown {
			return nil, fmt.Errorf("unknown enforcer")
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			profile.Content = apparmorprofile.GenerateAlwaysAllowProfile(name)
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			var bpfContent varmor.BpfContent
			profile.BpfContent = &bpfContent
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			profile.SeccompContent = seccompprofile.GenerateAlwaysAllowProfile()
		}

	case varmortypes.RuntimeDefaultMode:
		if e == varmortypes.Unknown {
			return nil, fmt.Errorf("unknown enforcer")
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			profile.Content = apparmorprofile.GenerateRuntimeDefaultProfile(name)
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			var bpfContent varmor.BpfContent
			err = bpfprofile.GenerateRuntimeDefaultProfile(&bpfContent, bpfenforcer.EnforceMode)
			if err != nil {
				return nil, err
			}
			profile.BpfContent = &bpfContent
		}
		// Seccomp
		// We need to mock an AlwaysAllow profile when switching a policy to RuntimeDefault mode
		// in case the containers in existing Pods can normally restart, because we can't update
		// the Seccomp settings of the existing Pods.
		if (e & varmortypes.Seccomp) != 0 {
			profile.SeccompContent = seccompprofile.GenerateAlwaysAllowProfile()
		}

	case varmortypes.EnhanceProtectMode:
		if e == varmortypes.Unknown {
			return nil, fmt.Errorf("unknown enforcer")
		}

		if policy.EnhanceProtect == nil {
			return nil, fmt.Errorf("the EnhanceProtect field is nil")
		}

		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			profile.Content = apparmorprofile.GenerateEnhanceProtectProfile(policy.EnhanceProtect, name)
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			var bpfContent varmor.BpfContent
			err = bpfprofile.GenerateEnhanceProtectProfile(policy.EnhanceProtect, &bpfContent)
			if err != nil {
				return nil, err
			}
			profile.BpfContent = &bpfContent
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			profile.SeccompContent, err = seccompprofile.GenerateEnhanceProtectProfile(policy.EnhanceProtect, name)
			if err != nil {
				return nil, err
			}
		}

	case varmortypes.BehaviorModelingMode:
		if e == varmortypes.Unknown {
			return nil, fmt.Errorf("unknown enforcer")
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			return nil, fmt.Errorf("fatal error: not supported by the enforcer")
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if complete {
				// Create profile based on the AlwaysAllow template after the behvior modeling was completed.
				profile.Content = apparmorprofile.GenerateAlwaysAllowProfile(name)
			} else {
				profile.Mode = "complain"
				profile.Content = apparmorprofile.GenerateBehaviorModelingProfile(name)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			profile.Mode = "complain"
			profile.SeccompContent = seccompprofile.GenerateBehaviorModelingProfile()
		}

	case varmortypes.DefenseInDepthMode:
		if e == varmortypes.Unknown {
			return nil, fmt.Errorf("unknown enforcer")
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			return nil, fmt.Errorf("fatal error: not supported by the enforcer")
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			apm, err := varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err == nil && apm.Data.Profile.Content != "" {
				profile.Content = apm.Data.Profile.Content
			} else {
				return nil, fmt.Errorf("fatal error: no existing AppArmor model found")
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			apm, err := varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err == nil && apm.Data.Profile.SeccompContent != "" {
				profile.SeccompContent = apm.Data.Profile.SeccompContent
			} else {
				return nil, fmt.Errorf("fatal error: no existing Seccomp model found")
			}
		}

	default:
		return nil, fmt.Errorf("unknown mode")
	}

	return &profile, nil
}

func NewArmorProfile(obj interface{}, varmorInterface varmorinterface.CrdV1beta1Interface, clusterScope bool) (*varmor.ArmorProfile, error) {
	ap := varmor.ArmorProfile{}
	controller := true

	if clusterScope {
		vcp := obj.(*varmor.VarmorClusterPolicy)

		ap.Name = GenerateArmorProfileName(varmorconfig.Namespace, vcp.Name, clusterScope)
		ap.Namespace = varmorconfig.Namespace
		ap.Labels = vcp.ObjectMeta.DeepCopy().Labels
		ap.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "crd.varmor.org/v1beta1",
				Kind:       "VarmorClusterPolicy",
				Name:       vcp.Name,
				UID:        vcp.UID,
				Controller: &controller,
			},
		}
		ap.Finalizers = []string{"varmor.org/ap-protection"}

		profile, err := GenerateProfile(vcp.Spec.Policy, ap.Name, ap.Namespace, varmorInterface, false)
		if err != nil {
			return nil, err
		}
		ap.Spec.Profile = *profile
		ap.Spec.Target = *vcp.Spec.Target.DeepCopy()
		ap.Spec.UpdateExistingWorkloads = vcp.Spec.UpdateExistingWorkloads

		if vcp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
			if vcp.Spec.Policy.ModelingOptions.Duration == 0 {
				return &ap, fmt.Errorf("invalid parameter: .Spec.Policy.ModelingOptions.Duration == 0")
			}
			ap.Spec.BehaviorModeling.Enable = true
			ap.Spec.BehaviorModeling.Duration = vcp.Spec.Policy.ModelingOptions.Duration
		}

	} else {
		vp := obj.(*varmor.VarmorPolicy)

		ap.Name = GenerateArmorProfileName(vp.Namespace, vp.Name, clusterScope)
		ap.Namespace = vp.Namespace
		ap.Labels = vp.ObjectMeta.DeepCopy().Labels
		ap.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "crd.varmor.org/v1beta1",
				Kind:       "VarmorPolicy",
				Name:       vp.Name,
				UID:        vp.UID,
				Controller: &controller,
			},
		}
		ap.Finalizers = []string{"varmor.org/ap-protection"}

		profile, err := GenerateProfile(vp.Spec.Policy, ap.Name, ap.Namespace, varmorInterface, false)
		if err != nil {
			return nil, err
		}
		ap.Spec.Profile = *profile
		ap.Spec.Target = *vp.Spec.Target.DeepCopy()
		ap.Spec.UpdateExistingWorkloads = vp.Spec.UpdateExistingWorkloads

		if vp.Spec.Policy.Mode == varmortypes.BehaviorModelingMode {
			if vp.Spec.Policy.ModelingOptions.Duration == 0 {
				return &ap, fmt.Errorf("invalid parameter: .Spec.Policy.ModelingOptions.Duration == 0")
			}
			ap.Spec.BehaviorModeling.Enable = true
			ap.Spec.BehaviorModeling.Duration = vp.Spec.Policy.ModelingOptions.Duration
		}
	}

	return &ap, nil
}
