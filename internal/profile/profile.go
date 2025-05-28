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
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorapm "github.com/bytedance/vArmor/internal/apm"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	apparmorprofile "github.com/bytedance/vArmor/internal/profile/apparmor"
	bpfprofile "github.com/bytedance/vArmor/internal/profile/bpf"
	seccompprofile "github.com/bytedance/vArmor/internal/profile/seccomp"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	bpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
)

// profileNameTemplate is the name template for ArmorProfile/ArmorProfileModel objects and AppArmor/Seccomp/BPF profiles.
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

func GenerateProfile(
	kubeClient *kubernetes.Clientset,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	policy varmor.Policy,
	name string, namespace string,
	complete bool,
	enablePodServiceEgressControl bool,
	logger logr.Logger) (*varmor.Profile, *varmortypes.EgressInfo, error) {
	var err error

	var egressInfo *varmortypes.EgressInfo

	profile := varmor.Profile{
		Name:     name,
		Enforcer: policy.Enforcer,
	}

	e := varmortypes.GetEnforcerType(policy.Enforcer)

	switch policy.Mode {
	case varmor.AlwaysAllowMode:
		if e == varmortypes.Unknown {
			return nil, nil, fmt.Errorf("unknown enforcer")
		}

		profile.Mode = varmor.ProfileModeEnforce

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

	case varmor.RuntimeDefaultMode:
		if e == varmortypes.Unknown {
			return nil, nil, fmt.Errorf("unknown enforcer")
		}

		profile.Mode = varmor.ProfileModeEnforce

		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			profile.Content = apparmorprofile.GenerateRuntimeDefaultProfile(name)
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			var bpfContent varmor.BpfContent
			err = bpfprofile.GenerateRuntimeDefaultProfile(&bpfContent, bpfenforcer.EnforceMode)
			if err != nil {
				return nil, nil, err
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

	case varmor.EnhanceProtectMode:
		if e == varmortypes.Unknown {
			return nil, nil, fmt.Errorf("unknown enforcer")
		}

		if policy.EnhanceProtect == nil {
			return nil, nil, fmt.Errorf("the policy.enhanceProtect field cannot be nil")
		}

		profile.Mode = varmor.ProfileModeEnforce

		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			profile.Content = apparmorprofile.GenerateEnhanceProtectProfile(policy.EnhanceProtect, name)
		}
		// BPF
		if (e & varmortypes.BPF) != 0 {
			var bpfContent varmor.BpfContent
			egressInfo, err = bpfprofile.GenerateEnhanceProtectProfile(kubeClient, policy.EnhanceProtect, &bpfContent, enablePodServiceEgressControl)
			if err != nil {
				return nil, nil, err
			}
			profile.BpfContent = &bpfContent
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			profile.SeccompContent, err = seccompprofile.GenerateEnhanceProtectProfile(policy.EnhanceProtect, name)
			if err != nil {
				return nil, nil, err
			}
		}

	case varmor.BehaviorModelingMode:
		if e == varmortypes.Unknown {
			return nil, nil, fmt.Errorf("unknown enforcer")
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			return nil, nil, fmt.Errorf("not supported by the BPF enforcer for now")
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if complete {
				// Create profile based on the AlwaysAllow template after the behvior modeling was completed.
				profile.Mode = varmor.ProfileModeEnforce
				profile.Content = apparmorprofile.GenerateAlwaysAllowProfile(name)
			} else {
				profile.Mode = varmor.ProfileModeComplain
				profile.Content = apparmorprofile.GenerateBehaviorModelingProfile(name)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			profile.Mode = varmor.ProfileModeComplain
			profile.SeccompContent = seccompprofile.GenerateBehaviorModelingProfile()
		}

	case varmor.DefenseInDepthMode:
		if e == varmortypes.Unknown {
			return nil, nil, fmt.Errorf("unknown enforcer")
		}

		if policy.DefenseInDepth == nil {
			return nil, nil, fmt.Errorf("the policy.defenseInDepth field cannot be nil")
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			return nil, nil, fmt.Errorf("not supported by the BPF enforcer for now")
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if policy.DefenseInDepth.AppArmor == nil {
				return nil, nil, fmt.Errorf("the policy.defenseInDepth.appArmor field cannot be nil")
			}

			if policy.DefenseInDepth.AllowViolations {
				profile.Mode = varmor.ProfileModeComplain
			} else {
				profile.Mode = varmor.ProfileModeEnforce
			}

			switch policy.DefenseInDepth.AppArmor.ProfileType {
			case varmor.ProfileTypeBehaviorModel:
				apm, err := varmorapm.RetrieveArmorProfileModel(varmorInterface, namespace, name, false, logger)
				if err != nil || apm.Data.Profile.Content == "" {
					return nil, nil, fmt.Errorf("failed to retrieve the AppArmor profile from the ArmorProfileModel object (%s/%s)", namespace, name)
				}

				profile.Content = apparmorprofile.GenerateDefenseInDepthProfile(
					policy.DefenseInDepth.AppArmor.AppArmorRawRules,
					apm.Data.Profile.Content,
					name)

			case varmor.ProfileTypeCustom:
				if policy.DefenseInDepth.AppArmor.CustomProfile == "" {
					return nil, nil, fmt.Errorf("the policy.defenseInDepth.appArmor.customProfile field cannot be empty")
				}

				profile.Content = apparmorprofile.GenerateDefenseInDepthProfile(
					policy.DefenseInDepth.AppArmor.AppArmorRawRules,
					policy.DefenseInDepth.AppArmor.CustomProfile,
					name)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if policy.DefenseInDepth.Seccomp == nil {
				return nil, nil, fmt.Errorf("the policy.defenseInDepth.seccomp field cannot be nil")
			}

			if policy.DefenseInDepth.AllowViolations {
				profile.Mode = varmor.ProfileModeComplain
			} else {
				profile.Mode = varmor.ProfileModeEnforce
			}

			switch policy.DefenseInDepth.Seccomp.ProfileType {
			case varmor.ProfileTypeBehaviorModel:
				apm, err := varmorapm.RetrieveArmorProfileModel(varmorInterface, namespace, name, false, logger)
				if err != nil || apm.Data.Profile.SeccompContent == "" {
					return nil, nil, fmt.Errorf("failed to retrieve Seccomp profile from the ArmorProfileModel object (%s/%s). error: %w", namespace, name, err)
				}
				profile.SeccompContent, err = seccompprofile.GenerateDefenseInDepthProfile(policy.DefenseInDepth, apm.Data.Profile.SeccompContent)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse the Seccomp profile from the ArmorProfileModel object (%s/%s). error: %w", namespace, name, err)
				}
			case varmor.ProfileTypeCustom:
				if policy.DefenseInDepth.Seccomp.CustomProfile == "" {
					return nil, nil, fmt.Errorf("the policy.defenseInDepth.seccomp.customProfile field cannot be empty")
				}
				profile.SeccompContent, err = seccompprofile.GenerateDefenseInDepthProfile(
					policy.DefenseInDepth,
					policy.DefenseInDepth.Seccomp.CustomProfile)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse the custom Seccomp profile from the policy.defenseInDepth.seccomp.customProfile field. error: %w", err)
				}
			}
		}

	default:
		return nil, nil, fmt.Errorf("unknown mode")
	}

	return &profile, egressInfo, nil
}

func NewArmorProfile(
	kubeClient *kubernetes.Clientset,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	obj interface{},
	clusterScope bool,
	enablePodServiceEgressControl bool,
	logger logr.Logger) (*varmor.ArmorProfile, *varmortypes.EgressInfo, error) {

	var ap varmor.ArmorProfile
	var profile *varmor.Profile
	var egressInfo *varmortypes.EgressInfo
	var err error

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

		profile, egressInfo, err = GenerateProfile(kubeClient, varmorInterface, vcp.Spec.Policy, ap.Name, ap.Namespace, false, enablePodServiceEgressControl, logger)
		if err != nil {
			return nil, nil, err
		}
		ap.Spec.Profile = *profile
		ap.Spec.Target = *vcp.Spec.Target.DeepCopy()
		ap.Spec.UpdateExistingWorkloads = vcp.Spec.UpdateExistingWorkloads

		if vcp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
			if vcp.Spec.Policy.ModelingOptions.Duration == 0 {
				return nil, nil, fmt.Errorf("invalid parameter: .Spec.Policy.ModelingOptions.Duration == 0")
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

		profile, egressInfo, err = GenerateProfile(kubeClient, varmorInterface, vp.Spec.Policy, ap.Name, ap.Namespace, false, enablePodServiceEgressControl, logger)
		if err != nil {
			return nil, nil, err
		}
		ap.Spec.Profile = *profile
		ap.Spec.Target = *vp.Spec.Target.DeepCopy()
		ap.Spec.UpdateExistingWorkloads = vp.Spec.UpdateExistingWorkloads

		if vp.Spec.Policy.Mode == varmor.BehaviorModelingMode {
			if vp.Spec.Policy.ModelingOptions.Duration == 0 {
				return nil, nil, fmt.Errorf("invalid parameter: .Spec.Policy.ModelingOptions.Duration == 0")
			}
			ap.Spec.BehaviorModeling.Enable = true
			ap.Spec.BehaviorModeling.Duration = vp.Spec.Policy.ModelingOptions.Duration
		}
	}

	return &ap, egressInfo, nil
}
