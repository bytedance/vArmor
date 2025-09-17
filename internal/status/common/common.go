// Package common provides common functions for the status service
package common

import (
	"context"
	"reflect"

	v1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

func UpdateVarmorPolicyStatus(
	i varmorinterface.CrdV1beta1Interface,
	vp *varmor.VarmorPolicy,
	profileName string,
	ready bool,
	phase varmor.VarmorPolicyPhase,
	condType varmor.VarmorPolicyConditionType,
	status v1.ConditionStatus,
	reason, message string) error {

	// Prepare for condition
	condition := varmor.VarmorPolicyCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}

	regain := false
	update := func() (err error) {
		if regain {
			vp, err = i.VarmorPolicies(vp.Namespace).Get(context.Background(), vp.Name, metav1.GetOptions{})
			if err != nil {
				if k8errors.IsNotFound(err) {
					return nil
				}
				return err
			}
		}

		// Update condition
		exist := false
		switch condition.Type {
		case varmor.VarmorPolicyCreated:
			for i, c := range vp.Status.Conditions {
				if c.Type == varmor.VarmorPolicyCreated {
					condition.DeepCopyInto(&vp.Status.Conditions[i])
					exist = true
					break
				}
			}
		case varmor.VarmorPolicyUpdated:
			for i, c := range vp.Status.Conditions {
				if c.Type == varmor.VarmorPolicyUpdated {
					condition.DeepCopyInto(&vp.Status.Conditions[i])
					exist = true
					break
				}
			}
		case varmor.VarmorPolicyReady:
			for i, c := range vp.Status.Conditions {
				if c.Type == varmor.VarmorPolicyReady {
					condition.DeepCopyInto(&vp.Status.Conditions[i])
					exist = true
					break
				}
			}
		}
		if !exist {
			vp.Status.Conditions = append(vp.Status.Conditions, condition)
		}

		// Update profile name
		if profileName != "" {
			vp.Status.ProfileName = profileName
		}

		// Update status
		vp.Status.Ready = ready
		if phase != varmor.VarmorPolicyUnchanged {
			vp.Status.Phase = phase
		}

		_, err = i.VarmorPolicies(vp.Namespace).UpdateStatus(context.Background(), vp, metav1.UpdateOptions{})
		if err != nil {
			regain = true
		}
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, update)
}

func UpdateVarmorClusterPolicyStatus(
	i varmorinterface.CrdV1beta1Interface,
	vcp *varmor.VarmorClusterPolicy,
	profileName string,
	ready bool,
	phase varmor.VarmorPolicyPhase,
	condType varmor.VarmorPolicyConditionType,
	status v1.ConditionStatus,
	reason, message string) error {

	// Prepare for condition
	condition := varmor.VarmorPolicyCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}

	regain := false
	update := func() (err error) {
		if regain {
			vcp, err = i.VarmorClusterPolicies().Get(context.Background(), vcp.Name, metav1.GetOptions{})
			if err != nil {
				if k8errors.IsNotFound(err) {
					return nil
				}
				return err
			}
		}

		// Update condition
		exist := false
		switch condition.Type {
		case varmor.VarmorPolicyCreated:
			for i, c := range vcp.Status.Conditions {
				if c.Type == varmor.VarmorPolicyCreated {
					condition.DeepCopyInto(&vcp.Status.Conditions[i])
					exist = true
					break
				}
			}
		case varmor.VarmorPolicyUpdated:
			for i, c := range vcp.Status.Conditions {
				if c.Type == varmor.VarmorPolicyUpdated {
					condition.DeepCopyInto(&vcp.Status.Conditions[i])
					exist = true
					break
				}
			}
		case varmor.VarmorPolicyReady:
			for i, c := range vcp.Status.Conditions {
				if c.Type == varmor.VarmorPolicyReady {
					condition.DeepCopyInto(&vcp.Status.Conditions[i])
					exist = true
					break
				}
			}
		}
		if !exist {
			vcp.Status.Conditions = append(vcp.Status.Conditions, condition)
		}

		// Update profile name
		if profileName != "" {
			vcp.Status.ProfileName = profileName
		}

		// Update status
		vcp.Status.Ready = ready
		if phase != varmor.VarmorPolicyUnchanged {
			vcp.Status.Phase = phase
		}

		_, err = i.VarmorClusterPolicies().UpdateStatus(context.Background(), vcp, metav1.UpdateOptions{})
		if err != nil {
			regain = true
		}
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, update)
}

func newArmorProfileCondition(
	nodeName string,
	condType varmor.ArmorProfileConditionType,
	status v1.ConditionStatus,
	reason, message string) *varmor.ArmorProfileCondition {

	return &varmor.ArmorProfileCondition{
		NodeName:           nodeName,
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

func UpdateArmorProfileStatus(
	i varmorinterface.CrdV1beta1Interface,
	ap *varmor.ArmorProfile,
	policyStatus *varmortypes.PolicyStatus,
	desiredNumber int32) error {

	var conditions []varmor.ArmorProfileCondition
	for nodeName, message := range policyStatus.NodeMessages {
		if message != string(varmor.ArmorProfileReady) {
			c := newArmorProfileCondition(nodeName, varmor.ArmorProfileReady, v1.ConditionFalse, "", message)
			conditions = append(conditions, *c)
		}
	}

	regain := false
	update := func() (err error) {
		if regain {
			ap, err = i.ArmorProfiles(ap.Namespace).Get(context.Background(), ap.Name, metav1.GetOptions{})
			if err != nil {
				if k8errors.IsNotFound(err) {
					return nil
				}
				return err
			}
		}
		// Nothing needs to be updated.
		if reflect.DeepEqual(ap.Status.Conditions, conditions) &&
			ap.Status.CurrentNumberLoaded == policyStatus.SuccessedNumber &&
			ap.Status.DesiredNumberLoaded == desiredNumber {
			return nil
		}
		ap.Status.DesiredNumberLoaded = desiredNumber
		ap.Status.CurrentNumberLoaded = policyStatus.SuccessedNumber
		if len(conditions) > 0 {
			ap.Status.Conditions = conditions
		} else {
			ap.Status.Conditions = nil
		}
		_, err = i.ArmorProfiles(ap.Namespace).UpdateStatus(context.Background(), ap, metav1.UpdateOptions{})
		if err != nil {
			regain = true
		}
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, update)
}

func newArmorProfileModelCondition(
	nodeName string,
	condType varmor.ArmorProfileModelConditionType,
	status v1.ConditionStatus,
	reason, message string) *varmor.ArmorProfileModelCondition {

	return &varmor.ArmorProfileModelCondition{
		NodeName:           nodeName,
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

func UpdateArmorProfileModelStatus(
	i varmorinterface.CrdV1beta1Interface,
	apm *varmor.ArmorProfileModel,
	modelingStatus *varmortypes.ModelingStatus,
	desiredNumber int32,
	complete bool) error {

	var conditions []varmor.ArmorProfileModelCondition
	for nodeName, message := range modelingStatus.NodeMessages {
		if message != string(varmor.ArmorProfileModelReady) {
			c := newArmorProfileModelCondition(nodeName, varmor.ArmorProfileModelReady, v1.ConditionFalse, "", message)
			conditions = append(conditions, *c)
		}
	}

	if reflect.DeepEqual(apm.Status.Conditions, conditions) &&
		apm.Status.CompletedNumber == modelingStatus.CompletedNumber {
		return nil
	}

	apm.Status.DesiredNumber = desiredNumber
	apm.Status.CompletedNumber = modelingStatus.CompletedNumber
	if complete {
		apm.Status.Ready = true
	}
	if len(conditions) > 0 {
		apm.Status.Conditions = conditions
	} else {
		apm.Status.Conditions = nil
	}

	_, err := i.ArmorProfileModels(apm.Namespace).UpdateStatus(context.Background(), apm, metav1.UpdateOptions{})

	return err
}

func MergeAppArmorResult(apm *varmor.ArmorProfileModel, appArmor *varmor.AppArmor) {
	if appArmor == nil {
		return
	}

	if apm.Data.DynamicResult.AppArmor == nil {
		apm.Data.DynamicResult.AppArmor = &varmor.AppArmor{}
	}

	for _, newProfile := range appArmor.Profiles {
		if !varmorutils.InStringArray(newProfile, apm.Data.DynamicResult.AppArmor.Profiles) {
			apm.Data.DynamicResult.AppArmor.Profiles = append(apm.Data.DynamicResult.AppArmor.Profiles, newProfile)
		}
	}

	for _, newExe := range appArmor.Executions {
		if !varmorutils.InStringArray(newExe, apm.Data.DynamicResult.AppArmor.Executions) {
			apm.Data.DynamicResult.AppArmor.Executions = append(apm.Data.DynamicResult.AppArmor.Executions, newExe)
		}
	}

	for _, newFile := range appArmor.Files {
		findFile := false
		for i, file := range apm.Data.DynamicResult.AppArmor.Files {
			if newFile.Path == file.Path {
				findFile = true

				for _, newPerm := range newFile.Permissions {
					if !varmorutils.InStringArray(newPerm, file.Permissions) {
						apm.Data.DynamicResult.AppArmor.Files[i].Permissions = append(apm.Data.DynamicResult.AppArmor.Files[i].Permissions, newPerm)
					}
				}

				// disable owner priority
				apm.Data.DynamicResult.AppArmor.Files[i].Owner = file.Owner && newFile.Owner

				// save oldPath if not exist
				if file.OldPath == "" && newFile.OldPath != "" {
					apm.Data.DynamicResult.AppArmor.Files[i].OldPath = newFile.OldPath
				}
				break
			}
		}
		if !findFile {
			apm.Data.DynamicResult.AppArmor.Files = append(apm.Data.DynamicResult.AppArmor.Files, newFile)
		}
	}

	for _, newCap := range appArmor.Capabilities {
		if !varmorutils.InStringArray(newCap, apm.Data.DynamicResult.AppArmor.Capabilities) {
			apm.Data.DynamicResult.AppArmor.Capabilities = append(apm.Data.DynamicResult.AppArmor.Capabilities, newCap)
		}
	}

	if appArmor.Network != nil {
		for _, newSocket := range appArmor.Network.Sockets {
			find := false
			if apm.Data.DynamicResult.AppArmor.Network != nil {
				for _, socket := range apm.Data.DynamicResult.AppArmor.Network.Sockets {
					if reflect.DeepEqual(newSocket, socket) {
						find = true
						break
					}
				}
			}

			if !find {
				if apm.Data.DynamicResult.AppArmor.Network == nil {
					apm.Data.DynamicResult.AppArmor.Network = &varmor.Network{}
				}
				apm.Data.DynamicResult.AppArmor.Network.Sockets = append(apm.Data.DynamicResult.AppArmor.Network.Sockets, newSocket)
			}
		}
	}

	for _, newPtrace := range appArmor.Ptraces {
		find := false
		for i, ptrace := range apm.Data.DynamicResult.AppArmor.Ptraces {
			if newPtrace.Peer == ptrace.Peer {
				find = true
				for _, newPerm := range newPtrace.Permissions {
					if !varmorutils.InStringArray(newPerm, ptrace.Permissions) {
						apm.Data.DynamicResult.AppArmor.Ptraces[i].Permissions = append(apm.Data.DynamicResult.AppArmor.Ptraces[i].Permissions, newPerm)
					}
				}
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Ptraces = append(apm.Data.DynamicResult.AppArmor.Ptraces, newPtrace)
		}
	}

	for _, newSignal := range appArmor.Signals {
		find := false
		for i, signal := range apm.Data.DynamicResult.AppArmor.Signals {
			if newSignal.Peer == signal.Peer {
				find = true

				for _, newPerm := range newSignal.Permissions {
					if !varmorutils.InStringArray(newPerm, signal.Permissions) {
						apm.Data.DynamicResult.AppArmor.Signals[i].Permissions = append(apm.Data.DynamicResult.AppArmor.Signals[i].Permissions, newPerm)
					}
				}

				for _, newSig := range newSignal.Signals {
					if !varmorutils.InStringArray(newSig, signal.Signals) {
						apm.Data.DynamicResult.AppArmor.Signals[i].Signals = append(apm.Data.DynamicResult.AppArmor.Signals[i].Signals, newSig)
					}
				}

				break
			}
		}
		if !find {
			apm.Data.DynamicResult.AppArmor.Signals = append(apm.Data.DynamicResult.AppArmor.Signals, newSignal)
		}
	}

	for _, newUnhandled := range appArmor.Unhandled {
		if !varmorutils.InStringArray(newUnhandled, apm.Data.DynamicResult.AppArmor.Unhandled) {
			apm.Data.DynamicResult.AppArmor.Unhandled = append(apm.Data.DynamicResult.AppArmor.Unhandled, newUnhandled)
		}
	}
}

func MergeBpfResult(apm *varmor.ArmorProfileModel, bpf *varmor.BPF) {
	if bpf == nil {
		return
	}

	if apm.Data.DynamicResult.Bpf == nil {
		apm.Data.DynamicResult.Bpf = &varmor.BPF{}
	}

	for _, newExec := range bpf.Executions {
		if !varmorutils.InStringArray(newExec, apm.Data.DynamicResult.Bpf.Executions) {
			apm.Data.DynamicResult.Bpf.Executions = append(apm.Data.DynamicResult.Bpf.Executions, newExec)
		}
	}

	for _, newFile := range bpf.Files {
		find := false
		for i, file := range apm.Data.DynamicResult.Bpf.Files {
			if newFile.Path == file.Path {
				find = true

				for _, newPerm := range newFile.Permissions {
					if !varmorutils.InStringArray(newPerm, file.Permissions) {
						apm.Data.DynamicResult.Bpf.Files[i].Permissions = append(apm.Data.DynamicResult.Bpf.Files[i].Permissions, newPerm)
					}
				}

				if file.OldPath == "" && newFile.OldPath != "" {
					apm.Data.DynamicResult.Bpf.Files[i].OldPath = newFile.OldPath
				}
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.Bpf.Files = append(apm.Data.DynamicResult.Bpf.Files, newFile)
		}
	}

	for _, newCap := range bpf.Capabilities {
		if !varmorutils.InStringArray(newCap, apm.Data.DynamicResult.Bpf.Capabilities) {
			apm.Data.DynamicResult.Bpf.Capabilities = append(apm.Data.DynamicResult.Bpf.Capabilities, newCap)
		}
	}

	if bpf.Network != nil {
		for _, newSocket := range bpf.Network.Sockets {
			find := false
			if apm.Data.DynamicResult.Bpf.Network != nil {
				for _, socket := range apm.Data.DynamicResult.Bpf.Network.Sockets {
					if reflect.DeepEqual(newSocket, socket) {
						find = true
						break
					}
				}
			}
			if !find {
				if apm.Data.DynamicResult.Bpf.Network == nil {
					apm.Data.DynamicResult.Bpf.Network = &varmor.Network{}
				}
				apm.Data.DynamicResult.Bpf.Network.Sockets = append(apm.Data.DynamicResult.Bpf.Network.Sockets, newSocket)
			}
		}

		for _, newEgress := range bpf.Network.Egresses {
			find := false
			if apm.Data.DynamicResult.Bpf.Network != nil {
				for i, egress := range apm.Data.DynamicResult.Bpf.Network.Egresses {
					if egress.IP == newEgress.IP {
						find = true
						for _, newPort := range newEgress.Ports {
							if !varmorutils.InUint16Array(newPort, egress.Ports) {
								apm.Data.DynamicResult.Bpf.Network.Egresses[i].Ports = append(apm.Data.DynamicResult.Bpf.Network.Egresses[i].Ports, newPort)
							}
						}
					}
				}
				if !find {
					if apm.Data.DynamicResult.Bpf.Network == nil {
						apm.Data.DynamicResult.Bpf.Network = &varmor.Network{}
					}
					apm.Data.DynamicResult.Bpf.Network.Egresses = append(apm.Data.DynamicResult.Bpf.Network.Egresses, newEgress)
				}
			}
		}
	}

	for _, newPtrace := range bpf.Ptraces {
		find := false
		for i, ptrace := range apm.Data.DynamicResult.Bpf.Ptraces {
			if newPtrace.External == ptrace.External {
				find = true
				for _, newPerm := range newPtrace.Permissions {
					if !varmorutils.InStringArray(newPerm, ptrace.Permissions) {
						apm.Data.DynamicResult.Bpf.Ptraces[i].Permissions = append(apm.Data.DynamicResult.Bpf.Ptraces[i].Permissions, newPerm)
					}
				}
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.Bpf.Ptraces = append(apm.Data.DynamicResult.Bpf.Ptraces, newPtrace)
		}
	}

	for _, newMount := range bpf.Mounts {
		find := false
		for i, mount := range apm.Data.DynamicResult.Bpf.Mounts {
			if newMount.Path == mount.Path && newMount.Type == mount.Type {
				find = true
				for _, newFlag := range newMount.Flags {
					if !varmorutils.InStringArray(newFlag, mount.Flags) {
						apm.Data.DynamicResult.Bpf.Mounts[i].Flags = append(apm.Data.DynamicResult.Bpf.Mounts[i].Flags, newFlag)
					}
				}
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.Bpf.Mounts = append(apm.Data.DynamicResult.Bpf.Mounts, newMount)
		}
	}
}

func MergeSeccompResult(apm *varmor.ArmorProfileModel, seccomp *varmor.Seccomp) {
	if seccomp == nil {
		return
	}

	if apm.Data.DynamicResult.Seccomp == nil {
		apm.Data.DynamicResult.Seccomp = &varmor.Seccomp{}
	}

	for _, newSyscall := range seccomp.Syscalls {
		find := false
		for _, syscall := range apm.Data.DynamicResult.Seccomp.Syscalls {
			if newSyscall == syscall {
				find = true
				break
			}
		}
		if !find {
			apm.Data.DynamicResult.Seccomp.Syscalls = append(apm.Data.DynamicResult.Seccomp.Syscalls, newSyscall)
		}
	}
}
