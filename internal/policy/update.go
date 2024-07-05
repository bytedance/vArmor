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

package policy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"

	appsV1 "k8s.io/api/apps/v1"
	coreV1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

func modifyDeploymentAnnotationsAndEnv(enforcer string, mode varmor.VarmorPolicyMode, target varmor.Target, deploy *appsV1.Deployment, profileName string, bpfExclusiveMode bool) {
	e := varmortypes.GetEnforcerType(enforcer)

	// Clean up first
	for key, value := range deploy.Spec.Template.Annotations {
		// BPF
		if (e & varmortypes.BPF) != 0 {
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
				parts := strings.Split(key, "/")
				if len(parts) != 2 {
					continue
				}
				// Clean up the seccomp settings from the SecurityContext
				for index, container := range deploy.Spec.Template.Spec.Containers {
					if container.Name == parts[1] {
						deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
					}
				}
			}
		}
	}

	// Add the modification time to annotation
	if deploy.Spec.Template.Annotations == nil {
		deploy.Spec.Template.Annotations = make(map[string]string)
	}

	if profileName == "" {
		return
	}

	// Setting new annotations and seccomp context
	for index, container := range deploy.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
				if bpfExclusiveMode {
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					deploy.Spec.Template.Annotations[key] = "unconfined"
				}
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
				(deploy.Spec.Template.Spec.SecurityContext != nil && deploy.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && deploy.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
				continue
			}

			deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if deploy.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			if mode == varmortypes.RuntimeDefaultMode {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type: "RuntimeDefault",
				}
			} else {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: &profileName,
				}
			}
		}
	}
}

func modifyStatefulSetAnnotationsAndEnv(enforcer string, mode varmor.VarmorPolicyMode, target varmor.Target, stateful *appsV1.StatefulSet, profileName string, bpfExclusiveMode bool) {
	e := varmortypes.GetEnforcerType(enforcer)

	// Clean up first
	for key, value := range stateful.Spec.Template.Annotations {
		// BPF
		if (e & varmortypes.BPF) != 0 {
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
				parts := strings.Split(key, "/")
				if len(parts) != 2 {
					continue
				}
				// Clean up the seccomp settings from the SecurityContext
				for index, container := range stateful.Spec.Template.Spec.Containers {
					if container.Name == parts[1] {
						stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
					}
				}
			}
		}
	}

	// Add the modification time to annotation
	if stateful.Spec.Template.Annotations == nil {
		stateful.Spec.Template.Annotations = make(map[string]string)
	}

	if profileName == "" {
		return
	}

	// Setting new annotations and seccomp context
	for index, container := range stateful.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
				if bpfExclusiveMode {
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					stateful.Spec.Template.Annotations[key] = "unconfined"
				}
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
				(stateful.Spec.Template.Spec.SecurityContext != nil && stateful.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && stateful.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
				continue
			}

			stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if stateful.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			if mode == varmortypes.RuntimeDefaultMode {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type: "RuntimeDefault",
				}
			} else {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: &profileName,
				}
			}
		}
	}
}

func modifyDaemonSetAnnotationsAndEnv(enforcer string, mode varmor.VarmorPolicyMode, target varmor.Target, daemon *appsV1.DaemonSet, profileName string, bpfExclusiveMode bool) {
	e := varmortypes.GetEnforcerType(enforcer)

	// Clean up first
	for key, value := range daemon.Spec.Template.Annotations {
		// BPF
		if (e & varmortypes.BPF) != 0 {
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
				parts := strings.Split(key, "/")
				if len(parts) != 2 {
					continue
				}
				// Clean up the seccomp settings from the SecurityContext
				for index, container := range daemon.Spec.Template.Spec.Containers {
					if container.Name == parts[1] {
						daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
					}
				}
			}
		}
	}

	// Add the modification time to annotation
	if daemon.Spec.Template.Annotations == nil {
		daemon.Spec.Template.Annotations = make(map[string]string)
	}

	if profileName == "" {
		return
	}

	// Setting new annotations and seccomp context
	for index, container := range daemon.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !varmorutils.InStringArray(container.Name, target.Containers) {
			continue
		}

		// BPF
		if (e & varmortypes.BPF) != 0 {
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
				if bpfExclusiveMode {
					key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
					daemon.Spec.Template.Annotations[key] = "unconfined"
				}
			}
		}
		// AppArmor
		if (e & varmortypes.AppArmor) != 0 {
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; !ok || value != "unconfined" {
				daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			}
		}
		// Seccomp
		if (e & varmortypes.Seccomp) != 0 {
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil && container.SecurityContext.SeccompProfile.Type == "Unconfined") ||
				(daemon.Spec.Template.Spec.SecurityContext != nil && daemon.Spec.Template.Spec.SecurityContext.SeccompProfile != nil && daemon.Spec.Template.Spec.SecurityContext.SeccompProfile.Type == "Unconfined") {
				continue
			}

			daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if daemon.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			if mode == varmortypes.RuntimeDefaultMode {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type: "RuntimeDefault",
				}
			} else {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: &profileName,
				}
			}
		}
	}
}

func updateWorkloadAnnotationsAndEnv(
	appsInterface appsv1.AppsV1Interface,
	namespace string,
	enforcer string,
	mode varmor.VarmorPolicyMode,
	target varmor.Target,
	profileName string,
	bpfExclusiveMode bool,
	logger logr.Logger) {

	matchFields := make(map[string]string)
	if target.Name != "" {
		matchFields["metadata.name"] = target.Name
	}

	// The target must have the webhook selector label.
	for key, value := range varmorconfig.WebhookSelectorLabel {
		if target.Selector == nil {
			target.Selector = &metav1.LabelSelector{}
		}
		if target.Selector.MatchLabels == nil {
			target.Selector.MatchLabels = make(map[string]string)
		}
		target.Selector.MatchLabels[key] = value
	}

	selector, err := metav1.LabelSelectorAsSelector(target.Selector)
	if err != nil {
		logger.Error(err, "LabelSelectorAsSelector()")
		return
	}

	listOpt := metav1.ListOptions{
		LabelSelector:   selector.String(),
		FieldSelector:   fields.Set(matchFields).String(),
		ResourceVersion: "0",
	}

	switch target.Kind {
	case "Deployment":
		deploys, err := appsInterface.Deployments(namespace).List(context.Background(), listOpt)
		if err != nil {
			logger.Error(err, "Deployments().List()")
			return
		}

		for _, item := range deploys.Items {
			needRegain := false
			deploy := &item

			updateDeployment := func() error {
				if needRegain {
					deploy, err = appsInterface.Deployments(deploy.Namespace).Get(context.Background(), deploy.Name, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					needRegain = false
				}

				deployOld := deploy.DeepCopy()
				modifyDeploymentAnnotationsAndEnv(enforcer, mode, target, deploy, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(deployOld, deploy) {
					return nil
				}
				deploy.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)
				deploy, err = appsInterface.Deployments(deploy.Namespace).Update(context.Background(), deploy, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "Deployments", "namespace", deploy.Namespace, "name", deploy.Name)
				} else {
					needRegain = true
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateDeployment)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		}

	case "StatefulSet":
		statefuls, err := appsInterface.StatefulSets(namespace).List(context.Background(), listOpt)
		if err != nil {
			logger.Error(err, "StatefulSets().List()")
			return
		}

		for _, item := range statefuls.Items {
			needRegain := false
			stateful := &item

			updateStateful := func() error {
				if needRegain {
					stateful, err = appsInterface.StatefulSets(stateful.Namespace).Get(context.Background(), stateful.Name, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					needRegain = false
				}

				statefulOld := stateful.DeepCopy()
				modifyStatefulSetAnnotationsAndEnv(enforcer, mode, target, stateful, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(statefulOld, stateful) {
					return nil
				}
				stateful.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)
				stateful, err = appsInterface.StatefulSets(stateful.Namespace).Update(context.Background(), stateful, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "StatefulSets", "namespace", stateful.Namespace, "name", stateful.Name)
				} else {
					needRegain = true
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateStateful)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		}

	case "DaemonSet":
		daemons, err := appsInterface.DaemonSets(namespace).List(context.Background(), listOpt)
		if err != nil {
			logger.Error(err, "DaemonSets().List()")
			return
		}

		if len(daemons.Items) == 0 {
			return
		}

		for _, item := range daemons.Items {
			needRegain := false
			daemon := &item

			updateDaemon := func() error {
				if needRegain {
					daemon, err = appsInterface.DaemonSets(daemon.Namespace).Get(context.Background(), daemon.Name, metav1.GetOptions{})
					if err != nil {
						if k8errors.IsNotFound(err) {
							return nil
						}
						return err
					}
					needRegain = false
				}

				daemonOld := daemon.DeepCopy()
				modifyDaemonSetAnnotationsAndEnv(enforcer, mode, target, daemon, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(daemonOld, &daemon) {
					return nil
				}
				daemon.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)
				daemon, err = appsInterface.DaemonSets(daemon.Namespace).Update(context.Background(), daemon, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "DaemonSets", "namespace", daemon.Namespace, "name", daemon.Name)
				} else {
					needRegain = true
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateDaemon)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		}
	}
}

func forceSetOwnerReference(ap *varmor.ArmorProfile, obj interface{}, clusterScope bool) {
	controller := true
	if clusterScope {
		vcp := obj.(*varmor.VarmorClusterPolicy)
		ap.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "crd.varmor.org/v1beta1",
				Kind:       "VarmorClusterPolicy",
				Name:       vcp.Name,
				UID:        vcp.UID,
				Controller: &controller,
			},
		}
	} else {
		vp := obj.(*varmor.VarmorPolicy)
		ap.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "crd.varmor.org/v1beta1",
				Kind:       "VarmorPolicy",
				Name:       vp.Name,
				UID:        vp.UID,
				Controller: &controller,
			},
		}
	}
}

func resetArmorProfileModelStatus(varmorInterface varmorinterface.CrdV1beta1Interface, namespace, name string) error {
	return retry.RetryOnConflict(retry.DefaultRetry,
		func() error {
			apm, err := varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				if k8errors.IsNotFound(err) {
					return nil
				}
				return err
			}
			apm.Status.CompletedNumber = 0
			apm.Status.Conditions = nil
			apm.Status.Ready = false
			_, err = varmorInterface.ArmorProfileModels(namespace).UpdateStatus(context.Background(), apm, metav1.UpdateOptions{})
			return err
		})
}
