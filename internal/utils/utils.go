// Copyright 2022-2023 vArmor Authors
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

package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsV1 "k8s.io/api/apps/v1"
	coreV1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
)

const (
	httpTimeout    = 3 * time.Second
	retryTimes     = 5
	serverURL      = "http://%s.%s:%d%s"
	debugServerURL = "http://%s:%d%s"
)

func httpPostWithRetry(reqBody []byte, debug bool, service string, namespace string, address string, port int, path string, retryTimes int) error {
	var url string
	if debug {
		url = fmt.Sprintf(debugServerURL, address, port, path)
	} else {
		url = fmt.Sprintf(serverURL, service, namespace, port, path)
	}

	client := &http.Client{Timeout: httpTimeout}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	var httpRsp *http.Response
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < retryTimes; i++ {
		httpRsp, err = client.Do(httpReq)
		if err == nil {
			defer httpRsp.Body.Close()
			if httpRsp.StatusCode == http.StatusOK {
				return nil
			} else {
				err = fmt.Errorf(fmt.Sprintf("http error code %d", httpRsp.StatusCode))
			}
		}
		r := rand.Intn(60) + 20
		time.Sleep(time.Duration(r) * time.Millisecond)
	}

	return err
}

func httpPostAndGetResponseWithRetry(reqBody []byte, debug bool, service string, namespace string, address string, port int, path string, retryTimes int) ([]byte, error) {
	var url string
	if debug {
		url = fmt.Sprintf(debugServerURL, address, port, path)
	} else {
		url = fmt.Sprintf(serverURL, service, namespace, port, path)
	}

	client := &http.Client{Timeout: httpTimeout}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	var httpRsp *http.Response
	for i := 0; i < retryTimes; i++ {
		httpRsp, err = client.Do(httpReq)
		if err == nil {
			defer httpRsp.Body.Close()
			if httpRsp.StatusCode == http.StatusOK {
				rspBody := make([]byte, len(reqBody))
				var n int
				n, err = httpRsp.Body.Read(rspBody)
				if n > 0 && err == io.EOF {
					return rspBody, nil
				}
			} else {
				err = fmt.Errorf(fmt.Sprintf("http error code %d", httpRsp.StatusCode))
			}
		}
		r := rand.Intn(10)
		time.Sleep(time.Duration(r) * time.Millisecond)
	}

	return nil, err
}

func RequestMLService(reqBody []byte, debug bool, address string, port int) ([]byte, error) {
	return httpPostAndGetResponseWithRetry(reqBody, debug, varmorconfig.MLServiceName, varmorconfig.Namespace, address, port, varmorconfig.MLPathClassifyPath, retryTimes)
}

func PostStatusToStatusService(reqBody []byte, debug bool, address string, port int) error {
	return httpPostWithRetry(reqBody, debug, varmorconfig.StatusServiceName, varmorconfig.Namespace, address, port, varmorconfig.StatusSyncPath, retryTimes)
}

func PostDataToStatusService(reqBody []byte, debug bool, address string, port int) error {
	return httpPostWithRetry(reqBody, debug, varmorconfig.StatusServiceName, varmorconfig.Namespace, address, port, varmorconfig.DataSyncPath, retryTimes)
}

func modifyDeploymentAnnotationsAndEnv(enforcer string, target varmor.Target, deploy *appsV1.Deployment, profileName, uniqueID string) {
	for key, value := range deploy.Spec.Template.Annotations {
		switch enforcer {
		case "BPF":
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
				container := key[len("container.bpf.security.beta.varmor.org/"):]
				apparmorKey := "container.apparmor.security.beta.kubernetes.io/" + container
				delete(deploy.Spec.Template.Annotations, apparmorKey)
			}
		case "AppArmor":
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
			}
		}
	}

	for index, container := range deploy.Spec.Template.Spec.Containers {
		newEnv := make([]coreV1.EnvVar, 0)
		for _, env := range container.Env {
			if env.Name == "VARMOR" {
				continue
			} else {
				newEnv = append(newEnv, env)
			}
		}
		deploy.Spec.Template.Spec.Containers[index].Env = newEnv
	}

	if deploy.Spec.Template.Annotations == nil {
		deploy.Spec.Template.Annotations = make(map[string]string)
	}
	deploy.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)

	if profileName == "" {
		return
	}

	for index, container := range deploy.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !InStringArray(container.Name, target.Containers) {
			continue
		}

		switch enforcer {
		case "BPF":
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			deploy.Spec.Template.Annotations[key] = "unconfined"
		case "AppArmor":
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)

			if uniqueID != "" {
				var newEnv coreV1.EnvVar
				newEnv.Name = "VARMOR"
				newEnv.Value = uniqueID
				if deploy.Spec.Template.Spec.Containers[index].Env == nil {
					deploy.Spec.Template.Spec.Containers[index].Env = make([]coreV1.EnvVar, 0)
				}
				deploy.Spec.Template.Spec.Containers[index].Env = append(deploy.Spec.Template.Spec.Containers[index].Env, newEnv)
			}
		}
	}
}

func modifyStatefulSetAnnotationsAndEnv(enforcer string, target varmor.Target, stateful *appsV1.StatefulSet, profileName, uniqueID string) {
	for key, value := range stateful.Spec.Template.Annotations {
		switch enforcer {
		case "BPF":
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
				container := key[len("container.bpf.security.beta.varmor.org/"):]
				apparmorKey := "container.apparmor.security.beta.kubernetes.io/" + container
				delete(stateful.Spec.Template.Annotations, apparmorKey)
			}
		case "AppArmor":
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
			}
		}
	}

	for index, container := range stateful.Spec.Template.Spec.Containers {
		newEnv := make([]coreV1.EnvVar, 0)
		for _, env := range container.Env {
			if env.Name == "VARMOR" {
				continue
			} else {
				newEnv = append(newEnv, env)
			}
		}
		stateful.Spec.Template.Spec.Containers[index].Env = newEnv
	}

	if stateful.Spec.Template.Annotations == nil {
		stateful.Spec.Template.Annotations = make(map[string]string)
	}
	stateful.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)

	if profileName == "" {
		return
	}

	for index, container := range stateful.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !InStringArray(container.Name, target.Containers) {
			continue
		}

		switch enforcer {
		case "BPF":
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			stateful.Spec.Template.Annotations[key] = "unconfined"
		case "AppArmor":
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)

			if uniqueID != "" {
				var newEnv coreV1.EnvVar
				newEnv.Name = "VARMOR"
				newEnv.Value = uniqueID
				if stateful.Spec.Template.Spec.Containers[index].Env == nil {
					stateful.Spec.Template.Spec.Containers[index].Env = make([]coreV1.EnvVar, 0)
				}
				stateful.Spec.Template.Spec.Containers[index].Env = append(stateful.Spec.Template.Spec.Containers[index].Env, newEnv)
			}
		}
	}
}

func modifyDaemonSetAnnotationsAndEnv(enforcer string, target varmor.Target, daemon *appsV1.DaemonSet, profileName, uniqueID string) {
	for key, value := range daemon.Spec.Template.Annotations {
		switch enforcer {
		case "BPF":
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
				container := key[len("container.bpf.security.beta.varmor.org/"):]
				apparmorKey := "container.apparmor.security.beta.kubernetes.io/" + container
				delete(daemon.Spec.Template.Annotations, apparmorKey)
			}
		case "AppArmor":
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
			}
		}
	}

	for index, container := range daemon.Spec.Template.Spec.Containers {
		newEnv := make([]coreV1.EnvVar, 0)
		for _, env := range container.Env {
			if env.Name == "VARMOR" {
				continue
			} else {
				newEnv = append(newEnv, env)
			}
		}
		daemon.Spec.Template.Spec.Containers[index].Env = newEnv
	}

	if daemon.Spec.Template.Annotations == nil {
		daemon.Spec.Template.Annotations = make(map[string]string)
	}
	daemon.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)

	if profileName == "" {
		return
	}

	for index, container := range daemon.Spec.Template.Spec.Containers {
		if len(target.Containers) != 0 && !InStringArray(container.Name, target.Containers) {
			continue
		}

		switch enforcer {
		case "BPF":
			key := fmt.Sprintf("container.bpf.security.beta.varmor.org/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			daemon.Spec.Template.Annotations[key] = "unconfined"
		case "AppArmor":
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)

			if uniqueID != "" {
				var newEnv coreV1.EnvVar
				newEnv.Name = "VARMOR"
				newEnv.Value = uniqueID
				if daemon.Spec.Template.Spec.Containers[index].Env == nil {
					daemon.Spec.Template.Spec.Containers[index].Env = make([]coreV1.EnvVar, 0)
				}
				daemon.Spec.Template.Spec.Containers[index].Env = append(daemon.Spec.Template.Spec.Containers[index].Env, newEnv)
			}
		}
	}
}

func UpdateWorkloadAnnotationsAndEnv(
	appsInterface appsv1.AppsV1Interface,
	namespace string,
	enforcer string,
	target varmor.Target,
	profileName string,
	uniqueID string,
	logger logr.Logger) {
	switch target.Kind {
	case "Deployment":
		if target.Name != "" {
			updateDeployment := func() error {
				deploy, err := appsInterface.Deployments(namespace).Get(context.Background(), target.Name, metav1.GetOptions{})
				if err != nil {
					if k8errors.IsNotFound(err) {
						return nil
					}
					return err
				}

				// The target must have the webhook selector label.
				for key, value := range varmorconfig.WebhookSelectorLabel {
					if _, ok := deploy.Annotations[key]; !ok {
						return nil
					}
					if deploy.Annotations[key] != value {
						return nil
					}
				}

				deployOld := deploy.DeepCopy()
				modifyDeploymentAnnotationsAndEnv(enforcer, target, deploy, profileName, uniqueID)
				if reflect.DeepEqual(deployOld, deploy) {
					return nil
				}
				deploy, err = appsInterface.Deployments(namespace).Update(context.Background(), deploy, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "Deployments", "namespace", deploy.Namespace, "name", deploy.Name)
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateDeployment)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		} else if target.Selector != nil {
			for key, value := range varmorconfig.WebhookSelectorLabel {
				// The target must have the webhook selector label.
				target.Selector.MatchLabels[key] = value
			}
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				logger.Error(err, "LabelSelectorAsSelector()")
				return
			}
			listOpt := metav1.ListOptions{
				LabelSelector:   selector.String(),
				ResourceVersion: "0",
			}
			deploys, err := appsInterface.Deployments(namespace).List(context.Background(), listOpt)
			if err != nil {
				logger.Error(err, "Deployments().List()")
				return
			}

			if len(deploys.Items) == 0 {
				return
			}

			for _, item := range deploys.Items {
				needRegain := false
				deploy := &item

				updateDeployment := func() error {
					if needRegain {
						deploy, err = appsInterface.Deployments(namespace).Get(context.Background(), deploy.Name, metav1.GetOptions{})
						if err != nil {
							if k8errors.IsNotFound(err) {
								return nil
							}
							return err
						}
						needRegain = false
					}

					deployOld := deploy.DeepCopy()
					modifyDeploymentAnnotationsAndEnv(enforcer, target, deploy, profileName, uniqueID)
					if reflect.DeepEqual(deployOld, deploy) {
						return nil
					}
					deploy, err = appsInterface.Deployments(namespace).Update(context.Background(), deploy, metav1.UpdateOptions{})
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
		}
	case "StatefulSet":
		if target.Name != "" {
			updateStateful := func() error {
				stateful, err := appsInterface.StatefulSets(namespace).Get(context.Background(), target.Name, metav1.GetOptions{})
				if err != nil {
					if k8errors.IsNotFound(err) {
						return nil
					}
					return err
				}

				// The target must have the webhook selector label.
				for key, value := range varmorconfig.WebhookSelectorLabel {
					if _, ok := stateful.Annotations[key]; !ok {
						return nil
					}
					if stateful.Annotations[key] != value {
						return nil
					}
				}

				statefulOld := stateful.DeepCopy()
				modifyStatefulSetAnnotationsAndEnv(enforcer, target, stateful, profileName, uniqueID)
				if reflect.DeepEqual(statefulOld, stateful) {
					return nil
				}
				stateful, err = appsInterface.StatefulSets(namespace).Update(context.Background(), stateful, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "StatefulSets", "namespace", stateful.Namespace, "name", stateful.Name)
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateStateful)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		} else if target.Selector != nil {
			for key, value := range varmorconfig.WebhookSelectorLabel {
				// The target must have the webhook selector label.
				target.Selector.MatchLabels[key] = value
			}
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				logger.Error(err, "LabelSelectorAsSelector()")
				return
			}
			listOpt := metav1.ListOptions{
				LabelSelector:   selector.String(),
				ResourceVersion: "0",
			}
			statefuls, err := appsInterface.StatefulSets(namespace).List(context.Background(), listOpt)
			if err != nil {
				logger.Error(err, "StatefulSets().List()")
				return
			}

			if len(statefuls.Items) == 0 {
				return
			}

			for _, item := range statefuls.Items {
				needRegain := false
				stateful := &item

				updateStateful := func() error {
					if needRegain {
						stateful, err = appsInterface.StatefulSets(namespace).Get(context.Background(), stateful.Name, metav1.GetOptions{})
						if err != nil {
							if k8errors.IsNotFound(err) {
								return nil
							}
							return err
						}
						needRegain = false
					}

					statefulOld := stateful.DeepCopy()
					modifyStatefulSetAnnotationsAndEnv(enforcer, target, stateful, profileName, uniqueID)
					if reflect.DeepEqual(statefulOld, stateful) {
						return nil
					}
					stateful, err = appsInterface.StatefulSets(namespace).Update(context.Background(), stateful, metav1.UpdateOptions{})
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
		}
	case "DaemonSet":
		if target.Name != "" {
			updateDaemon := func() error {
				daemon, err := appsInterface.DaemonSets(namespace).Get(context.Background(), target.Name, metav1.GetOptions{})
				if err != nil {
					if k8errors.IsNotFound(err) {
						return nil
					}
					return err
				}

				// The target must have the webhook selector label.
				for key, value := range varmorconfig.WebhookSelectorLabel {
					if _, ok := daemon.Annotations[key]; !ok {
						return nil
					}
					if daemon.Annotations[key] != value {
						return nil
					}
				}

				daemonOld := daemon.DeepCopy()
				modifyDaemonSetAnnotationsAndEnv(enforcer, target, daemon, profileName, uniqueID)
				if reflect.DeepEqual(daemonOld, daemon) {
					return nil
				}
				daemon, err = appsInterface.DaemonSets(namespace).Update(context.Background(), daemon, metav1.UpdateOptions{})
				if err == nil {
					logger.Info("the target workload has been updated", "Kind", "DaemonSets", "namespace", daemon.Namespace, "name", daemon.Name)
				}
				return err
			}

			err := retry.RetryOnConflict(retry.DefaultRetry, updateDaemon)
			if err != nil {
				logger.Error(err, "failed to update the target workload")
			}
		} else if target.Selector != nil {
			for key, value := range varmorconfig.WebhookSelectorLabel {
				// The target must have the webhook selector label.
				target.Selector.MatchLabels[key] = value
			}
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				logger.Error(err, "LabelSelectorAsSelector()")
				return
			}
			listOpt := metav1.ListOptions{
				LabelSelector:   selector.String(),
				ResourceVersion: "0",
			}
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
						daemon, err = appsInterface.DaemonSets(namespace).Get(context.Background(), daemon.Name, metav1.GetOptions{})
						if err != nil {
							if k8errors.IsNotFound(err) {
								return nil
							}
							return err
						}
						needRegain = false
					}

					daemonOld := daemon.DeepCopy()
					modifyDaemonSetAnnotationsAndEnv(enforcer, target, daemon, profileName, uniqueID)
					if reflect.DeepEqual(daemonOld, &daemon) {
						return nil
					}
					daemon, err = appsInterface.DaemonSets(namespace).Update(context.Background(), daemon, metav1.UpdateOptions{})
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
}

func TagLeaderPod(podInterface corev1.PodInterface) error {
	jsonPatch := `[{"op": "add", "path": "/metadata/labels/identity", "value": "leader"}]`
	_, err := podInterface.Patch(context.Background(), os.Getenv("HOSTNAME"), types.JSONPatchType, []byte(jsonPatch), metav1.PatchOptions{})

	return err
}

func UnTagLeaderPod(podInterface corev1.PodInterface) error {
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app.kubernetes.io/component": "varmor-manager",
			"identity":                    "leader",
		},
	}

	listOpt := metav1.ListOptions{
		LabelSelector:   labels.Set(selector.MatchLabels).String(),
		ResourceVersion: "0",
	}
	pods, err := podInterface.List(context.Background(), listOpt)
	if err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	for _, pod := range pods.Items {
		jsonPatch := `[{"op": "remove", "path": "/metadata/labels/identity"}]`
		_, err := podInterface.Patch(context.Background(), pod.Name, types.JSONPatchType, []byte(jsonPatch), metav1.PatchOptions{})
		if err != nil {
			return err
		}
	}

	return err
}

func InStringArray(c string, array []string) bool {
	for _, v := range array {
		if v == c {
			return true
		}
	}
	return false
}

func InUint32Array(i uint32, array []uint32) bool {
	for _, v := range array {
		if v == i {
			return true
		}
	}
	return false
}
