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
	"crypto/tls"
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
	"k8s.io/apimachinery/pkg/fields"
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
	httpsServerURL = "https://%s.%s:%d%s"
	httpsDebugURL  = "https://%s:%d%s"
	serverURL      = "http://%s.%s:%d%s"
	debugServerURL = "http://%s:%d%s"
)

func httpsPostWithRetryAndToken(reqBody []byte, debug bool, service string, namespace string, address string, port int, path string, retryTimes int) error {
	var url string
	if debug {
		url = fmt.Sprintf(httpsDebugURL, address, port, path)
	} else {
		url = fmt.Sprintf(httpsServerURL, service, namespace, port, path)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: httpTimeout, Transport: tr}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Token", GetToken())
	var httpRsp *http.Response

	for i := 0; i < retryTimes; i++ {
		httpRsp, err = client.Do(httpReq)
		if err == nil {
			defer httpRsp.Body.Close()
			switch httpRsp.StatusCode {
			case http.StatusOK:
				return nil
			case http.StatusUnauthorized:
				if !debug {
					// try update token
					updateChan <- true
				}
			default:
				err = fmt.Errorf(fmt.Sprintf("http error code %d", httpRsp.StatusCode))
			}
		}
		r := rand.Intn(60) + 20
		time.Sleep(time.Duration(r) * time.Millisecond)
	}

	return err
}

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
	httpReq.Header.Set("Content-Type", "application/json")
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
	return httpsPostWithRetryAndToken(reqBody, debug, varmorconfig.StatusServiceName, varmorconfig.Namespace, address, port, varmorconfig.StatusSyncPath, retryTimes)
}

func PostDataToStatusService(reqBody []byte, debug bool, address string, port int) error {
	return httpsPostWithRetryAndToken(reqBody, debug, varmorconfig.StatusServiceName, varmorconfig.Namespace, address, port, varmorconfig.DataSyncPath, retryTimes)
}

func modifyDeploymentAnnotationsAndEnv(enforcer string, target varmor.Target, deploy *appsV1.Deployment, profileName string, bpfExclusiveMode bool) {
	// Clean up the annotations
	for key, value := range deploy.Spec.Template.Annotations {
		switch enforcer {
		case "BPF":
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
			}
		case "AppArmor":
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
			}
		case "Seccomp":
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(deploy.Spec.Template.Annotations, key)
			}
		}
	}

	// Clean up the seccomp settings
	for index, container := range deploy.Spec.Template.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil &&
			strings.HasPrefix(*container.SecurityContext.SeccompProfile.LocalhostProfile, "varmor-") {
			deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
		}
	}

	// Add the modification time to annotation
	if deploy.Spec.Template.Annotations == nil {
		deploy.Spec.Template.Annotations = make(map[string]string)
	}
	deploy.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)

	if profileName == "" {
		return
	}

	// Setting new annotations and seccomp context
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

			if bpfExclusiveMode {
				key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
				deploy.Spec.Template.Annotations[key] = "unconfined"
			}
		case "AppArmor":
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := deploy.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
		case "Seccomp":
			if (container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil) ||
				(container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(deploy.Spec.Template.Spec.SecurityContext != nil && deploy.Spec.Template.Spec.SecurityContext.SeccompProfile != nil) {
				continue
			}
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			deploy.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if deploy.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				deploy.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			deploy.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
				Type:             "Localhost",
				LocalhostProfile: &profileName,
			}
		}
	}
}

func modifyStatefulSetAnnotationsAndEnv(enforcer string, target varmor.Target, stateful *appsV1.StatefulSet, profileName string, bpfExclusiveMode bool) {
	// Clean up the annotations
	for key, value := range stateful.Spec.Template.Annotations {
		switch enforcer {
		case "BPF":
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
			}
		case "AppArmor":
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
			}
		case "Seccomp":
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(stateful.Spec.Template.Annotations, key)
			}
		}
	}

	// Clean up the seccomp settings
	for index, container := range stateful.Spec.Template.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil &&
			strings.HasPrefix(*container.SecurityContext.SeccompProfile.LocalhostProfile, "varmor-") {
			stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
		}
	}

	// Add the modification time to annotation
	if stateful.Spec.Template.Annotations == nil {
		stateful.Spec.Template.Annotations = make(map[string]string)
	}
	stateful.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)

	if profileName == "" {
		return
	}

	// Setting new annotations and seccomp context
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

			if bpfExclusiveMode {
				key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
				stateful.Spec.Template.Annotations[key] = "unconfined"
			}
		case "AppArmor":
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := stateful.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
		case "Seccomp":
			if (container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil) ||
				(container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(stateful.Spec.Template.Spec.SecurityContext != nil && stateful.Spec.Template.Spec.SecurityContext.SeccompProfile != nil) {
				continue
			}
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			stateful.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if stateful.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				stateful.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			stateful.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
				Type:             "Localhost",
				LocalhostProfile: &profileName,
			}
		}
	}
}

func modifyDaemonSetAnnotationsAndEnv(enforcer string, target varmor.Target, daemon *appsV1.DaemonSet, profileName string, bpfExclusiveMode bool) {
	// Clean up the annotations
	for key, value := range daemon.Spec.Template.Annotations {
		switch enforcer {
		case "BPF":
			if strings.HasPrefix(key, "container.bpf.security.beta.varmor.org/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
			}
		case "AppArmor":
			if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
			}
		case "Seccomp":
			if strings.HasPrefix(key, "container.seccomp.security.beta.varmor.org/") && value != "unconfined" {
				delete(daemon.Spec.Template.Annotations, key)
			}
		}
	}

	// Clean up the seccomp settings
	for index, container := range daemon.Spec.Template.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil &&
			strings.HasPrefix(*container.SecurityContext.SeccompProfile.LocalhostProfile, "varmor-") {
			daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = nil
		}
	}

	// Add the modification time to annotation
	if daemon.Spec.Template.Annotations == nil {
		daemon.Spec.Template.Annotations = make(map[string]string)
	}
	daemon.Spec.Template.Annotations["controller.varmor.org/restartedAt"] = time.Now().Format(time.RFC3339)

	if profileName == "" {
		return
	}

	// Setting new annotations and seccomp context
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

			if bpfExclusiveMode {
				key = fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
				daemon.Spec.Template.Annotations[key] = "unconfined"
			}
		case "AppArmor":
			key := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
			if value, ok := daemon.Spec.Template.Annotations[key]; ok && value == "unconfined" {
				continue
			}
			daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
		case "Seccomp":
			if (container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil) ||
				(container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
				(daemon.Spec.Template.Spec.SecurityContext != nil && daemon.Spec.Template.Spec.SecurityContext.SeccompProfile != nil) {
				continue
			}
			key := fmt.Sprintf("container.seccomp.security.beta.varmor.org/%s", container.Name)
			daemon.Spec.Template.Annotations[key] = fmt.Sprintf("localhost/%s", profileName)
			if daemon.Spec.Template.Spec.Containers[index].SecurityContext == nil {
				daemon.Spec.Template.Spec.Containers[index].SecurityContext = &coreV1.SecurityContext{}
			}
			daemon.Spec.Template.Spec.Containers[index].SecurityContext.SeccompProfile = &coreV1.SeccompProfile{
				Type:             "Localhost",
				LocalhostProfile: &profileName,
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
				modifyDeploymentAnnotationsAndEnv(enforcer, target, deploy, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(deployOld, deploy) {
					return nil
				}
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
				modifyStatefulSetAnnotationsAndEnv(enforcer, target, stateful, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(statefulOld, stateful) {
					return nil
				}
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
				modifyDaemonSetAnnotationsAndEnv(enforcer, target, daemon, profileName, bpfExclusiveMode)
				if reflect.DeepEqual(daemonOld, &daemon) {
					return nil
				}
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

func TagLeaderPod(podInterface corev1.PodInterface) error {
	jsonPatch := `[{"op": "add", "path": "/metadata/labels/identity", "value": "leader"}]`
	_, err := podInterface.Patch(context.Background(), os.Getenv("HOSTNAME"), types.JSONPatchType, []byte(jsonPatch), metav1.PatchOptions{})

	return err
}

func UnTagLeaderPod(podInterface corev1.PodInterface) error {
	matchLabels := map[string]string{
		"app.kubernetes.io/component": "varmor-manager",
		"identity":                    "leader",
	}

	listOpt := metav1.ListOptions{
		LabelSelector:   labels.Set(matchLabels).String(),
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
