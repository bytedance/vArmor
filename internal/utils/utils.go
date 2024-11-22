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
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
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
				return fmt.Errorf(fmt.Sprintf("http error code %d", httpRsp.StatusCode))
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
		r := rand.Intn(60) + 20
		time.Sleep(time.Duration(r) * time.Millisecond)
	}

	return nil, err
}

func RequestClassifierService(reqBody []byte, debug bool, address string, port int) ([]byte, error) {
	return httpPostAndGetResponseWithRetry(reqBody, debug, varmorconfig.ClassifierServiceName, varmorconfig.Namespace, address, port, varmorconfig.ClassifierPathClassifyPath, retryTimes)
}

func PostStatusToStatusService(reqBody []byte, debug bool, address string, port int) error {
	return httpsPostWithRetryAndToken(reqBody, debug, varmorconfig.StatusServiceName, varmorconfig.Namespace, address, port, varmorconfig.StatusSyncPath, retryTimes)
}

func PostDataToStatusService(reqBody []byte, debug bool, address string, port int) error {
	return httpsPostWithRetryAndToken(reqBody, debug, varmorconfig.StatusServiceName, varmorconfig.Namespace, address, port, varmorconfig.DataSyncPath, retryTimes)
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

func SetAgentReady() {
	atomic.StoreInt32(&AgentReady, 1)
}

func SetAgentUnready() {
	atomic.StoreInt32(&AgentReady, 0)
}

func WaitForManagerReady(debug bool, address string, port int) {
	var url string
	if debug {
		url = fmt.Sprintf(httpsDebugURL, address, port, "/healthz")
	} else {
		url = fmt.Sprintf(httpsServerURL, varmorconfig.StatusServiceName, varmorconfig.Namespace, port, "/healthz")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	for {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == 200 {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func GinLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		o := fmt.Sprintf("%s [GIN] \"statusCode\"=\"%d\" \"latency\"=\"%v\" \"clientIP\"=\"%s\" \"method\"=\"%s\" \"path\"=\"%s\" \"msg\"=\"%s\"\n",
			time.Now().Format("0102 15:04:05.000000"),
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Method,
			param.Path,
			param.ErrorMessage)

		if param.StatusCode&200 != 200 {
			return "E" + o
		}
		return ""
	})
}

func IsAppArmorGA(versionInfo *version.Info) (bool, error) {
	major, err := strconv.Atoi(versionInfo.Major)
	if err != nil {
		return false, err
	}

	minor, err := strconv.Atoi(strings.TrimRight(versionInfo.Minor, "+"))
	if err != nil {
		return false, err
	}

	if major <= 1 && minor < 30 {
		return false, nil
	}
	return true, nil
}

func RemoveArmorProfileFinalizers(i varmorinterface.CrdV1beta1Interface, namespace, name string) error {
	removeFinalizers := func() error {
		ap, err := i.ArmorProfiles(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			ap.Finalizers = []string{}
			_, err = i.ArmorProfiles(namespace).Update(context.Background(), ap, metav1.UpdateOptions{})
		}
		return err
	}
	return retry.RetryOnConflict(retry.DefaultRetry, removeFinalizers)
}
