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
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	version "github.com/hashicorp/go-version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	varmorTypes "github.com/bytedance/vArmor/internal/types"
)

const (
	containerdDefaultProfile = `
## == Managed by vArmor == ##
## Attention:
##   This is a mock profile, only use to avoid cri-containerd.apparmor.d being removed by aa-remove-unknown unexpectedly.
##   This profile is not used to be loaded into the kernel.

abi <abi/3.0>,
#include <tunables/global>

profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted) {
}
`

	minKernelVersionForAppArmorLSM = "4.15"
	minKernelVersionForBPFLSM      = "5.7"
	regexVersion                   = "^\\d+\\.?\\d*\\.?\\d*" // ^\d+\.?\d*\.?\d*
)

type templateData struct {
	DiskDevices []string
}

func isAppArmorEnabled() bool {
	content, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil {
		return false
	}
	if strings.Contains(string(content), "Y") {
		return true
	}
	return false
}

func isBpfLsmEnabled() bool {
	content, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	if strings.Contains(string(content), "bpf") {
		return true
	}
	return false
}

func versionGreaterThanOrEqual(current, minimum string) (bool, error) {
	regex, err := regexp.Compile(regexVersion)
	if err != nil {
		return false, err
	}
	current = regex.FindString(current)
	currentVersion, err := version.NewVersion(current)
	if err != nil {
		return false, err
	}
	minVersion, err := version.NewVersion(minimum)
	if err != nil {
		return false, err
	}

	if currentVersion.GreaterThanOrEqual(minVersion) {
		return true, nil
	}
	return false, fmt.Errorf(fmt.Sprintf("the current version (%s) < the minimum testd version (%s)", current, minimum))
}

func isLSMSupported(lsm string) (bool, error) {
	ret, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return false, err
	}

	switch lsm {
	case "AppArmor":
		if !isAppArmorEnabled() {
			return false, fmt.Errorf("the AppArmor LSM is disabled")
		}
		return versionGreaterThanOrEqual(string(ret), minKernelVersionForAppArmorLSM)
	case "BPF":
		if !isBpfLsmEnabled() {
			return false, fmt.Errorf("the BPF LSM is disabled")
		}
		return versionGreaterThanOrEqual(string(ret), minKernelVersionForBPFLSM)
	default:
		return false, fmt.Errorf("unsupported LSM")
	}
}

// retrieveNodeName retrieve nodeName from the varmor:agent pod's specification.
func retrieveNodeName(podInterface corev1.PodInterface, debug bool) (string, error) {
	if debug {
		return os.Hostname()
	}

	pod, err := podInterface.Get(context.Background(), os.Getenv("HOSTNAME"), metav1.GetOptions{})
	if err == nil {
		return pod.Spec.NodeName, nil
	} else {
		return "", err
	}
}

func retrieveDiskDeviceList() ([]string, error) {
	f, err := os.Open("/proc/partitions")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)

	var devices []string
	for {
		p, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(p, "major") {
			continue
		} else {
			dev := strings.Fields(p)
			if len(dev) == 4 {
				devices = append(devices, dev[3])
			}
		}
	}
	return devices, nil
}

func retrieveTemplateData() (*templateData, error) {
	data := templateData{}

	// Retrieve the list of Node disk devices.
	devices, err := retrieveDiskDeviceList()
	if err != nil {
		return nil, err
	}
	data.DiskDevices = append(data.DiskDevices, devices...)

	return &data, nil
}

func generateAppArmorProfile(templateContent string, templateData *templateData, f io.Writer) error {
	t, err := template.New("apparmor_profile").Parse(templateContent)
	if err != nil {
		return err
	}
	return t.Execute(f, templateData)
}

func saveAppArmorProfile(fileName string, content string) error {
	templateContent, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return err
	}

	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	templateData, err := retrieveTemplateData()
	if err != nil {
		return err
	}

	return generateAppArmorProfile(string(templateContent), templateData, f)
}

func newProfileStatus(namespace, name, nodeName string, status varmorTypes.Status, message string) *varmorTypes.ProfileStatus {
	s := varmorTypes.ProfileStatus{
		Namespace:   namespace,
		ProfileName: name,
		NodeName:    nodeName,
		Status:      status,
		Message:     message,
	}
	return &s
}

// This profile is not used to be loaded into the kernel.
// It use to avoid cri-containerd.apparmor.d being removed by aa-remove-unknown unexpectedly.
func saveMockAppArmorProfile(fileName string, content string) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	return err
}
